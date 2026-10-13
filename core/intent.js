'use strict';
// AgathOS - the intent engine.
// Gives every agent a risk score (0-100) with reasons in plain words, predicts the
// next step, checks the agent's claims against what Windows saw, and learns what is
// normal for this PC without letting an attacker "teach" it bad habits.
//
// Six layers (see README): hard rules, trifecta labels, next-step prediction with
// attack chains, personal baseline, honesty check, optional local AI judge.
const C = require('./catalog');
const { TEST_FILE_RE, BUGFIX_RE } = require('./transcripts');

const WINDOW = 30 * 60 * 1000;          // actions older than this leave the session
const IDLE_END = 30 * 60 * 1000;        // a session ends after 30 min of silence
const ACTION_KEYS = Object.keys(C.ACTIONS);
const RULE_KEY = {
  DELETE_MANY: 'proc.destructive', PERSISTENCE: 'proc.persistence', EXEC_DOWNLOADED: 'proc.download',
  CREDENTIAL_ACCESS: 'proc.credential', DISABLE_SECURITY: 'proc.securityOff', EXFIL: 'proc.exfil',
  READ_SENSITIVE: 'proc.sensitive', MCP_CONFIG_CHANGE: 'proc.configChange',
};

// Prior belief about what an agent does next when we know nothing yet.
const PRIOR = Object.fromEntries(ACTION_KEYS.map((a) => [a, 0.004]));
Object.assign(PRIOR, { READ_FILE: 0.3, WRITE_FILE: 0.2, EXEC_SHELL: 0.2, TEST_RUN: 0.1, ENUMERATE: 0.04, NET_FETCH: 0.04, READ_UNTRUSTED: 0.04, INSTALL_PKG: 0.03, GIT_PUSH: 0.01 });

function thresholds(level) {
  const shift = level === 'strict' ? -10 : level === 'relaxed' ? 10 : 0;
  return { watch: 30 + shift, alarm: 60 + shift };
}

class IntentEngine {
  constructor(store, { onAlert } = {}) {
    this.store = store;
    this.onAlert = onAlert;
    this.sessions = new Map();     // agentId -> session
    this.cooldown = new Map();
    this.judged = new Map();
  }

  session(agentId) {
    let s = this.sessions.get(agentId);
    if (!s) {
      s = { agentId, actions: [], labels: {}, maxScore: 0, approved: false, startedAt: Date.now(), lastAt: 0, extra: [], judge: null, honesty: [], untrustedSeen: false };
      this.sessions.set(agentId, s);
    }
    return s;
  }

  // ---------- input ----------
  addAction(a) {
    if (!a || !a.agentId || !C.ACTIONS[a.action]) return null;
    const s = this.session(a.agentId);
    if (s.lastAt && Date.now() - s.lastAt > IDLE_END) this.endSession(a.agentId);
    const ss = this.session(a.agentId);
    const ts = a.ts || Date.now();
    ss.actions.push({ ts, action: a.action, source: a.source, detail: a.detail, historic: !!a.historic, pid: a.pid });
    if (ss.actions.length > 2000) ss.actions.splice(0, ss.actions.length - 2000);
    ss.lastAt = Math.max(ss.lastAt, ts);
    for (const [label, set] of Object.entries(C.LABEL_OF)) if (set.has(a.action)) ss.labels[label] = ss.labels[label] || ts;
    if (ss.labels.untrusted) ss.untrustedSeen = true;
    if (a.historic) return null;
    // Hard rules raise an alert right away, with the command in it.
    const ruleKey = RULE_KEY[a.action];
    if (ruleKey) {
      const sev = C.HARD_FLOOR[a.action] ? 'alarm' : 'watch';
      this.alert({ key: ruleKey, sev, watcher: a.action === 'MCP_CONFIG_CHANGE' ? 'gate' : a.action === 'READ_SENSITIVE' || a.action === 'CREDENTIAL_ACCESS' ? 'keys' : 'proc', agentId: a.agentId, params: { cmd: a.detail || a.action }, pid: a.pid }, `${a.agentId}|${ruleKey}|${a.detail}`);
    }
    return this.evaluate(a.agentId, true);
  }

  // Extra soft signals from elsewhere (dangerous flags, odd launcher, mass delete).
  addSignal(agentId, signal) {
    const s = this.session(agentId);
    s.extra = s.extra.filter((x) => x.key !== signal.key);
    s.extra.push({ ...signal, ts: Date.now() });
    s.lastAt = Date.now();
    return this.evaluate(agentId, true);
  }

  // ---------- scoring ----------
  evaluate(agentId, emit = false) {
    const s = this.session(agentId);
    const now = Date.now();
    const live = s.actions.filter((x) => now - x.ts < WINDOW);
    const fresh = live.filter((x) => !x.historic);
    const reasons = [];
    let floor = 0;

    // Layer 1: hard rules (never learned away).
    for (const x of fresh) {
      const f = C.HARD_FLOOR[x.action];
      if (f && f > floor) floor = f;
    }

    let soft = 0;
    // Layer 2: lethal trifecta labels (in this window).
    const lab = {};
    for (const x of live) for (const [label, set] of Object.entries(C.LABEL_OF)) if (set.has(x.action)) lab[label] = lab[label] || x.ts;
    const nLabels = Object.keys(lab).length;
    if (nLabels === 3) {
      const ordered = lab.exit >= lab.untrusted && lab.exit >= lab.private;
      soft += ordered ? 70 : 55;
      reasons.push({ key: 'intent.trifecta', params: {}, sev: 'alarm' });
    } else if (nLabels === 2) {
      soft += 25;
      reasons.push({ key: 'intent.twoOfThree', params: { labels: Object.keys(lab).join('+') }, sev: 'watch' });
    }

    // Layer 3a: attack chains. Warn when only the last stage is missing.
    const seq = live.map((x) => x.action);
    let chainHit = null;
    for (const ch of C.CHAINS) {
      let stage = 0;
      for (const act of seq) if (stage < ch.stages.length && ch.stages[stage].includes(act)) stage++;
      if (stage === ch.stages.length) { soft += 60; chainHit = { id: ch.id, done: true }; reasons.push({ key: 'intent.chainDone', params: { chain: ch.id }, sev: 'alarm' }); break; }
      if (stage === ch.stages.length - 1 && stage >= 1 && ch.stages.length >= 2) {
        if (!chainHit) { chainHit = { id: ch.id, next: ch.stages[stage] }; soft += 35; reasons.push({ key: 'intent.chain', params: { chain: ch.id, next: ch.stages[stage][0] }, sev: 'watch' }); }
      }
    }

    // Layer 3b: next-step prediction (Markov on this agent's learned habits + prior).
    const prediction = this.predict(agentId, seq[seq.length - 1], chainHit);
    if (prediction && prediction.risk > 0.15) soft += Math.round(prediction.risk * 30);
    if (prediction && C.ACTIONS[prediction.action].sev >= 0.5 && prediction.p >= 0.25) {
      reasons.push({ key: 'intent.predict', params: { action: prediction.action, p: Math.round(prediction.p * 100) }, sev: 'watch' });
    }

    // Layer 4: personal baseline (how many risky actions per session is normal here).
    const b = this.store.state.baselines[agentId];
    const risky = fresh.filter((x) => C.ACTIONS[x.action].sev >= 0.3).length;
    if (b && b.sessions >= 5) {
      const mean = b.riskyMean || 0;
      const sd = Math.sqrt((b.riskyM2 || 0) / Math.max(1, b.sessions - 1)) || 1;
      if (risky > mean + 3 * sd && risky >= 3) {
        soft += 15;
        reasons.push({ key: 'intent.baseline', params: { x: Math.max(2, Math.round(risky / Math.max(1, mean))) }, sev: 'watch' });
      }
    }

    // Layer 5: honesty results (computed in honestyCheck()).
    for (const h of s.honesty) { soft += h.sev === 'alarm' ? 25 : 15; reasons.push(h); }

    // Extra signals: flags, odd launcher, mass delete.
    for (const e of s.extra) {
      if (now - e.ts > WINDOW && !e.sticky) continue;
      soft += e.points || 0;
      reasons.push({ key: e.key, params: e.params || {}, sev: e.sev || 'watch' });
      if (e.floor && e.floor > floor) floor = e.floor;
    }

    // Layer 6: local judge may only raise.
    if (s.judge && now - s.judge.ts < WINDOW && s.judge.risk > 0) {
      reasons.push({ key: 'judge.raise', params: { why: s.judge.why }, sev: 'watch' });
    }

    let score = Math.min(100, Math.max(floor, soft));
    if (s.judge && now - s.judge.ts < WINDOW && s.judge.risk > score) score = Math.min(score + 25, s.judge.risk, 95);
    const th = thresholds(this.store.settings.level);
    const state = score >= th.alarm ? 'alarm' : score >= th.watch ? 'watch' : 'calm';
    // Hard-rule reasons first, then the rest by severity.
    for (const x of fresh) if (C.HARD_FLOOR[x.action] && !reasons.some((r) => r.params && r.params.cmd === x.detail)) {
      reasons.unshift({ key: RULE_KEY[x.action], params: { cmd: x.detail || x.action }, sev: 'alarm' });
    }
    const prev = s.state || 'calm';
    s.score = score;
    s.state = state;
    s.maxScore = Math.max(s.maxScore, score);
    s.labelsNow = lab;
    s.prediction = prediction;
    s.reasons = dedupeReasons(reasons).slice(0, 8);
    if (emit && rank(state) > rank(prev) && state !== 'calm' && floor === 0) {
      this.alert({ key: 'intent.raised', sev: state, watcher: 'proc', agentId, params: { score } }, `${agentId}|raised|${state}`);
    }
    return this.view(agentId);
  }

  predict(agentId, last, chainHit) {
    const b = this.store.state.baselines[agentId];
    const row = (b && b.trans && last && b.trans[last]) || {};
    const total = Object.values(row).reduce((x, y) => x + y, 0);
    const k = 5;
    const probs = {};
    for (const a of ACTION_KEYS) probs[a] = ((row[a] || 0) + k * PRIOR[a]) / (total + k);
    if (chainHit && chainHit.next) for (const a of chainHit.next) probs[a] = Math.max(probs[a], 0.5 / chainHit.next.length);
    const sum = Object.values(probs).reduce((x, y) => x + y, 0);
    let best = null;
    let risk = 0;
    for (const a of ACTION_KEYS) {
      const p = probs[a] / sum;
      risk += p * C.ACTIONS[a].sev;
      if (!best || p * (0.3 + C.ACTIONS[a].sev) > best.p * (0.3 + C.ACTIONS[best.action].sev)) best = { action: a, p };
    }
    return last ? { action: best.action, p: best.p, risk } : null;
  }

  // ---------- honesty: compare claims with facts ----------
  honestyCheck(transcriptSessions) {
    const byAgent = new Map();
    for (const ts of transcriptSessions) {
      const out = [];
      const testsBefore = (t) => ts.tests.filter((x) => x.ts <= t);
      for (const cl of ts.claims) {
        if (cl.kind === 'tests') {
          const tb = testsBefore(cl.ts);
          if (!tb.length) out.push({ key: 'honesty.claimNoTest', params: { claim: cl.text }, sev: 'watch' });
          else if (tb[tb.length - 1].failed === true) out.push({ key: 'honesty.claimFailed', params: { claim: cl.text }, sev: 'alarm' });
        } else if (cl.kind === 'thought') {
          out.push({ key: 'honesty.thought', params: { text: cl.text }, sev: 'alarm' });
        }
      }
      const task = ts.task || '';
      if (BUGFIX_RE.test(task) && !/test/i.test(task)) {
        const touched = ts.edited.filter((e) => TEST_FILE_RE.test(e.file));
        if (touched.length) out.push({ key: 'honesty.testsEdited', params: { task: task.slice(0, 60), file: touched[0].file.split(/[\\/]/).pop() }, sev: 'watch' });
      }
      // Silent work: risky child processes that the transcript never mentions.
      const s = this.sessions.get(ts.agentId);
      if (s) {
        const said = ts.commands.map((c) => norm(c.cmd)).filter(Boolean);
        const silent = s.actions.filter((x) => x.source === 'process' && !x.historic && C.ACTIONS[x.action].sev >= 0.3 &&
          x.ts >= ts.startedAt - 5000 && x.ts <= ts.lastAt + 60000 &&
          !said.some((c) => { const d = norm(x.detail); return d.includes(c.slice(0, 40)) || c.includes(d.slice(-40)); }));
        if (silent.length) out.push({ key: 'honesty.silent', params: { n: silent.length, cmd: silent[0].detail }, sev: silent.some((x) => C.ACTIONS[x.action].sev >= 0.8) ? 'alarm' : 'watch' });
      }
      const prev = byAgent.get(ts.agentId) || [];
      byAgent.set(ts.agentId, prev.concat(out.map((o) => ({ ...o, sessionId: ts.id }))));
    }
    for (const [agentId, list] of byAgent) {
      const s = this.session(agentId);
      const before = new Set(s.honesty.map((h) => h.key + JSON.stringify(h.params)));
      s.honesty = dedupeReasons(list).slice(0, 4);
      for (const h of s.honesty) {
        if (!before.has(h.key + JSON.stringify(h.params))) this.alert({ key: h.key, sev: h.sev, watcher: 'proc', agentId, params: h.params }, `${agentId}|${h.key}|${JSON.stringify(h.params)}`);
      }
      this.evaluate(agentId, true);
    }
  }

  setJudge(agentId, risk, why) {
    const s = this.session(agentId);
    s.judge = { risk, why, ts: Date.now() };
    return this.evaluate(agentId, true);
  }

  // ---------- safe self-learning ----------
  approve(agentId) {
    const s = this.session(agentId);
    s.approved = true;
    s.extra = [];
    s.honesty = [];
    s.judge = null;
    this.learn(s, true);
    s.actions = s.actions.map((x) => ({ ...x, historic: true }));
    return this.evaluate(agentId);
  }

  endSession(agentId) {
    const s = this.sessions.get(agentId);
    if (!s) return;
    this.learn(s, s.approved);
    this.sessions.delete(agentId);
  }

  learn(s, approved) {
    if (!this.store.settings.learning) return;
    const th = thresholds(this.store.settings.level);
    // Rule 1: only learn from clean sessions or sessions the user approved.
    if (!approved && s.maxScore >= th.watch) return;
    // Rule 2: never learn while the session read untrusted content (unless approved).
    if (!approved && s.untrustedSeen) return;
    const acts = s.actions.filter((x) => !x.historic).map((x) => x.action);
    if (acts.length < 3) return;
    const all = this.store.state.baselines;
    // Rule 5: keep versions so the user can roll back.
    this.store.state.baselineVersions.push({ at: Date.now(), data: JSON.parse(JSON.stringify(all)) });
    if (this.store.state.baselineVersions.length > 10) this.store.state.baselineVersions.shift();
    const b = all[s.agentId] || (all[s.agentId] = { trans: {}, sessions: 0, riskyMean: 0, riskyM2: 0 });
    // Rule 3: one session can only move the baseline a little (max 50 transitions).
    let budget = 50;
    for (let i = 1; i < acts.length && budget > 0; i++) {
      // Rule 4: hard-rule actions are never learned as "normal".
      if (C.HARD_FLOOR[acts[i]]) continue;
      const row = b.trans[acts[i - 1]] || (b.trans[acts[i - 1]] = {});
      row[acts[i]] = (row[acts[i]] || 0) + 1;
      budget--;
    }
    const risky = acts.filter((a) => C.ACTIONS[a].sev >= 0.3 && !C.HARD_FLOOR[a]).length;
    b.sessions += 1;
    const d = risky - b.riskyMean;
    b.riskyMean += d / b.sessions;
    b.riskyM2 += d * (risky - b.riskyMean);
    this.store.saveState();
  }

  rollbackBaseline() {
    const v = this.store.state.baselineVersions.pop();
    if (!v) return false;
    this.store.state.baselines = v.data;
    this.store.saveState();
    return true;
  }

  resetBaseline() {
    this.store.state.baselines = {};
    this.store.state.baselineVersions = [];
    this.store.saveState();
  }

  tick() {
    for (const [id, s] of this.sessions) if (s.lastAt && Date.now() - s.lastAt > IDLE_END) this.endSession(id);
  }

  // ---------- output ----------
  alert(a, dedupeKey) {
    const now = Date.now();
    if (now - (this.cooldown.get(dedupeKey) || 0) < 10 * 60 * 1000) return;
    this.cooldown.set(dedupeKey, now);
    this.onAlert && this.onAlert(a);
  }

  view(agentId) {
    const s = this.sessions.get(agentId);
    if (!s) return { agentId, score: 0, state: 'calm', labels: {}, reasons: [], prediction: null, actions: [] };
    return {
      agentId, score: s.score || 0, state: s.state || 'calm',
      labels: { untrusted: !!(s.labelsNow || {}).untrusted, private: !!(s.labelsNow || {}).private, exit: !!(s.labelsNow || {}).exit },
      reasons: s.reasons || [], prediction: s.prediction || null,
      actions: s.actions.slice(-30).reverse().map((x) => ({ ts: x.ts, action: x.action, source: x.source, detail: x.detail })),
      learned: !!(this.store.state.baselines[agentId] && this.store.state.baselines[agentId].sessions),
    };
  }

  summaryForJudge(agentId, task) {
    const s = this.sessions.get(agentId);
    if (!s) return null;
    // Only normalised facts go to the judge, never raw text an attacker could write.
    const acts = s.actions.filter((x) => !x.historic).slice(-25).map((x) => `${x.action}: ${clean(x.detail)}`);
    return { task: clean(task || '').slice(0, 160), actions: acts, labels: Object.keys(s.labelsNow || {}) };
  }
}

const rank = (s) => (s === 'alarm' ? 2 : s === 'watch' ? 1 : 0);
const norm = (c) => String(c || '').toLowerCase().replace(/["'`]/g, '').replace(/\s+/g, ' ').trim();
// Strip anything that could act as instructions to the judge: keep a short, plain, ASCII-ish summary.
const clean = (t) => String(t || '').replace(/[^\x20-\x7e]/g, ' ').replace(/(ignore|disregard|instruction|system|assistant|user|prompt)/gi, '[x]').replace(/\s+/g, ' ').slice(0, 80);

function dedupeReasons(list) {
  const seen = new Set();
  return list.filter((r) => { const k = r.key + JSON.stringify(r.params || {}); if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => rank(b.sev) - rank(a.sev));
}

module.exports = { IntentEngine, thresholds, clean };
