'use strict';
// AgathOS - who may use the local API, and how.
//
// Two kinds of keys:
//   * the owner key (api-token.txt): for tools of the person who runs AgathOS. It can read, ask and press the stop button.
//   * agent keys: one for each AI program, made in the window by the person, shown once, kept only as a hash and taken back with one
//     click. They can read, ask ("may I do this?", "is this text or file safe?") and report a worry. Nothing else.
// Neither key can resume agents, approve a finding, release a file or change a setting: the API has no route for that. Those stay
// with the person in the window.
//
// Files (in the data folder, readable by the person only):
//   api-token.txt      the owner key. A file that others could read is not secret any more: it is replaced by a new key.
//   agent-tokens.json  the agent keys, as hashes
//   api-audit.jsonl    every request, as a chain of hashes (see audit.js)
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { AuditLog } = require('./audit');
const Z = require('./untrusted');

const IS_WIN = process.platform === 'win32';
const SCOPES = ['read', 'ask', 'report'];
const MAX_TOKENS = 20;
// [how many requests, in how many milliseconds] for each kind of request. A busy agent that asks before every step stays far below this.
const LIMITS = { read: [120, 60000], ask: [300, 60000], scan: [60, 60000], report: [6, 3600000], admin: [20, 60000] };

const sha = (s) => crypto.createHash('sha256').update(String(s)).digest('hex');
const digest = (s) => crypto.createHash('sha256').update(String(s)).digest();

// A file that only the person can read (on Windows the profile folder is private already; the mode bits do not apply there).
function writePrivate(file, data) {
  const tmp = `${file}.${process.pid}.tmp`;
  fs.writeFileSync(tmp, data, { mode: 0o600 });
  try { fs.chmodSync(tmp, 0o600); } catch (_) { /* a file system without modes */ }
  fs.renameSync(tmp, file);
}

class AgentAccess {
  constructor(dir, { onEvent, now = Date.now, limits, days = 30 } = {}) {
    this.dir = dir;
    this.now = now;
    this.onEvent = typeof onEvent === 'function' ? onEvent : () => {};
    this.limits = { ...LIMITS, ...(limits || {}) };
    fs.mkdirSync(dir, { recursive: true });
    if (!IS_WIN) { try { fs.chmodSync(dir, 0o700); } catch (_) { /* not ours to change */ } }
    this.adminFile = path.join(dir, 'api-token.txt');
    this.tokensFile = path.join(dir, 'agent-tokens.json');
    const a = this.loadAdmin();
    this.admin = a.token;
    this.rotated = a.rotated;
    this.tokens = this.loadTokens();
    this.audit = new AuditLog(path.join(dir, 'api-audit.jsonl'), { days, now });
    this.buckets = new Map();
    this.problems = new Map();      // kind -> { n, last }: bad requests are reported once in a while, not every time
    this.badAudit = { n: 0, last: 0 };
    this.saveTimer = null;
  }

  // ---- the owner key ----
  loadAdmin() {
    let token = '';
    try { token = fs.readFileSync(this.adminFile, 'utf8').trim(); } catch (_) { /* none yet */ }
    let rotated = false;
    if (token && !IS_WIN) {
      try { if (fs.statSync(this.adminFile).mode & 0o077) { token = ''; rotated = true; } } catch (_) { token = ''; }
    }
    if (token && token.length < 32) { token = ''; rotated = true; }
    if (!token) {
      token = crypto.randomBytes(24).toString('hex');
      try { writePrivate(this.adminFile, token); } catch (_) { /* the key lives in memory for this run */ }
    }
    return { token, rotated };
  }

  // ---- the agent keys ----
  loadTokens() {
    let j = {};
    try { j = JSON.parse(fs.readFileSync(this.tokensFile, 'utf8')); } catch (_) { /* none yet */ }
    if (!IS_WIN) { try { fs.chmodSync(this.tokensFile, 0o600); } catch (_) { /* no file yet */ } }
    const list = Array.isArray(j.tokens) ? j.tokens : [];
    const out = [];
    for (const t of list) {
      if (!t || typeof t !== 'object' || out.length >= MAX_TOKENS) continue;
      const id = String(t.id || '').replace(/[^0-9a-f]/g, '').slice(0, 16);
      const hash = /^[0-9a-f]{64}$/.test(String(t.hash || '')) ? t.hash : '';
      if (!id || !hash || out.some((x) => x.id === id)) continue;
      out.push({
        id, hash, name: Z.text(t.name, 40) || 'agent',
        scopes: (Array.isArray(t.scopes) ? t.scopes : SCOPES).filter((s) => SCOPES.includes(s)),
        created: Number(t.created) || 0, lastUsed: Number(t.lastUsed) || 0, calls: Math.max(0, Number(t.calls) || 0),
      });
    }
    return out;
  }

  saveTokens() {
    clearTimeout(this.saveTimer);
    this.saveTimer = null;
    try { writePrivate(this.tokensFile, JSON.stringify({ v: 1, tokens: this.tokens }, null, 1)); } catch (_) { /* disk full or locked: try again next time */ }
  }

  // For the window: no hashes.
  list() {
    return this.tokens.map(({ hash, ...t }) => ({ ...t }));
  }

  // A new key. The text of the key is returned once and kept nowhere.
  create(name, scopes) {
    if (this.tokens.length >= MAX_TOKENS) return { ok: false, error: 'limit' };
    const clean = Z.text(name, 40);
    if (!clean) return { ok: false, error: 'name' };
    const token = 'agt_' + crypto.randomBytes(24).toString('base64url');
    const rec = {
      id: crypto.randomBytes(4).toString('hex'), name: clean,
      scopes: Array.isArray(scopes) && scopes.length ? scopes.filter((s) => SCOPES.includes(s)) : SCOPES.slice(),
      created: this.now(), lastUsed: 0, calls: 0, hash: sha(token),
    };
    this.tokens.push(rec);
    this.saveTokens();
    this.audit.append({ who: 'window', id: rec.id, name: clean, method: 'KEY', path: 'created', status: 200 });
    this.onEvent({ key: 'api.tokenAdded', sev: 'calm', watcher: 'gate', params: { name: clean } });
    return { ok: true, id: rec.id, name: rec.name, token };
  }

  revoke(id) {
    const i = this.tokens.findIndex((t) => t.id === String(id));
    if (i < 0) return false;
    const [t] = this.tokens.splice(i, 1);
    this.saveTokens();
    this.audit.append({ who: 'window', id: t.id, name: t.name, method: 'KEY', path: 'revoked', status: 200 });
    this.onEvent({ key: 'api.tokenRevoked', sev: 'calm', watcher: 'gate', params: { name: t.name } });
    return true;
  }

  // Who is asking? null when the key is wrong. The keys are compared as hashes, so the time it takes says nothing.
  authenticate(header) {
    const given = String(header || '').replace(/^Bearer\s+/i, '').trim();
    if (!given || given.length > 200) return null;
    const d = digest(given);
    if (crypto.timingSafeEqual(d, digest(this.admin))) return { kind: 'admin', id: 'admin', name: 'owner', scopes: ['read', 'ask', 'report', 'pause'] };
    let found = null;
    for (const t of this.tokens) {
      if (crypto.timingSafeEqual(d, Buffer.from(t.hash, 'hex')) && !found) found = t;
    }
    return found ? { kind: 'agent', id: found.id, name: found.name, scopes: found.scopes } : null;
  }

  // Used once more: the window shows when an agent last asked and how often. Written to disk now and then, not at every request.
  touch(who) {
    if (who.kind !== 'agent') return;
    const t = this.tokens.find((x) => x.id === who.id);
    if (!t) return;
    t.lastUsed = this.now();
    t.calls++;
    if (!this.saveTimer) { this.saveTimer = setTimeout(() => this.saveTokens(), 30000); if (this.saveTimer.unref) this.saveTimer.unref(); }
  }

  // ---- limits ----
  // Another request of this kind from this key: allowed, or how long to wait.
  take(who, cls) {
    const lim = this.limits[cls];
    if (!lim) return { ok: true };
    const [count, win] = lim;
    const key = `${who.id}|${cls}`;
    const t = this.now();
    const hits = (this.buckets.get(key) || []).filter((x) => t - x < win);
    if (hits.length >= count) { this.buckets.set(key, hits); return { ok: false, retryMs: Math.max(1000, win - (t - hits[0])) }; }
    hits.push(t);
    this.buckets.set(key, hits);
    return { ok: true };
  }

  // Something wrong with a request is told to the person once in a while (the log has every one of them).
  problem(kind, name) {
    const p = this.problems.get(kind) || { n: 0, last: 0 };
    p.n++;
    const t = this.now();
    if (t - p.last > 60000) {
      this.onEvent(kind === 'bad'
        ? { key: 'api.badToken', sev: 'watch', watcher: 'gate', params: { n: p.n } }
        : { key: 'api.overLimit', sev: 'calm', watcher: 'gate', params: { n: p.n, name: Z.text(name, 40) } });
      p.n = 0;
      p.last = t;
    }
    this.problems.set(kind, p);
  }

  // One line in the log of requests.
  record(row) {
    return this.audit.append(row);
  }

  // Requests with a wrong key come in lumps when something guesses: one line for every ten seconds.
  recordBad(row) {
    const t = this.now();
    this.badAudit.n++;
    if (t - this.badAudit.last < 10000) return null;
    const n = this.badAudit.n;
    this.badAudit = { n: 0, last: t };
    return this.audit.append({ ...row, n });
  }

  stop() {
    if (this.saveTimer) this.saveTokens();
  }
}

module.exports = { AgentAccess, SCOPES, LIMITS, MAX_TOKENS, writePrivate };
