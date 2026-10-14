'use strict';
// AgathOS - local storage. Nothing leaves the PC.
//  events.jsonl  append-only log; every line carries the hash of the line before
//                it, so an edited or removed line breaks the chain visibly.
//  state.json    settings, approvals, pins, baselines (written atomically).
const fs = require('fs');
const path = require('path');
const { sha256 } = require('./util');

const DEFAULT_SETTINGS = {
  level: 'balanced',          // strict | balanced | relaxed
  realtime: true,             // keep watching in the background
  pollSeconds: 5,             // process poll interval
  fullScanHours: 6,           // scheduled full scan
  roots: [],                  // project folders to watch (filled on first start)
  modelDirs: [],              // model folders to scan (filled on first start)
  notify: 'notify',           // log | notify | ask
  notifyLevel: 'alarm',       // pop-ups for: alarm (danger only) | watch (danger and attention)
  quietHours: { on: false, from: '22:00', to: '08:00' },   // only critical danger comes through
  autoFreezeOnMassDelete: true,
  massDeleteThreshold: 40,    // files deleted within 10 s
  portCheck: true,
  wormWatch: true,            // warn when a program sweeps the home network (worm behaviour)
  backupCheck: true,          // warn when work folders show no sign of a second copy
  pkgCheck: true,             // look for package and workflow worms (install scripts, GitHub workflows) in your projects
  hotkey: true,               // Ctrl+Alt+Shift+P pauses all agents
  judge: { enabled: false, model: 'qwen2.5:7b' },
  learning: true,
  startWithWindows: true,     // start quietly in the tray (--hidden) when you sign in
  closeToTray: true,
  logDays: 30,
  api: true,                  // local API on 127.0.0.1 for hooks and future apps
  downloadGuard: true,        // check new files in Downloads right away
  updates: true,              // check GitHub Releases for a new version once a day
  autoUpdate: true,           // Windows, installed app: install a new version by itself at a quiet moment
  // "Fix it": auto mode is off until you switch it on. level: gentle | firm | max | custom
  fix: { auto: false, level: 'firm', minSev: 'alarm', custom: { agent: 'block', port: 'localOnly', mcp: 'disable', hidden: 'clean', inject: 'off', model: 'quarantine', auto: 'off' } },
};

// A settings file that was edited by hand, or half written, must not break the timers
// (an interval of 600 hours or more overflows and then fires every millisecond).
const LIMITS = { pollSeconds: [2, 60], fullScanHours: [1, 168], massDeleteThreshold: [1, 1000], logDays: [1, 365] };
function sanitize(s) {
  for (const [k, [lo, hi]] of Object.entries(LIMITS)) {
    const n = Number(s[k]);
    s[k] = Number.isFinite(n) ? Math.min(hi, Math.max(lo, Math.round(n))) : DEFAULT_SETTINGS[k];
  }
  for (const k of ['roots', 'modelDirs']) s[k] = Array.isArray(s[k]) ? s[k].filter((x) => typeof x === 'string' && x) : [];
  return s;
}

class Store {
  constructor(dir) {
    this.dir = dir;
    fs.mkdirSync(dir, { recursive: true });
    this.eventsFile = path.join(dir, 'events.jsonl');
    this.stateFile = path.join(dir, 'state.json');
    this.state = this.loadState();
    this.lastHash = '0'.repeat(64);
    this.events = [];
    this.chainOk = true;
    this.loadEvents();
  }

  loadState() {
    let s = {};
    try { s = JSON.parse(fs.readFileSync(this.stateFile, 'utf8')); } catch (_) {}
    const old = s.settings || {};
    const oldFix = old.fix || {};
    s.settings = sanitize({ ...DEFAULT_SETTINGS, ...old, judge: { ...DEFAULT_SETTINGS.judge, ...(old.judge || {}) },
      fix: { ...DEFAULT_SETTINGS.fix, ...oldFix, custom: { ...DEFAULT_SETTINGS.fix.custom, ...(oldFix.custom || {}) } } });
    s.remedies = s.remedies || [];     // what "Fix it" changed, with what is needed to undo it
    s.approvals = s.approvals || {};   // id -> { hash, at }   (MCP servers, agents, skills, autostarts)
    s.ignored = s.ignored || {};       // finding id -> at
    s.pins = s.pins || {};             // id -> hash of last seen definition
    s.baselines = s.baselines || {};   // agentKind -> baseline object
    s.baselineVersions = s.baselineVersions || [];
    s.seen = s.seen || {};             // inventory fingerprints from the last scan
    s.firstRun = s.firstRun !== false;
    return s;
  }

  saveState() {
    const tmp = this.stateFile + '.tmp';
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.state, null, 1));
      fs.renameSync(tmp, this.stateFile);
    } catch (_) { /* disk full or locked: try again next time */ }
  }

  get settings() { return this.state.settings; }

  updateSettings(patch) {
    const s = this.state.settings;
    for (const [k, v] of Object.entries(patch || {})) {
      if (!(k in DEFAULT_SETTINGS)) continue;
      if (k === 'judge') s.judge = { ...s.judge, ...v };
      else if (k === 'fix') s.fix = { ...s.fix, ...v, custom: { ...s.fix.custom, ...((v && v.custom) || {}) } };
      else s[k] = v;
    }
    sanitize(s);
    this.saveState();
    return s;
  }

  loadEvents() {
    let txt = '';
    try { txt = fs.readFileSync(this.eventsFile, 'utf8'); } catch (_) { return; }
    const cutoff = Date.now() - this.state.settings.logDays * 86400000;
    let prev = '0'.repeat(64);
    const keep = [];
    for (const line of txt.split('\n')) {
      if (!line.trim()) continue;
      let e;
      try { e = JSON.parse(line); } catch (_) { this.chainOk = false; continue; }
      const { hash, ...body } = e;
      if (body.prev !== prev || sha256(JSON.stringify(body)) !== hash) this.chainOk = false;
      prev = hash;
      if (e.ts >= cutoff) keep.push(e);
    }
    this.lastHash = prev;
    this.events = keep.slice(-5000);
    // Old lines are dropped by rewriting the file with a fresh chain.
    if (keep.length < txt.split('\n').filter(Boolean).length) this.rewrite(keep);
  }

  rewrite(list) {
    let prev = '0'.repeat(64);
    const lines = list.map((e) => {
      const { hash, prev: _p, ...rest } = e;
      const body = { ...rest, prev };
      const h = sha256(JSON.stringify(body));
      prev = h;
      return JSON.stringify({ ...body, hash: h });
    });
    try { fs.writeFileSync(this.eventsFile, lines.join('\n') + (lines.length ? '\n' : '')); } catch (_) {}
    this.lastHash = prev;
    this.events = lines.map((l) => JSON.parse(l));
  }

  append(event) {
    const body = { ...event, ts: event.ts || Date.now(), prev: this.lastHash };
    const hash = sha256(JSON.stringify(body));
    const full = { ...body, hash };
    try { fs.appendFileSync(this.eventsFile, JSON.stringify(full) + '\n'); } catch (_) {}
    this.lastHash = hash;
    this.events.push(full);
    if (this.events.length > 5000) this.events.splice(0, this.events.length - 5000);
    return full;
  }

  // Check the whole file again (button in settings).
  verify() {
    let txt = '';
    try { txt = fs.readFileSync(this.eventsFile, 'utf8'); } catch (_) { return { ok: true, lines: 0 }; }
    let prev = '0'.repeat(64);
    let n = 0;
    for (const line of txt.split('\n')) {
      if (!line.trim()) continue;
      n++;
      let e;
      try { e = JSON.parse(line); } catch (_) { return { ok: false, line: n }; }
      const { hash, ...body } = e;
      if (body.prev !== prev || sha256(JSON.stringify(body)) !== hash) return { ok: false, line: n };
      prev = hash;
    }
    return { ok: true, lines: n };
  }
}

module.exports = { Store, DEFAULT_SETTINGS };
