'use strict';
// AgathOS - what an AI program is told about this PC.
//
// In the window a finding carries the sentence that gave it away ("copy yourself to every other folder"). An AI program is not given
// that sentence: it may be an attack on the reader. A finding is described here in our own words: what kind of thing it is, where it is,
// how serious it is and why. From the details of a finding only values of a harmless kind are taken (a count, the name of a program),
// cleaned, cut short and checked once more for sentences that give orders. Everything is plain data; the wrapper that says so is made
// by untrusted.js.
const Z = require('./untrusted');
const T = require('./textscan');

let EN = null;
function english() {
  if (!EN) { try { EN = require('../src/i18n.js').I18N.en || {}; } catch (_) { EN = {}; } }
  return EN;
}

const STATES = ['calm', 'watch', 'alarm'];
const rank = { calm: 0, watch: 1, alarm: 2 };
const state = (s) => (STATES.includes(s) ? s : 'calm');
const worst = (list) => list.reduce((w, s) => (rank[state(s)] > rank[w] ? state(s) : w), 'calm');

// Details of a finding that may be handed over. A number stays a number; a name is cleaned. Anything else (the sentence found, a command
// line, the words of an AI) is left out.
const NUMBERS = new Set(['n', 'was', 's', 'calls', 'port', 'a', 'm', 'pid', 'min', 'w', 'score', 'p', 'issues', 'mcp', 'x']);
const WORDS = new Set(['name', 'app', 'agent', 'host', 'provider', 'brand', 'script', 'label', 'pkg', 'kinds', 'kind', 'tool', 'where', 'folders',
  'folder', 'product', 'format', 'process', 'parent', 'chain', 'part', 'labels', 'action', 'fix', 'next', 'level', 'v', 'cve', 'file', 'agents',
  'from', 'to', 'browser', 'service', 'repos', 'sites', 'perms']);
// Codes that have their own words.
const CODED = { action: 'act.', fix: 'fixact.', next: 'act.', chain: 'chain.', part: 'xray.part.' };

// A short piece of text from outside: cleaned, and gone when it reads like an order.
function str(s, max = 60) {
  const x = Z.text(s, max);
  if (!x) return '';
  let r;
  try { r = T.scanText(x); } catch (_) { return '[removed]'; }
  return r.reasons.some((q) => q.key === 'file.injectionPhrase' || q.key === 'file.hiddenTags' || q.key === 'file.bidi') ? '[removed]' : x;
}

// The value of one detail: a string, or null when it may not be handed over.
function detail(key, v, dict) {
  if (v == null) return '';
  if (NUMBERS.has(key)) {
    if (typeof v === 'number') return Number.isFinite(v) ? String(Math.round(v * 100) / 100) : '';
    return /^\d{1,10}$/.test(String(v)) ? String(v) : null;
  }
  if (!WORDS.has(key)) return null;
  if (key === 'labels') return String(v).split('+').slice(0, 6).map((l) => str(dict['label.' + l] || l, 30)).join(' + ');
  if (key === 'agents') return v ? `(${str(v, 60)})` : '';
  if (key === 'file' || key === 'where') return str(String(v).split(/[\\/]/).pop() || v, key === 'where' ? 60 : 80);
  if (CODED[key]) return str(dict[CODED[key] + v] || v, 60);
  return str(v, 60);
}

// The English text of a reason, with the details put in. A detail that may not be handed over goes out of the sentence (with its quote
// marks), or becomes three dots when the sentence needs a word in that place.
function say(key, params) {
  const dict = english();
  const tpl = dict[key];
  if (typeof tpl !== 'string') return /^[\w.]{1,60}$/.test(String(key)) ? String(key) : '';
  const p = params && typeof params === 'object' ? params : {};
  const get = (k) => detail(k, p[k], dict);
  let s = tpl.replace(/(?:\s*:)?\s*["“‘]\{(\w+)\}["”’]/g, (m, k) => { const v = get(k); return v === null ? '' : m.replace(`{${k}}`, () => v); });
  s = s.replace(/\{(\w+)\}/g, (m, k) => { const v = get(k); return v === null ? '…' : v; });
  return Z.text(s.replace(/\s+([.,:])(?=\s|$)/g, '$1'), 220);
}

// [{ severity, text }]: what is wrong, worst first. Calm remarks only when there is nothing else.
function reasons(list, limit = 6) {
  const all = Array.isArray(list) ? list.filter((r) => r && typeof r === 'object' && typeof r.key === 'string') : [];
  const bad = all.filter((r) => r.sev !== 'calm');
  const use = (bad.length ? bad : all).slice().sort((a, b) => rank[state(b.sev)] - rank[state(a.sev)]).slice(0, limit);
  return use.map((r) => ({ severity: state(r.sev), text: say(r.key, r.params) })).filter((r) => r.text);
}

const base = (p) => String(p || '').split(/[\\/]/).filter(Boolean).pop() || '';

// What each kind of finding is called, and where its name is.
const KINDS = [
  ['mcp', 'mcp', (x) => x.name],
  ['files', 'file', (x) => base(x.path)],
  ['models', 'model', (x) => x.name || base(x.path)],
  ['ports', 'port', (x) => x.process || x.name || (x.port ? 'port ' + x.port : '')],
  ['autostarts', 'autostart', (x) => x.name],
  ['extensions', 'extension', (x) => x.name],
  ['backups', 'backup', (x) => x.names || x.id],
  ['packages', 'package', (x) => x.name || base(x.path)],
  ['copies', 'copy', (x) => x.name],
  ['links', 'link', (x) => x.label || x.name || x.host],
];

// Everything that is not calm, worst first.
function findings(snap, { limit = 50 } = {}) {
  const out = [];
  for (const [coll, kind, nameOf] of KINDS) {
    for (const x of Array.isArray(snap && snap[coll]) ? snap[coll] : []) {
      if (!x || state(x.state) === 'calm') continue;
      out.push({
        kind, name: str(nameOf(x), 60), ...(x.app ? { app: str(x.app, 40) } : {}), state: state(x.state),
        ...(x.short ? { where: str(x.short, 100) } : {}), approved: !!x.approved, reasons: reasons(x.reasons),
      });
    }
  }
  out.sort((a, b) => rank[b.state] - rank[a.state]);
  const max = Math.max(1, Math.min(200, Number(limit) || 50));
  return { total: out.length, shown: Math.min(out.length, max), items: out.slice(0, max) };
}

function agents(snap) {
  return (Array.isArray(snap && snap.agents) ? snap.agents : []).slice(0, 100).map((a) => ({
    name: str(a.name, 40), kind: str(a.kind, 20), state: state(a.state), running: Array.isArray(a.running) ? a.running.length : 0,
    paused: !!a.paused, score: Number.isFinite(a.score) ? Math.round(a.score) : 0, reasons: reasons(a.reasons, 5),
  }));
}

// since: only events after this time (milliseconds). Newest last.
function events(list, { since = 0, limit = 100 } = {}) {
  const min = Number(since) || 0;
  const max = Math.max(1, Math.min(200, Number(limit) || 100));
  return (Array.isArray(list) ? list : []).filter((e) => e && e.ts > min).slice(-max)
    .map((e) => ({ time: e.ts, severity: state(e.sev), watcher: str(e.watcher, 12), text: say(e.key, e.params) })).filter((e) => e.text);
}

function status(snap) {
  const w = Array.isArray(snap && snap.watchers) ? snap.watchers : [];
  const g = (snap && snap.guard) || {};
  return {
    state: worst(w.map((x) => x.state)), lastScan: Number(snap && snap.lastScan) || 0, scanning: !!(snap && snap.scanning),
    pausedAll: !!(snap && snap.pausedAll), lockdown: !!(snap && snap.lockdown),
    guard: { installed: !!g.installed, enabled: !!g.enabled, running: !!g.running },
    counts: Z.value(snap && snap.counts), logIntact: !(snap && snap.chainOk === false),
    watchers: w.map((x) => ({ id: str(x.id, 12), state: state(x.state) })),
    running: (Array.isArray(snap && snap.agents) ? snap.agents : []).filter((a) => a.running && a.running.length)
      .map((a) => ({ id: str(a.id, 30), name: str(a.name, 40), state: state(a.state), score: Number.isFinite(a.score) ? Math.round(a.score) : 0 })),
  };
}

module.exports = { say, reasons, findings, agents, events, status, str, detail };
