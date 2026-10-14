'use strict';
// AgathOS - "Fix it".
// Turns every finding into a concrete step, applies the steps you pick (or, when you
// switched auto-fix on, the steps your level allows) and keeps what is needed to undo them.
//
// Every step is reversible except "stop agent":
//   freeze      pause the agent's process tree                  undo: resume
//   block       freeze + firewall rule for the agent's program  undo: remove rule, resume
//   kill        stop the agent's process tree                   undo: -
//   localOnly   firewall: AI port only reachable from this PC   undo: remove rule
//   disable     take an MCP server out of the app's config      undo: put it back
//               (a copy of the whole file is kept as well)
//   clean       strip invisible characters from a file         undo: restore the copy
//   quarantine  rename a file to *.agathos-quarantine           undo: rename back
//   disableTask turn off a scheduled task                       undo: turn it on again
const fs = require('fs');
const path = require('path');
const U = require('./util');

// What each kind of finding can do, from gentle to hard. 'off' = leave it, show only.
const CATS = {
  agent: ['off', 'freeze', 'block', 'kill'],
  port: ['off', 'localOnly'],
  mcp: ['off', 'disable'],
  hidden: ['off', 'clean'],
  inject: ['off', 'quarantine'],
  model: ['off', 'quarantine'],
  auto: ['off', 'disableTask'],
};
const PRESETS = {
  gentle: { agent: 'freeze', port: 'localOnly', mcp: 'off', hidden: 'off', inject: 'off', model: 'off', auto: 'off' },
  firm: { agent: 'block', port: 'localOnly', mcp: 'disable', hidden: 'clean', inject: 'off', model: 'quarantine', auto: 'off' },
  max: { agent: 'kill', port: 'localOnly', mcp: 'disable', hidden: 'clean', inject: 'quarantine', model: 'quarantine', auto: 'disableTask' },
};
const LEVELS = ['gentle', 'firm', 'max', 'custom'];
const DEFAULT_FIX = { auto: false, level: 'firm', minSev: 'alarm', custom: { ...PRESETS.firm } };
const RANK = { calm: 0, watch: 1, alarm: 2 };
const QSUFFIX = '.agathos-quarantine';

// Without AgathOS Guard there is no firewall: "pause + cut internet" becomes "pause".
function optionsFor(cat) {
  return !U.IS_WIN && cat === 'agent' ? CATS.agent.filter((o) => o !== 'block') : CATS[cat];
}

function policy(fix) {
  const f = fix || DEFAULT_FIX;
  if (f.level !== 'custom') return PRESETS[f.level] || PRESETS.firm;
  const out = {};
  for (const [cat, opts] of Object.entries(CATS)) {
    const v = f.custom && f.custom[cat];
    out[cat] = opts.includes(v) ? v : PRESETS.firm[cat];
  }
  return out;
}

const HIDDEN_KEYS = new Set(['file.hiddenTags', 'file.hidden', 'file.bidi']);
const MANUAL_FILE_KEYS = new Set(['file.secret', 'config.autoApprove', 'config.baseUrl', 'config.repoHooks']);

// ---------- dismiss ----------
// "Dismiss" = you looked at it and accept it. The finding stops counting until it changes:
// the fingerprint is the set of reasons, so a new kind of problem brings it back.
const fingerprint = (reasons) => U.sha256(JSON.stringify((reasons || []).map((r) => `${r.key}|${r.sev}`).sort())).slice(0, 16);
function targetKey(t) {
  if (!t) return null;
  if (t.type === 'agent') return `agent:${t.id}`;
  if (t.type === 'port') return `port:${t.port}`;
  if (t.type === 'mcp') return `mcp:${t.id}`;
  if (t.type === 'file') return `file:${t.id}`;
  if (t.type === 'model') return `model:${U.sha256(String(t.path)).slice(0, 16)}`;
  if (t.type === 'auto') return `auto:${t.id}`;
  if (t.type === 'ext') return `ext:${t.id}`;
  if (t.type === 'backup') return `backup:${t.id}`;
  if (t.type === 'pkg') return `pkg:${t.id}`;
  if (t.type === 'link') return `link:${t.id}`;
  if (t.type === 'copy') return `copy:${t.id}`;
  return null;
}
function isDismissed(state, key, reasons) {
  const d = state.dismissed && key && state.dismissed[key];
  return !!d && d.fp === fingerprint(reasons);
}

// ---------- plan ----------
// Builds the list of steps from the engine's current findings.
// sev filter: 'watch' = everything that is not calm (the button), 'alarm' = only danger (auto mode).
function plan(engine, fix, minSev = 'watch') {
  const pol = policy(fix);
  const steps = [];
  const min = RANK[minSev] || 1;
  const dismissed = engine.store.state.dismissed || {};
  const add = (s) => {
    if (RANK[s.sev] < min) return;
    s.tkey = targetKey(s.target);
    s.fp = fingerprint(s.reasons);
    if (s.tkey && dismissed[s.tkey] && dismissed[s.tkey].fp === itemFp(s.tkey)) return;
    // Watch-level items get "off" by default: you decide. Danger gets the level's action.
    let preset = s.cat === 'manual' ? 'guide' : pol[s.cat];
    if (s.cat === 'agent' && !optionsFor('agent').includes(preset)) preset = 'freeze';
    const action = s.cat === 'manual' ? 'guide' : (s.sev === 'alarm' || s.cat === 'hidden' || s.cat === 'port') ? preset : 'off';
    steps.push({ ...s, action, preset, options: s.cat === 'manual' ? ['guide'] : optionsFor(s.cat) });
  };
  const inv = engine.inventory;
  const snapAgents = engine.agentsView();
  const itemFp = (key) => fingerprint(itemReasons(engine, key, snapAgents));

  for (const a of snapAgents) {
    if (!a.running.length || a.state !== 'alarm') continue;
    add({ id: `agent:${a.id}`, cat: 'agent', sev: a.state, name: a.name, where: `PID ${a.running[0].pid}`, reasons: a.reasons, target: { type: 'agent', id: a.id }, paused: a.paused });
  }
  for (const p of inv.ports) {
    if (!p.exposed) continue;
    // A firewall rule needs AgathOS Guard, which only exists on Windows. On a Mac it is a step for you.
    add({ id: `port:${p.port}`, cat: U.IS_WIN ? 'port' : 'manual', sev: 'alarm', name: `${p.product} · ${p.port}`, where: `${p.addr}:${p.port}`, reasons: [{ key: 'port.open', params: { product: p.product, addr: p.addr, port: p.port }, sev: 'alarm' }], target: { type: 'port', port: p.port }, needGuard: true });
  }
  for (const m of inv.mcp) {
    if (m.state === 'calm' || m.approved) continue;
    add({ id: `mcp:${m.id}`, cat: 'mcp', sev: m.state, name: m.name, where: `${m.app} · ${U.shortPath(m.file)}`, reasons: m.reasons, target: { type: 'mcp', id: m.id } });
  }
  for (const f of [...inv.files, ...inv.configs]) {
    if (f.state === 'calm') continue;
    if (engine.store.state.ignored[f.id]) continue;
    const reasons = f.reasons || [];
    const base = { sev: f.state, name: path.basename(String(f.path)), where: U.shortPath(f.path), target: { type: 'file', id: f.id, path: f.path } };
    const hidden = reasons.filter((r) => HIDDEN_KEYS.has(r.key));
    const inject = reasons.filter((r) => r.key === 'file.injectionPhrase');
    const manual = reasons.filter((r) => MANUAL_FILE_KEYS.has(r.key));
    const isFile = !String(f.path).startsWith('Environment');
    if (inject.length && isFile) add({ ...base, id: `inject:${f.id}`, cat: 'inject', sev: 'alarm', reasons: inject });
    if (hidden.length && isFile) add({ ...base, id: `hidden:${f.id}`, cat: 'hidden', sev: worstOf(hidden), reasons: hidden });
    if (manual.length) add({ ...base, id: `manual:${f.id}`, cat: 'manual', sev: worstOf(manual), reasons: manual });
  }
  for (const m of inv.models) {
    if (m.state === 'calm') continue;
    const id = U.sha256(m.path).slice(0, 16);
    add({ id: `model:${id}`, cat: 'model', sev: m.state, name: m.name || path.basename(m.path), where: U.shortPath(m.path), reasons: m.reasons, target: { type: 'model', path: m.path } });
  }
  // No sign of a backup: only you can turn one on.
  for (const b of inv.backups || []) {
    if (b.state === 'calm') continue;
    add({ id: `manual:backup:${b.id}`, cat: 'manual', sev: b.state, name: b.names, where: '', reasons: b.reasons.filter((r) => r.sev !== 'calm'), target: { type: 'backup', id: b.id } });
  }
  // Install scripts and workflows that look like a worm: nothing is deleted for you, you decide.
  for (const p of inv.packages || []) {
    if (p.state === 'calm') continue;
    add({ id: `manual:pkg:${p.id}`, cat: 'manual', sev: p.state, name: p.name, where: U.shortPath(p.path), reasons: p.reasons, target: { type: 'pkg', id: p.id } });
  }
  // Where a program sends its prompts: AgathOS does not rewrite your settings; you approve the address or change it yourself.
  for (const l of inv.links || []) {
    if (l.dupOf || l.state === 'calm') continue;
    add({ id: `manual:link:${l.id}`, cat: 'manual', sev: l.state, name: l.kind === 'board' ? `${l.name} · ${l.label}` : `${l.app} → ${l.label}`, where: l.file && l.file !== 'Environment' ? U.shortPath(l.file) : (l.file || ''),
      reasons: l.reasons.filter((r) => r.sev !== 'calm'), target: { type: 'link', id: l.id } });
  }
  // Copy Guard: an order to copy, a text that spreads, a model in a place where copies leave the PC. Nothing is deleted for you: you look, then fix it or approve it.
  for (const c of inv.copies || []) {
    if (c.state === 'calm') continue;
    const where = c.ctype === 'spread' ? `${U.shortPath(c.files && c.files[0] || '')}${c.n > 1 ? ` (+${c.n - 1})` : ''}` : c.file ? U.shortPath(c.file) : '';
    add({ id: `manual:copy:${c.id}`, cat: 'manual', sev: c.state, name: c.name, where, reasons: c.reasons.filter((r) => r.sev !== 'calm'), target: { type: 'copy', id: c.id } });
  }
  // Browser extensions: AgathOS cannot remove them for you; you decide in the browser.
  for (const x of inv.extensions || []) {
    if (x.state === 'calm') continue;
    add({ id: `manual:ext:${x.id}`, cat: 'manual', sev: x.state, name: `${x.name} (${x.browser})`, where: U.shortPath(x.path), reasons: x.reasons, target: { type: 'ext', id: x.id } });
  }
  for (const a of inv.autostarts) {
    if (a.state === 'calm' || engine.store.state.ignored[a.id]) continue;
    if (a.kind === 'task' || a.kind === 'launchd') add({ id: `auto:${a.id}`, cat: 'auto', sev: a.state, name: a.name, where: a.command.slice(0, 160), reasons: a.reasons, target: { type: 'auto', id: a.id, name: a.name, taskPath: a.where } });
    else add({ id: `manual:${a.id}`, cat: 'manual', sev: a.state, name: a.name, where: a.command.slice(0, 160), reasons: a.reasons, target: { type: 'auto', id: a.id } });
  }
  // Agents that run with safety switched off: only you can change how you start them.
  for (const a of snapAgents) {
    const flag = (a.reasons || []).find((r) => r.key === 'flag.dangerous');
    if (a.running.length && flag && a.state !== 'alarm') add({ id: `manual:flag:${a.id}`, cat: 'manual', sev: 'watch', name: a.name, where: flag.params.flag || '', reasons: [flag], target: { type: 'agent', id: a.id } });
  }
  steps.sort((x, y) => (RANK[y.sev] - RANK[x.sev]) || (x.cat === 'manual') - (y.cat === 'manual'));
  return steps;
}

// All reasons of the item behind a target key (one file can give several steps).
function itemReasons(engine, key, agents) {
  const [kind, ...rest] = String(key).split(':');
  const id = rest.join(':');
  const inv = engine.inventory;
  if (kind === 'agent') { const a = (agents || engine.agentsView()).find((x) => x.id === id); return a ? a.reasons : []; }
  if (kind === 'port') { const p = inv.ports.find((x) => String(x.port) === id); return p ? p.reasons : []; }
  if (kind === 'mcp') { const m = inv.mcp.find((x) => x.id === id); return m ? m.reasons : []; }
  if (kind === 'file') { const f = [...inv.files, ...inv.configs].find((x) => x.id === id); return f ? f.reasons : []; }
  if (kind === 'model') { const m = inv.models.find((x) => U.sha256(x.path).slice(0, 16) === id); return m ? m.reasons : []; }
  if (kind === 'auto') { const a = inv.autostarts.find((x) => x.id === id); return a ? a.reasons : []; }
  if (kind === 'ext') { const x = (inv.extensions || []).find((e) => e.id === id); return x ? x.reasons : []; }
  if (kind === 'pkg') { const p = (inv.packages || []).find((e) => e.id === id); return p ? p.reasons : []; }
  if (kind === 'backup') { const b = (inv.backups || []).find((e) => e.id === id); return b ? b.reasons : []; }
  if (kind === 'link') { const l = (inv.links || []).find((e) => e.id === id); return l ? l.reasons : []; }
  if (kind === 'copy') { const c = (inv.copies || []).find((e) => e.id === id); return c ? c.reasons : []; }
  return [];
}

function dismiss(engine, key) {
  const steps = plan(engine, engine.store.settings.fix, 'watch');
  const step = steps.find((x) => x.tkey === key);
  if (!step) return { ok: false };
  engine.store.state.dismissed = engine.store.state.dismissed || {};
  engine.store.state.dismissed[key] = { fp: fingerprint(itemReasons(engine, key)), at: Date.now(), name: step.name, sev: step.sev };
  engine.store.saveState();
  engine.event({ key: 'fix.dismissEv', sev: 'calm', watcher: watcherOf(step.cat), params: { name: step.name } });
  return { ok: true };
}
function restore(engine, key) {
  const d = engine.store.state.dismissed && engine.store.state.dismissed[key];
  if (!d) return { ok: false };
  delete engine.store.state.dismissed[key];
  engine.store.saveState();
  engine.event({ key: 'fix.restoreEv', sev: 'calm', watcher: 'gate', params: { name: d.name } });
  return { ok: true };
}

const worstOf = (reasons) => reasons.reduce((a, r) => (RANK[r.sev] > RANK[a] ? r.sev : a), 'calm');

// ---------- apply ----------
// picks: [{ id, action }]. The plan is rebuilt here, so the window can only choose
// among steps the engine itself found; it can never pass its own paths or targets.
async function apply(engine, picks, fix, { source = 'user' } = {}) {
  const current = plan(engine, fix, 'watch');
  const results = [];
  for (const pick of picks || []) {
    const step = current.find((s) => s.id === pick.id);
    if (!step || step.cat === 'manual') continue;
    const action = pick.action || step.action;
    if (!step.options.includes(action) || action === 'off') continue;
    let r;
    try { r = await doAction(engine, step, action); } catch (err) { r = { ok: false, error: String(err && err.message || err) }; }
    const rec = { rid: U.sha256(`${step.id}|${action}|${Date.now()}|${Math.random()}`).slice(0, 12), at: Date.now(), stepId: step.id, cat: step.cat, action, name: step.name, where: step.where, ok: !!r.ok, undo: r.ok ? r.undo || null : null, source, needGuard: !!r.needGuard, error: r.error || null };
    results.push(rec);
    engine.event({ key: rec.ok ? 'fix.applied' : 'fix.failed', sev: rec.ok ? 'calm' : 'watch', watcher: watcherOf(step.cat), params: { fix: action, name: step.name } });
    if (rec.ok) {
      const list = engine.store.state.remedies || [];
      list.unshift(rec);
      engine.store.state.remedies = list.slice(0, 100);
    }
  }
  engine.store.saveState();
  return results;
}

const watcherOf = (cat) => ({ agent: 'proc', port: 'net', mcp: 'gate', hidden: 'traps', inject: 'traps', model: 'files', auto: 'proc' }[cat] || 'gate');

async function doAction(engine, step, action) {
  const t = step.target;
  switch (action) {
    case 'freeze': {
      if (step.paused) return { ok: true, undo: { type: 'resume', id: t.id } };
      const r = await engine.freezeAgent(t.id, 'fix');
      return { ok: r.ok, undo: { type: 'resume', id: t.id } };
    }
    case 'block': {
      const f = step.paused ? { ok: true } : await engine.freezeAgent(t.id, 'fix');
      const b = await engine.blockAgent(t.id, true);
      // Without Guard the freeze still counts; the firewall part is reported separately.
      return { ok: f.ok || b.ok, needGuard: !!b.needGuard, undo: { type: 'unblock', id: t.id, blocked: !!b.ok } };
    }
    case 'kill': {
      const r = await engine.killAgent(t.id);
      return { ok: r.ok, undo: null };
    }
    case 'localOnly': {
      const r = await engine.localOnly(t.port, true);
      return { ok: r.ok, needGuard: !!r.needGuard, undo: { type: 'localOnlyOff', port: t.port } };
    }
    case 'disable': {
      const m = engine.inventory.mcp.find((x) => x.id === t.id);
      if (!m) return { ok: false, error: 'gone' };
      return disableMcp(engine.store.dir, m);
    }
    case 'clean': return cleanFile(engine.store.dir, t.path);
    case 'quarantine': return quarantine(t.path);
    case 'disableTask': return taskEnabled(t.name, t.taskPath, false);
    default: return { ok: false, error: 'unknown action' };
  }
}

async function undo(engine, rid) {
  const list = engine.store.state.remedies || [];
  const rec = list.find((r) => r.rid === rid);
  if (!rec || !rec.undo || rec.undone) return { ok: false };
  const u = rec.undo;
  let r = { ok: false };
  try {
    if (u.type === 'resume') r = await engine.resumeAgent(u.id);
    else if (u.type === 'unblock') { if (u.blocked) await engine.blockAgent(u.id, false); r = await engine.resumeAgent(u.id); r = { ok: true }; }
    else if (u.type === 'localOnlyOff') r = await engine.localOnly(u.port, false);
    else if (u.type === 'mcpRestore') r = restoreMcp(u);
    else if (u.type === 'fileRestore') r = restoreFile(u);
    else if (u.type === 'unquarantine') r = unquarantine(u);
    else if (u.type === 'taskOn') r = await taskEnabled(u.name, u.taskPath, true);
  } catch (err) { r = { ok: false, error: String(err && err.message || err) }; }
  if (r.ok) {
    rec.undone = Date.now();
    engine.event({ key: 'fix.undoneEv', sev: 'calm', watcher: watcherOf(rec.cat), params: { fix: rec.action, name: rec.name } });
    engine.store.saveState();
  }
  return { ok: !!r.ok, error: r.error };
}

// ---------- MCP config editing ----------
function backupDir(storeDir) {
  const d = path.join(storeDir, 'quarantine');
  fs.mkdirSync(d, { recursive: true });
  return d;
}
function backupCopy(storeDir, file) {
  const dst = path.join(backupDir(storeDir), `${Date.now()}-${U.sha256(file).slice(0, 8)}-${path.basename(file)}`);
  fs.copyFileSync(file, dst);
  return dst;
}
function detectIndent(text) {
  const m = text.match(/\n([ \t]+)"/);
  return m ? m[1] : 2;
}
function parseStrict(text) {
  try { return JSON.parse(text.replace(/^﻿/, '')); } catch (_) { return undefined; }
}

const JSON_CONTAINERS = [['mcpServers'], ['servers'], ['amp.mcpServers'], ['context_servers'], ['mcp', 'servers'], ['mcp'], ['mcp.servers']];
const dig = (obj, keys) => keys.reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);
const own = (o, k) => o && typeof o === 'object' && Object.prototype.hasOwnProperty.call(o, k);

// Finds where a server named the way inventory.serversFromJson names it lives in the JSON.
function locate(json, name) {
  for (const keys of JSON_CONTAINERS) {
    const o = dig(json, keys);
    if (own(o, name) && o[name] && typeof o[name] === 'object' && !Array.isArray(o[name])) return { keys, key: name };
  }
  const pm = name.match(/^(.*) \((.+)\)$/);
  if (pm && json.projects && typeof json.projects === 'object') {
    for (const [proj, p] of Object.entries(json.projects)) {
      if (path.basename(proj) === pm[2] && p && own(p.mcpServers, pm[1])) return { keys: ['projects', proj, 'mcpServers'], key: pm[1] };
    }
  }
  const cm = name.match(/^server-(\d+)$/);
  const arr = dig(json, ['experimental', 'modelContextProtocolServers']);
  if (cm && Array.isArray(arr) && arr[Number(cm[1]) - 1]) return { keys: ['experimental', 'modelContextProtocolServers'], index: Number(cm[1]) - 1 };
  return null;
}

function disableMcp(storeDir, m) {
  const file = m.file;
  const text = fs.readFileSync(file, 'utf8');
  const backup = backupCopy(storeDir, file);
  if (/\.toml$/i.test(file)) {
    const cut = cutTomlServer(text, m.name);
    if (!cut) return { ok: false, error: 'not found' };
    fs.writeFileSync(file, cut.text);
    return { ok: true, undo: { type: 'mcpRestore', file, toml: cut.removed, backup } };
  }
  const json = parseStrict(text);
  // A file with comments (JSONC) is not rewritten: we would lose your comments.
  if (json === undefined) return { ok: false, error: 'jsonc' };
  const loc = locate(json, m.name);
  if (!loc) return { ok: false, error: 'not found' };
  const parent = dig(json, loc.keys);
  let value;
  if ('index' in loc) value = parent.splice(loc.index, 1)[0];
  else { value = parent[loc.key]; delete parent[loc.key]; }
  fs.writeFileSync(file, JSON.stringify(json, null, detectIndent(text)) + (text.endsWith('\n') ? '\n' : ''));
  return { ok: true, undo: { type: 'mcpRestore', file, keys: loc.keys, key: loc.key, index: loc.index, value, backup } };
}

function restoreMcp(u) {
  const text = U.readText(u.file);
  if (text == null) return { ok: false, error: 'file gone' };
  if (u.toml != null) {
    fs.writeFileSync(u.file, text.replace(/\s*$/, '\n\n') + u.toml.trim() + '\n');
    return { ok: true };
  }
  const json = parseStrict(text);
  if (json === undefined) return { ok: false, error: 'jsonc' };
  let o = json;
  for (const k of u.keys) {
    if (!o[k] || typeof o[k] !== 'object') o[k] = u.index != null && k === u.keys[u.keys.length - 1] ? [] : {};
    o = o[k];
  }
  if (u.index != null && Array.isArray(o)) o.splice(Math.min(u.index, o.length), 0, u.value);
  else o[u.key] = u.value;
  fs.writeFileSync(u.file, JSON.stringify(json, null, detectIndent(text)) + (text.endsWith('\n') ? '\n' : ''));
  return { ok: true };
}

// Removes [mcp_servers.<name>] and its sub tables ([mcp_servers.<name>.env]) from a TOML file.
function cutTomlServer(text, name) {
  const esc = name.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  const head = new RegExp(`^\\s*\\[mcp_servers\\.(?:"${esc}"|'${esc}'|${esc})(?:\\.[^\\]]+)?\\]\\s*$`);
  const lines = text.split(/\r?\n/);
  const eol = text.includes('\r\n') ? '\r\n' : '\n';
  const keep = [];
  const removed = [];
  let inside = false;
  for (const line of lines) {
    if (/^\s*\[/.test(line)) inside = head.test(line);
    (inside ? removed : keep).push(line);
  }
  if (!removed.length) return null;
  return { text: keep.join(eol), removed: removed.join(eol) };
}

// ---------- files ----------
const STRIP = /[​-‍⁠-⁤᠎­‪-‮⁦-⁩]|[\u{E0000}-\u{E007F}]/gu;
function cleanFile(storeDir, file) {
  if (!file || !path.isAbsolute(file)) return { ok: false, error: 'path' };
  const text = fs.readFileSync(file, 'utf8');
  const bom = text.charCodeAt(0) === 0xfeff ? '﻿' : '';
  const cleaned = bom + text.slice(bom.length).replace(STRIP, '').replace(/﻿/g, '');
  if (cleaned === text) return { ok: false, error: 'nothing to clean' };
  const backup = backupCopy(storeDir, file);
  fs.writeFileSync(file, cleaned);
  return { ok: true, undo: { type: 'fileRestore', file, backup, hash: U.sha256(cleaned) } };
}
function restoreFile(u) {
  const now = U.readText(u.file);
  // Changed again since we cleaned it? Then do not overwrite your newer work.
  if (now != null && U.sha256(now) !== u.hash) return { ok: false, error: 'changed since' };
  fs.copyFileSync(u.backup, u.file);
  return { ok: true };
}
function quarantine(file) {
  if (!file || !path.isAbsolute(file) || !U.exists(file)) return { ok: false, error: 'path' };
  const dst = file + QSUFFIX;
  if (U.exists(dst)) return { ok: false, error: 'exists' };
  fs.renameSync(file, dst);
  return { ok: true, undo: { type: 'unquarantine', file, dst } };
}
function unquarantine(u) {
  if (U.exists(u.file)) return { ok: false, error: 'exists' };
  fs.renameSync(u.dst, u.file);
  return { ok: true };
}

// ---------- scheduled tasks ----------
async function taskEnabled(name, taskPath, on) {
  if (U.IS_MAC) {
    const r = await require('./mac').launchAgentEnabled(name, taskPath, on);
    return { ...r, undo: r.ok && !on ? { type: 'taskOn', name, taskPath } : undefined };
  }
  if (!U.IS_WIN) return { ok: false, error: 'windows only' };
  const out = await U.ps.run(`try { ${on ? 'Enable' : 'Disable'}-ScheduledTask -TaskName ${U.psq(name)} -TaskPath ${U.psq(taskPath || '\\')} -ErrorAction Stop | Out-Null; 'AGATHOS_OK' } catch { 'AGATHOS_FAIL ' + $_.Exception.Message }`, 20000);
  const ok = /AGATHOS_OK/.test(out || '');
  return { ok, error: ok ? null : String(out || '').replace('AGATHOS_FAIL', '').trim().slice(0, 200), undo: ok && !on ? { type: 'taskOn', name, taskPath } : undefined };
}

// ---------- auto mode ----------
// Called after a scan and after every alarm. Only runs when you switched it on.
// Each step runs at most once per hour, so a finding that cannot be fixed does not loop.
async function auto(engine) {
  const fix = engine.store.settings.fix || DEFAULT_FIX;
  if (!fix.auto || engine.fixing) return [];
  engine.fixing = true;
  try {
    const done = engine.autoDone || (engine.autoDone = new Map());
    const now = Date.now();
    const picks = plan(engine, fix, fix.minSev === 'watch' ? 'watch' : 'alarm')
      .filter((s) => s.cat !== 'manual' && s.preset !== 'off' && (s.sev === 'alarm' || fix.minSev === 'watch'))
      .filter((s) => now - (done.get(s.id) || 0) > 3600000)
      .map((s) => { done.set(s.id, now); return { id: s.id, action: s.preset }; });
    if (!picks.length) return [];
    const res = await apply(engine, picks, fix, { source: 'auto' });
    const ok = res.filter((r) => r.ok).length;
    if (ok) engine.event({ key: 'fix.auto', sev: 'watch', watcher: 'gate', params: { n: ok } });
    return res;
  } finally {
    engine.fixing = false;
  }
}

module.exports = { fingerprint, targetKey, isDismissed, itemReasons, dismiss, restore, CATS, PRESETS, LEVELS, DEFAULT_FIX, QSUFFIX, policy, plan, apply, undo, auto, locate, cutTomlServer, cleanFile, quarantine, disableMcp, restoreMcp, restoreFile, unquarantine };
