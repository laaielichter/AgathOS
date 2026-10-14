'use strict';
// AgathOS - macOS. The same watchers as on Windows, built on the tools every Mac has:
//   ps         process list with parent, start time, path and command line
//   netstat    open TCP ports and connections per process (lsof is the way back when netstat does not say which process)
//   SIGSTOP    freeze (SIGCONT resumes); SIGTERM/SIGKILL to stop
//   launchd    LaunchAgents and LaunchDaemons (autostart), launchctl to turn them off
//   codesign   who signed a program
// No admin rights needed. AgathOS Guard (firewall and deep logging) is Windows only.
const fs = require('fs');
const os = require('os');
const path = require('path');
const { execFile } = require('child_process');
const U = require('./util');

const IS_MAC = process.platform === 'darwin';
const ENV = { ...process.env, LC_ALL: 'C', LANG: 'C' };

function run(cmd, args, timeout = 8000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, env: ENV, maxBuffer: 16 * 1024 * 1024 }, (err, stdout, stderr) => {
      resolve({ ok: !err, code: err ? (typeof err.code === 'number' ? err.code : 1) : 0, out: String(stdout || ''), err: String(stderr || '') });
    });
  });
}

// ---------- PATH ----------
// Apps started from the Dock get a short PATH (/usr/bin:/bin...). Agents live in
// Homebrew, npm, bun, cargo or ~/.local/bin, so ask the login shell once.
async function fixPath() {
  if (!IS_MAC) return;
  const extra = ['/opt/homebrew/bin', '/usr/local/bin', path.join(U.HOME, '.local', 'bin'), path.join(U.HOME, '.npm-global', 'bin'),
    path.join(U.HOME, '.bun', 'bin'), path.join(U.HOME, '.cargo', 'bin'), path.join(U.HOME, '.volta', 'bin'), path.join(U.HOME, '.claude', 'local')];
  const shell = process.env.SHELL && /\/(zsh|bash)$/.test(process.env.SHELL) ? process.env.SHELL : '/bin/zsh';
  const r = await run(shell, ['-ilc', 'printf "__P__%s__P__" "$PATH"'], 4000);
  const m = r.out.match(/__P__(.*)__P__/);
  const parts = [...(m ? m[1].split(':') : []), ...String(process.env.PATH || '').split(':'), ...extra].filter(Boolean);
  process.env.PATH = [...new Set(parts)].join(':');
  ENV.PATH = process.env.PATH;
}

// ---------- processes ----------
// Same shape as the Windows list: { p, pp, n, c, e, t }.
async function listProcesses() {
  if (!IS_MAC) return [];
  const [a, b] = await Promise.all([
    run('/bin/ps', ['-axww', '-o', 'pid=,ppid=,lstart=,comm='], 10000),
    run('/bin/ps', ['-axww', '-o', 'pid=,args='], 10000),
  ]);
  if (!a.ok) return [];
  return parsePs(a.out, b.out);
}
function parsePs(commOut, argsOut) {
  const args = new Map();
  for (const line of argsOut.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(.*)$/);
    if (m) args.set(+m[1], m[2]);
  }
  const rows = [];
  for (const line of commOut.split('\n')) {
    const m = line.match(/^\s*(\d+)\s+(\d+)\s+(\w{3}\s+\w{3}\s+\d+\s+\d+:\d+:\d+\s+\d{4})\s+(.*)$/);
    if (!m) continue;
    const comm = m[4].trim();
    const pid = +m[1];
    rows.push({ p: pid, pp: +m[2], n: path.basename(comm).replace(/^-/, ''), c: args.get(pid) || comm, e: comm.startsWith('/') ? comm : null, t: Date.parse(m[3]) || 0 });
  }
  return rows;
}

// ---------- network ----------
function splitAddr(s) {
  const m = String(s).match(/^\[?(.*?)\]?:(\d+|\*)$/);
  if (!m) return { a: '', p: 0 };
  return { a: m[1] === '*' ? '0.0.0.0' : m[1], p: m[2] === '*' ? 0 : +m[2] };
}

// netstat writes an address as host.port ("192.168.1.5.443", "::1.631", "*.22") and "*.*" for nothing.
function splitNetstatAddr(s) {
  const t = String(s);
  const i = t.lastIndexOf('.');
  if (i < 0) return { a: '', p: 0 };
  const host = t.slice(0, i).replace(/%.*$/, '');
  const port = t.slice(i + 1);
  return { a: host === '*' || host === '' ? '0.0.0.0' : host, p: port === '*' ? 0 : +port || 0 };
}
const NS_STATE = { LISTEN: 'Listen', ESTABLISHED: 'Established', SYN_SENT: 'SynSent' };
// "netstat -anv -p tcp" names the process of every socket: as "name:pid" in one column (newer macOS), or as "pid epid" in two (older).
const NS_NEW = /^(tcp\S*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+([A-Z][A-Z_0-9]*)\s+\d+\s+\d+\s+\d+\s+\d+\s+(.*?):(\d+)\s+[0-9a-f]{5}\s+[0-9a-f]{8}\b/i;
const NS_OLD = /^(tcp\S*)\s+\d+\s+\d+\s+(\S+)\s+(\S+)\s+([A-Z][A-Z_0-9]*)\s+\d+\s+\d+\s+(\d+)\s+(\d+)\s+[0-9a-f]{5}\s+[0-9a-f]{8}\b/i;
// Gives the rows { la, lp, ra, rp, state, pid, n } for listeners, open connections and attempts. Other states are left out.
function parseNetstat(text) {
  const rows = [];
  let mode = null;
  for (const raw of String(text || '').split('\n')) {
    const line = raw.trim();
    if (/^Proto\b/.test(line)) { mode = /process:pid/.test(line) ? 'new' : /\bpid\b/.test(line) ? 'old' : null; continue; }
    if (!mode || !/^tcp/.test(line)) continue;
    const m = (mode === 'new' ? NS_NEW : NS_OLD).exec(line);
    if (!m) continue;
    const state = NS_STATE[m[4].toUpperCase()];
    if (!state) continue;
    const l = splitNetstatAddr(m[2]);
    const r = splitNetstatAddr(m[3]);
    const pid = mode === 'new' ? +m[6] : +m[5];
    rows.push({ la: l.a, lp: l.p, ra: r.a, rp: r.p, state, pid, n: mode === 'new' ? m[5] : '' });
  }
  return rows;
}
async function netstatRows() {
  const r = await run('/usr/sbin/netstat', ['-anv', '-p', 'tcp'], 8000);
  return r.ok ? parseNetstat(r.out) : [];
}
async function connections() {
  if (!IS_MAC) return [];
  const rows = await netstatRows();
  if (rows.length) return rows.filter((x) => x.state === 'Listen' || x.state === 'Established');
  const r = await run('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:LISTEN,ESTABLISHED', '-F', 'pcnT'], 12000);
  return parseLsof(r.out);
}
// Outgoing connections and attempts (SYN_SENT) for the worm watch.
async function attempts() {
  if (!IS_MAC) return [];
  const rows = await netstatRows();
  if (rows.length) return rows.filter((x) => x.state === 'SynSent' || x.state === 'Established');
  const r = await run('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:SYN_SENT,ESTABLISHED', '-F', 'pcnT'], 6000);
  return parseLsof(r.out, true).filter((x) => x.state !== 'Listen');
}
function parseLsof(text, withAttempts = false) {
  if (!text) return [];
  const rows = [];
  let pid = 0;
  let name = '';
  let cur = null;
  for (const line of text.split('\n')) {
    const k = line[0];
    const v = line.slice(1);
    if (k === 'p') { pid = +v; name = ''; cur = null; }
    else if (k === 'c') name = v;
    else if (k === 'n') {
      const [l, rem] = v.split('->');
      const la = splitAddr(l);
      const ra = rem ? splitAddr(rem) : { a: '0.0.0.0', p: 0 };
      cur = { la: la.a, lp: la.p, ra: ra.a, rp: ra.p, state: rem ? 'Established' : 'Listen', pid, n: name };
      rows.push(cur);
    } else if (k === 'T' && cur && v.startsWith('ST=')) {
      cur.state = /LISTEN/.test(v) ? 'Listen' : /ESTABLISHED/.test(v) ? 'Established' : /SYN_SENT/.test(v) ? 'SynSent' : v.slice(3);
    }
  }
  return rows.filter((x) => x.state === 'Listen' || x.state === 'Established' || (withAttempts && x.state === 'SynSent'));
}

// ---------- stop button ----------
const PROTECTED = /^(launchd|kernel_task|windowserver|loginwindow|finder|dock|systemuiserver|controlcenter|coreservicesd|agathos.*|electron.*)$/i;
const safe = (pid, name) => pid > 1 && pid !== process.pid && pid !== process.ppid && !PROTECTED.test(String(name || ''));

function signalAll(pids, sig, names = {}) {
  const done = [];
  for (const pid of pids) {
    if (!safe(pid, names[pid])) continue;
    try { process.kill(pid, sig); done.push(pid); } catch (_) {}
  }
  return done;
}
async function suspend(pids, names = {}) {
  // Parent first, so it cannot start new children while we work down the tree.
  const done = signalAll(pids, 'SIGSTOP', names);
  return { ok: done.length > 0, done };
}
async function resume(pids) {
  const done = signalAll([...pids].reverse(), 'SIGCONT');
  return { ok: done.length > 0, done };
}
async function kill(rootPid, name, tree = []) {
  if (!safe(rootPid, name)) return { ok: false };
  const all = [...new Set([rootPid, ...tree])];
  // Frozen processes cannot handle SIGTERM: wake them first.
  signalAll(all, 'SIGCONT');
  const done = signalAll(all, 'SIGTERM');
  setTimeout(() => signalAll(all, 'SIGKILL'), 2500);
  return { ok: done.length > 0 };
}

// ---------- autostart (launchd) ----------
const LAUNCH_DIRS = [
  [path.join(U.HOME, 'Library', 'LaunchAgents'), 'launchd'],
  ['/Library/LaunchAgents', 'launchd-system'],
  ['/Library/LaunchDaemons', 'launchd-system'],
];
async function plist(file) {
  const r = await run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file], 4000);
  try { return JSON.parse(r.out); } catch (_) { return null; }
}
async function autostarts() {
  if (!IS_MAC) return [];
  const out = [];
  for (const [dir, kind] of LAUNCH_DIRS) {
    let names = [];
    try { names = fs.readdirSync(dir).filter((n) => n.endsWith('.plist')); } catch (_) { continue; }
    for (const n of names.slice(0, 300)) {
      const file = path.join(dir, n);
      const p = await plist(file);
      if (!p) continue;
      const label = String(p.Label || n.replace(/\.plist$/, ''));
      if (/^com\.apple\./.test(label) || p.Disabled === true) continue;
      const cmd = Array.isArray(p.ProgramArguments) ? p.ProgramArguments.join(' ') : String(p.Program || '');
      if (!cmd) continue;
      const reasons = [];
      let state = 'calm';
      if (/curl[^|\n]*\|\s*(ba|z)?sh|wget[^|\n]*\|\s*(ba|z)?sh|osascript|base64\s+(-d|-D|--decode)|python[0-9.]*\s+-c|\b(ba|z)?sh\s+-c\s+.*(curl|wget)/i.test(cmd)) { reasons.push({ key: 'auto.hiddenScript', params: {}, sev: 'alarm' }); state = 'alarm'; }
      if (/(^|\s|")(\/tmp\/|\/private\/tmp\/|\/private\/var\/folders\/|\/var\/folders\/|[^\s]*\/Downloads\/)/.test(cmd)) { reasons.push({ key: 'auto.tempPath', params: {}, sev: 'watch' }); if (state === 'calm') state = 'watch'; }
      if (/(^|\/|\s)(node|python[0-9.]*|bun|deno|npx|uvx)(\s|$)/i.test(cmd)) { reasons.push({ key: 'auto.scriptRuntime', params: {}, sev: 'watch' }); if (state === 'calm') state = 'watch'; }
      if (/claude|codex|gemini|openclaw|ollama|agent|mcp|llm|gpt/i.test(cmd + ' ' + label)) reasons.push({ key: 'auto.ai', params: {}, sev: 'calm' });
      const id = U.sha256(`${kind}|${label}|${cmd}`).slice(0, 16);
      out.push({ id, kind, name: label, command: cmd, where: file, state, reasons });
    }
  }
  return out;
}

// Turn a user LaunchAgent off (and back on). Persistent, no admin needed.
async function launchAgentEnabled(label, plistPath, on) {
  if (!IS_MAC) return { ok: false, error: 'mac only' };
  const dom = `gui/${os.userInfo().uid}`;
  if (on) {
    const a = await run('/bin/launchctl', ['enable', `${dom}/${label}`]);
    if (plistPath) await run('/bin/launchctl', ['bootstrap', dom, plistPath]);
    return { ok: a.ok, error: a.ok ? null : a.err.trim().slice(0, 200) };
  }
  const a = await run('/bin/launchctl', ['disable', `${dom}/${label}`]);
  await run('/bin/launchctl', ['bootout', `${dom}/${label}`]);
  return { ok: a.ok, error: a.ok ? null : a.err.trim().slice(0, 200) };
}

// ---------- signature ----------
async function signature(exe) {
  if (!IS_MAC || !exe) return null;
  const d = await run('/usr/bin/codesign', ['-dv', '--verbose=2', exe], 8000);
  const text = d.err + d.out;
  if (/not signed at all/i.test(text)) return { valid: false, status: 'NotSigned', signer: '' };
  const auth = (text.match(/^Authority=(.+)$/m) || [])[1] || '';
  if (/Signature=adhoc/i.test(text) && !auth) return { valid: false, status: 'adhoc', signer: '' };
  const v = await run('/usr/bin/codesign', ['--verify', '--strict', exe], 8000);
  const signer = auth.replace(/^(Developer ID Application|Apple Development|Mac Developer):\s*/, '').replace(/\s*\([A-Z0-9]{10}\)$/, '');
  return { valid: v.ok && !!auth, status: v.ok ? 'Valid' : 'Invalid', signer };
}

// ---------- environment in shell startup files ----------
const SHELL_RC = ['.zshrc', '.zprofile', '.zshenv', '.bash_profile', '.bashrc', '.profile', '.config/fish/config.fish'].map((f) => path.join(U.HOME, f));
function shellExports(names) {
  const vals = {};
  for (const f of SHELL_RC) {
    const t = U.readText(f);
    if (!t) continue;
    for (const v of names) {
      const m = t.match(new RegExp(`^\\s*(?:export\\s+|set\\s+-gx\\s+)?${v}[=\\s]["']?(https?://[^"'\\s]+)`, 'm'));
      if (m) vals[v] = m[1];
    }
  }
  return vals;
}

module.exports = { IS_MAC, fixPath, listProcesses, parsePs, parseLsof, parseNetstat, splitNetstatAddr, connections, attempts, suspend, resume, kill, autostarts, launchAgentEnabled, signature, shellExports, SHELL_RC, splitAddr };
