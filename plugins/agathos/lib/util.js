'use strict';
// AgathOS - shared helpers: paths, hashing and safe file reads. (Starting programs is in shell.js.)
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const HOME = os.homedir();
// On a Mac the apps keep their settings in ~/Library/Application Support, the same
// folder names as %APPDATA% on Windows (Claude, Code\User, Cursor\User ...).
const MAC_SUPPORT = path.join(HOME, 'Library', 'Application Support');
const APPDATA = process.env.APPDATA || (IS_MAC ? MAC_SUPPORT : path.join(HOME, 'AppData', 'Roaming'));
const LOCALAPPDATA = process.env.LOCALAPPDATA || (IS_MAC ? MAC_SUPPORT : path.join(HOME, 'AppData', 'Local'));

const sha256 = (data) => crypto.createHash('sha256').update(data).digest('hex');

function exists(p) {
  try { fs.accessSync(p); return true; } catch (_) { return false; }
}

function statSafe(p) {
  try { return fs.statSync(p); } catch (_) { return null; }
}

// Read at most `max` bytes of a text file. Big files are cut, never skipped:
// attackers pad files to dodge scanners that skip large files.
function readText(p, max = 2 * 1024 * 1024) {
  try {
    const st = fs.statSync(p);
    if (!st.isFile()) return null;
    const fd = fs.openSync(p, 'r');
    const len = Math.min(st.size, max);
    const buf = Buffer.alloc(len);
    fs.readSync(fd, buf, 0, len, 0);
    fs.closeSync(fd);
    return buf.toString('utf8');
  } catch (_) {
    return null;
  }
}

function readHead(p, n) {
  try {
    const fd = fs.openSync(p, 'r');
    const buf = Buffer.alloc(n);
    const got = fs.readSync(fd, buf, 0, n, 0);
    fs.closeSync(fd);
    return buf.subarray(0, got);
  } catch (_) {
    return null;
  }
}

function readJsonLoose(p) {
  const txt = readText(p);
  if (txt == null) return null;
  try { return JSON.parse(stripJsonComments(txt)); } catch (_) { return null; }
}

// VS Code style settings allow comments and trailing commas.
function stripJsonComments(s) {
  let out = '';
  let inStr = false;
  for (let i = 0; i < s.length; i++) {
    const c = s[i];
    const n = s[i + 1];
    if (inStr) {
      out += c;
      if (c === '\\') { out += n || ''; i++; } else if (c === '"') inStr = false;
      continue;
    }
    if (c === '"') { inStr = true; out += c; continue; }
    if (c === '/' && n === '/') { while (i < s.length && s[i] !== '\n') i++; out += '\n'; continue; }
    if (c === '/' && n === '*') { i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) i++; i++; continue; }
    out += c;
  }
  return out.replace(/,\s*([}\]])/g, '$1');
}

// Walk a directory tree with limits. Skips heavy folders.
const SKIP_DIRS = new Set(['node_modules', '.git', '.hg', '.svn', 'venv', '.venv', '__pycache__', '$RECYCLE.BIN',
  'System Volume Information', 'AppData', '.cache', 'dist', 'build', 'target', '.next', '.gradle', 'Library']);

// The walk is written as steps (a generator that stops after every folder). Run to the end at once (walk), or with a short pause
// every few milliseconds (runCooperative), so a big folder on a slow disk does not freeze the window, the tray and the stop button.
function* walkSteps(root, { maxDepth = 4, maxFiles = 20000, filter = () => true, skipDirs = SKIP_DIRS } = {}) {
  const out = [];
  const stack = [[root, 0]];
  while (stack.length && out.length < maxFiles) {
    const [dir, depth] = stack.pop();
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch (_) { continue; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        if (depth < maxDepth && !skipDirs.has(e.name) && !e.isSymbolicLink()) stack.push([full, depth + 1]);
      } else if (e.isFile() && filter(full, e.name)) {
        out.push(full);
        if (out.length >= maxFiles) break;
      }
    }
    yield;
  }
  return out;
}

// A stepwise job (a generator) to its end, without a pause.
function run(job) {
  let r = job.next();
  while (!r.done) r = job.next();
  return r.value;
}

// A stepwise job to its end, but after every `sliceMs` of work the event loop gets a turn.
async function runCooperative(job, sliceMs = 12) {
  let since = Date.now();
  let r = job.next();
  while (!r.done) {
    if (Date.now() - since >= sliceMs) {
      await new Promise((resolve) => setImmediate(resolve));
      since = Date.now();
    }
    r = job.next();
  }
  return r.value;
}

const walk = (root, opts) => run(walkSteps(root, opts));

// Grok Build keeps its settings, sessions, skills and plugins in GROK_HOME, or in ~/.grok when that is not set.
const grokHome = () => {
  const v = process.env.GROK_HOME;
  return v && path.isAbsolute(v) ? v.replace(/[\\/]+$/, '') : path.join(HOME, '.grok');
};

const expand = (p) => {
  const out = p.replace(/^~(?=$|[\\/])/, HOME)
    .replace(/%USERPROFILE%/gi, HOME)
    .replace(/%APPDATA%/gi, APPDATA)
    .replace(/%LOCALAPPDATA%/gi, LOCALAPPDATA)
    .replace(/%GROK_HOME%/gi, () => grokHome());
  // Catalog paths use Windows separators; tests on other systems need '/'.
  return IS_WIN ? out : out.replace(/\\/g, '/');
};

const shortPath = (p) => (p && p.toLowerCase().startsWith(HOME.toLowerCase()) ? '~' + p.slice(HOME.length) : p);

// Wraps a job for a timer: a new round does not start while the previous one is still running, so a slow
// round (a busy PC, a hung helper) cannot pile up rounds behind it or handle the same events twice.
// A round that has been running for `hungMs` counts as hung and is not waited for. Errors are swallowed.
function exclusive(fn, { hungMs = 60000, now = Date.now } = {}) {
  let startedAt = null;
  let round = 0;
  return () => {
    if (startedAt !== null && now() - startedAt < hungMs) return false;
    const mine = ++round;
    startedAt = now();
    Promise.resolve().then(fn).catch(() => {}).finally(() => { if (round === mine) startedAt = null; });
    return true;
  };
}

// Starting programs is in shell.js, loaded only when a program is really started.
const shell = () => require('./shell');
const execFileText = (...args) => shell().execFileText(...args);
const ps = new Proxy({}, { get: (_t, key) => { const real = shell().ps; const v = real[key]; return typeof v === 'function' ? v.bind(real) : v; } });

// Escape a value for a single-quoted PowerShell string.
const psq = (s) => "'" + String(s).replace(/'/g, "''") + "'";

module.exports = {
  IS_WIN, IS_MAC, HOME, APPDATA, LOCALAPPDATA, sha256, exists, statSafe, readText, readHead, readJsonLoose,
  stripJsonComments, walk, walkSteps, run, runCooperative, expand, grokHome, shortPath, exclusive, execFileText, ps, psq, SKIP_DIRS,
};
