'use strict';
// AgathOS - shared helpers: paths, hashing, safe file reads and a persistent
// PowerShell bridge (one long-lived process instead of one per poll).
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const IS_WIN = process.platform === 'win32';
const HOME = os.homedir();
const APPDATA = process.env.APPDATA || path.join(HOME, 'AppData', 'Roaming');
const LOCALAPPDATA = process.env.LOCALAPPDATA || path.join(HOME, 'AppData', 'Local');

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

function walk(root, { maxDepth = 4, maxFiles = 20000, filter = () => true, skipDirs = SKIP_DIRS } = {}) {
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
  }
  return out;
}

const expand = (p) => {
  const out = p.replace(/^~(?=$|[\\/])/, HOME)
    .replace(/%USERPROFILE%/gi, HOME)
    .replace(/%APPDATA%/gi, APPDATA)
    .replace(/%LOCALAPPDATA%/gi, LOCALAPPDATA);
  // Catalog paths use Windows separators; tests on other systems need '/'.
  return IS_WIN ? out : out.replace(/\\/g, '/');
};

const shortPath = (p) => (p && p.toLowerCase().startsWith(HOME.toLowerCase()) ? '~' + p.slice(HOME.length) : p);

function execFileText(cmd, args, timeout = 6000) {
  return new Promise((resolve) => {
    execFile(cmd, args, { timeout, windowsHide: true, maxBuffer: 4 * 1024 * 1024 }, (err, stdout) => {
      resolve(err && !stdout ? null : String(stdout || ''));
    });
  });
}

// ---------- Persistent PowerShell ----------
// Scripts are queued and run one at a time. Each ends with a unique marker.
class PowerShell {
  constructor() {
    this.proc = null;
    this.queue = [];
    this.busy = false;
    this.buf = '';
    this.current = null;
  }

  start() {
    if (!IS_WIN || this.proc) return;
    this.proc = spawn('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', '-'], {
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    });
    this.proc.stdout.setEncoding('utf8');
    this.proc.stdout.on('data', (d) => this.onData(d));
    this.proc.stderr.on('data', () => {});
    this.proc.on('exit', () => {
      this.proc = null;
      if (this.current) { this.current.resolve(null); this.current = null; }
      this.busy = false;
      this.next();
    });
    this.proc.stdin.write('[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n$ProgressPreference = "SilentlyContinue"\n$ErrorActionPreference = "SilentlyContinue"\n');
  }

  run(script, timeout = 15000) {
    if (!IS_WIN) return Promise.resolve(null);
    return new Promise((resolve) => {
      this.queue.push({ script, timeout, resolve });
      this.next();
    });
  }

  async json(script, timeout) {
    const out = await this.run(script, timeout);
    if (!out || !out.trim()) return [];
    try {
      const v = JSON.parse(out.trim());
      return Array.isArray(v) ? v : [v];
    } catch (_) {
      return [];
    }
  }

  next() {
    if (this.busy || !this.queue.length) return;
    this.start();
    if (!this.proc) { this.queue.shift().resolve(null); return; }
    const job = this.queue.shift();
    this.busy = true;
    this.buf = '';
    const marker = `<<AGATHOS:${crypto.randomBytes(6).toString('hex')}>>`;
    job.marker = marker;
    job.timer = setTimeout(() => {
      // A hung script: restart the shell so the queue keeps moving.
      try { this.proc.kill(); } catch (_) {}
    }, job.timeout);
    this.current = job;
    // One line per job: with "-Command -" PowerShell reads stdin like a console, where
    // multi-line blocks and here-strings need an extra blank line. Base64 avoids all of that.
    const b64 = Buffer.from(job.script, 'utf8').toString('base64');
    this.proc.stdin.write(`try { Invoke-Expression ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('${b64}'))) } catch {}; Write-Output '${marker}'\n`);
  }

  onData(d) {
    if (!this.current) return;
    this.buf += d;
    const i = this.buf.indexOf(this.current.marker);
    if (i === -1) return;
    const out = this.buf.slice(0, i);
    const job = this.current;
    clearTimeout(job.timer);
    this.current = null;
    this.busy = false;
    this.buf = '';
    job.resolve(out);
    this.next();
  }

  stop() {
    try { if (this.proc) this.proc.kill(); } catch (_) {}
    this.proc = null;
  }
}

const ps = new PowerShell();

// Escape a value for a single-quoted PowerShell string.
const psq = (s) => "'" + String(s).replace(/'/g, "''") + "'";

module.exports = {
  IS_WIN, HOME, APPDATA, LOCALAPPDATA, sha256, exists, statSafe, readText, readHead, readJsonLoose,
  stripJsonComments, walk, expand, shortPath, execFileText, ps, psq, SKIP_DIRS,
};
