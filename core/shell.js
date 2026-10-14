'use strict';
// AgathOS - starting programs: running a command, and the persistent PowerShell bridge (one long-lived process instead of one per poll).
// Everything that starts a program on this PC lives in this file. The files that only read (the scanners, and the copy of them that a
// plugin carries) do not load it, so they cannot start one.
const crypto = require('crypto');
const { spawn, execFile } = require('child_process');

const IS_WIN = process.platform === 'win32';

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
    this.generation = 0;       // counts the PowerShell processes that were started: a script that put something into one has to do it again after a restart
  }

  start() {
    if (!IS_WIN || this.proc) return;
    this.generation++;
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

module.exports = { execFileText, PowerShell, ps };
