'use strict';
// AgathOS - the log of requests from AI programs.
//
// Every line holds the hash of the line before it, like the event log, so a line that is removed or changed breaks the chain and shows.
// Only who asked what and what was answered is written here: never a key or a token, never the text that was checked.
const fs = require('fs');
const crypto = require('crypto');

const ZERO = '0'.repeat(64);
const sha = (s) => crypto.createHash('sha256').update(s).digest('hex');
const DAY = 86400000;

class AuditLog {
  // days: how long lines are kept. maxLines: the most lines in the file.
  constructor(file, { maxLines = 20000, days = 30, keep = 2000, now = Date.now } = {}) {
    this.file = file;
    this.maxLines = maxLines;
    this.days = days;
    this.keep = keep;           // lines kept in memory for the window
    this.now = now;
    this.last = ZERO;
    this.rows = [];
    this.ok = true;             // false when a line was changed or removed
    this.lines = 0;
    this.load(true);
  }

  // first: the file is read at the start of the program; only then does a broken chain count as tampering (the flag `ok`).
  load(first = false) {
    let txt = '';
    try { txt = fs.readFileSync(this.file, 'utf8'); } catch (_) { return; }
    const cutoff = this.now() - this.days * DAY;
    // A crash while a line was being written leaves half a line at the end: that is not tampering, the line is dropped.
    const torn = txt.length > 0 && !txt.endsWith('\n');
    const lines = txt.split('\n');
    let prev = ZERO;
    let bad = false;
    const kept = [];
    let n = 0;
    for (let i = 0; i < lines.length; i++) {
      if (!lines[i].trim()) continue;
      let e;
      try { e = JSON.parse(lines[i]); } catch (_) { if (torn && i === lines.length - 1) continue; n++; bad = true; continue; }
      n++;
      const { hash, ...body } = e;
      if (body.prev !== prev || sha(JSON.stringify(body)) !== hash) bad = true;
      prev = hash || prev;
      if (e.ts >= cutoff) kept.push(e);
    }
    if (first) this.ok = !bad;
    this.last = prev;
    this.lines = n;
    // Old lines are dropped by writing the file again with a new chain. A file that was tampered with is kept aside once, as proof,
    // and the chain starts again, so the alarm is given once and not at every start.
    if (bad) { try { fs.copyFileSync(this.file, this.file + '.broken'); } catch (_) { /* no copy, the alarm stands */ } }
    if (bad || torn || kept.length < n || kept.length > this.maxLines) this.rewrite(kept.slice(-this.maxLines));
    else this.rows = kept.slice(-this.keep);
  }

  rewrite(list) {
    let prev = ZERO;
    const out = list.map((e) => {
      const { hash, prev: _p, ...rest } = e;
      const body = { ...rest, prev };
      const h = sha(JSON.stringify(body));
      prev = h;
      return { ...body, hash: h };
    });
    try { fs.writeFileSync(this.file, out.map((e) => JSON.stringify(e)).join('\n') + (out.length ? '\n' : ''), { mode: 0o600 }); } catch (_) { /* disk full or locked */ }
    this.last = prev;
    this.lines = out.length;
    this.rows = out.slice(-this.keep);
  }

  append(row) {
    const body = { ...row, ts: row.ts || this.now(), prev: this.last };
    const hash = sha(JSON.stringify(body));
    const full = { ...body, hash };
    try { fs.appendFileSync(this.file, JSON.stringify(full) + '\n', { mode: 0o600 }); } catch (_) { /* disk full or locked */ }
    this.last = hash;
    this.lines++;
    this.rows.push(full);
    if (this.rows.length > this.keep) this.rows.splice(0, this.rows.length - this.keep);
    if (this.lines > this.maxLines + 500) this.load();   // now and then, cut the file down to size
    return full;
  }

  // The newest lines first, for the window.
  tail(n = 100) {
    return this.rows.slice(-Math.max(1, Math.min(500, n))).reverse();
  }

  // Check the whole file again.
  verify() {
    let txt = '';
    try { txt = fs.readFileSync(this.file, 'utf8'); } catch (_) { return { ok: true, lines: 0 }; }
    let prev = ZERO;
    let n = 0;
    for (const line of txt.split('\n')) {
      if (!line.trim()) continue;
      n++;
      let e;
      try { e = JSON.parse(line); } catch (_) { return { ok: false, line: n }; }
      const { hash, ...body } = e;
      if (body.prev !== prev || sha(JSON.stringify(body)) !== hash) return { ok: false, line: n };
      prev = hash;
    }
    return { ok: true, lines: n };
  }
}

module.exports = { AuditLog };
