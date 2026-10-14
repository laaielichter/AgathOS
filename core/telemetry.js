'use strict';
// AgathOS - live telemetry for the dashboard.
// The window can show what happens right now: new programs, agent actions, network connections,
// file activity and alerts, second by second. This module only counts and remembers a short while
// (about two and a half minutes, in memory). Nothing here is written to disk or leaves the PC,
// and it reads no file contents: it only gets the names that the watchers already know.
const KEEP = 150;          // samples of one second
const FEED = 300;          // lines in the live log
const SEND = 80;           // lines per push to the window
const CHANNELS = ['spawns', 'actions', 'conns', 'files', 'alerts'];
const RANK = { calm: 0, watch: 1, alarm: 2 };

const zero = () => Object.fromEntries(CHANNELS.map((c) => [c, 0]));

class Telemetry {
  constructor({ now = Date.now } = {}) {
    this.now = now;
    this.cur = zero();                 // counters of the second in progress
    this.curSev = 'calm';              // worst alert of that second
    this.series = [];                  // [{ t, spawns, actions, conns, files, alerts, sev }]
    this.feed = [];                    // [{ id, ts, kind, key, params, sev }]
    this.seq = 0;
    this.gauges = { procs: 0, agents: 0, open: 0 };
    this.bucket = new Map();           // folder -> { n, del }
  }

  count(channel, n = 1) {
    if (channel in this.cur) this.cur[channel] += n;
  }

  gauge(name, value) {
    this.gauges[name] = value;
  }

  // One line for the live log. Params are plain strings and numbers: the window turns key + params into text.
  note(kind, key, params = {}, sev = 'calm') {
    const e = { id: ++this.seq, ts: this.now(), kind, key, params, sev: RANK[sev] != null ? sev : 'calm' };
    this.feed.push(e);
    if (this.feed.length > FEED) this.feed.splice(0, this.feed.length - FEED);
    return e;
  }

  // An alert (an event of the audit log). Calm events show in the log only.
  alert(sev) {
    if (RANK[sev] > 0) {
      this.cur.alerts++;
      if (RANK[sev] > RANK[this.curSev]) this.curSev = sev;
    }
  }

  // A file changed below a work folder. Lines are bundled per folder, once per second.
  file(dir, deleted = false) {
    const b = this.bucket.get(dir) || { n: 0, del: 0 };
    b.n++;
    if (deleted) b.del++;
    this.bucket.set(dir, b);
  }

  // Called every second: closes the current second.
  sample() {
    let files = 0;
    const lines = [];
    for (const [dir, b] of this.bucket) {
      files += b.n;
      // A single save is noise; a burst or a deletion is worth a line.
      if (b.del > 0 || b.n >= 5) lines.push([dir, b]);
    }
    this.bucket.clear();
    this.cur.files += files;
    lines.sort((a, b) => b[1].n - a[1].n);
    for (const [dir, b] of lines.slice(0, 3)) {
      this.note('file', b.del ? 'live.filesGone' : 'live.files', { dir, n: b.n, del: b.del }, b.del >= 10 ? 'watch' : 'calm');
    }
    const row = { t: this.now(), ...this.cur, sev: this.curSev };
    this.series.push(row);
    if (this.series.length > KEEP) this.series.splice(0, this.series.length - KEEP);
    this.cur = zero();
    this.curSev = 'calm';
    return row;
  }

  // What the window needs: the series (small), the gauges and the log lines it has not seen yet.
  view(since = 0) {
    const from = Number.isFinite(since) ? since : 0;
    return {
      seq: this.seq, t: this.now(), keep: KEEP, gauges: { ...this.gauges },
      series: this.series.slice(),
      feed: this.feed.filter((e) => e.id > from).slice(-SEND),
    };
  }
}

module.exports = { Telemetry, KEEP, FEED, CHANNELS };
