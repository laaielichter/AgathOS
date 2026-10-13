'use strict';
// AgathOS - calm notifications. No notification circus:
//  1. Level: by default only danger pops up; attention goes to the log and the tray dot.
//  2. No repeats: the same finding is not shown again within 6 hours (unless it got worse).
//  3. Bundling: what happens within 15 seconds becomes one notification.
//  4. A limit: at most 3 per hour; after that one "more in AgathOS" and then quiet.
//  5. Window open: no pop-up, the window already shows it.
//  6. Quiet hours and snooze: only critical danger comes through.
// Critical = something is being damaged or stolen right now. That always comes through.
const CRITICAL = new Set(['mass.delete', 'pause.autoFrozen', 'intent.trifecta', 'intent.chainDone', 'proc.exfil', 'mcp.malicious', 'log.tampered', 'dl.model', 'proc.securityOff']);
// Things that are news but never worth a pop-up.
const NEVER = /^(fix\.|pause\.(frozen|resumed|killed|all|allResumed)|agent\.(started|stopped|approved)|scan\.|app\.|fw\.(blocked|unblocked|localOnly|lockdown))/;

const REPEAT_MS = 6 * 3600 * 1000;
const BUNDLE_MS = 15 * 1000;
const HOUR = 3600 * 1000;
const PER_HOUR = 3;
const RANK = { calm: 0, watch: 1, alarm: 2 };

function inQuietHours(q, now = new Date()) {
  if (!q || !q.on) return false;
  const toMin = (s) => { const m = /^(\d{1,2}):(\d{2})$/.exec(String(s || '')); return m ? (+m[1] % 24) * 60 + (+m[2] % 60) : null; };
  const from = toMin(q.from);
  const to = toMin(q.to);
  if (from == null || to == null || from === to) return false;
  const cur = now.getHours() * 60 + now.getMinutes();
  return from < to ? cur >= from && cur < to : cur >= from || cur < to;
}

class Notifier {
  // show(list, { sound }) puts one notification on screen for a list of events.
  constructor({ show, settings, snoozed, windowFocused, now = () => Date.now() }) {
    this.show = show;
    this.settings = settings;
    this.snoozed = snoozed;
    this.windowFocused = windowFocused;
    this.now = now;
    this.seen = new Map();      // fingerprint -> { at, sev }
    this.sent = [];             // timestamps of pop-ups in the last hour
    this.pending = [];
    this.timer = null;
    this.overflowAt = 0;
  }

  fingerprint(e) {
    const t = e.target || {};
    return `${e.key}|${t.type || ''}|${t.id || t.path || t.port || ''}|${e.agentId || ''}|${e.params && (e.params.file || e.params.name || e.params.port || '')}`;
  }

  // Returns why an event was not shown (for tests), or 'queued'.
  push(e) {
    const s = this.settings();
    if (!e || e.sev === 'calm' || NEVER.test(e.key)) return 'never';
    if (s.notify === 'log') return 'log only';
    const critical = CRITICAL.has(e.key) && e.sev === 'alarm';
    const level = s.notifyLevel === 'watch' ? 1 : 2;
    if (RANK[e.sev] < level && !critical) return 'below level';
    if (!critical && (this.snoozed() || inQuietHours(s.quietHours, new Date(this.now())))) return 'quiet';
    if (!critical && this.windowFocused()) return 'window open';
    const fp = this.fingerprint(e);
    const prev = this.seen.get(fp);
    if (prev && this.now() - prev.at < REPEAT_MS && RANK[e.sev] <= RANK[prev.sev]) return 'repeat';
    this.seen.set(fp, { at: this.now(), sev: e.sev });
    if (this.seen.size > 2000) this.seen.clear();
    this.pending.push({ e, critical });
    if (critical) { this.flush(); return 'queued'; }
    if (!this.timer) this.timer = setTimeout(() => this.flush(), BUNDLE_MS);
    return 'queued';
  }

  flush() {
    clearTimeout(this.timer);
    this.timer = null;
    if (!this.pending.length) return;
    const batch = this.pending.splice(0);
    const critical = batch.some((x) => x.critical);
    const now = this.now();
    this.sent = this.sent.filter((t) => now - t < HOUR);
    if (!critical && this.sent.length >= PER_HOUR) {
      // One quiet hint per hour that more is waiting, then silence.
      if (now - this.overflowAt > HOUR) { this.overflowAt = now; this.show(batch.map((x) => x.e), { sound: false, overflow: true }); }
      return;
    }
    this.sent.push(now);
    const events = batch.map((x) => x.e).sort((a, b) => RANK[b.sev] - RANK[a.sev]);
    this.show(events, { sound: events[0].sev === 'alarm' });
  }
}

module.exports = { Notifier, inQuietHours, CRITICAL };
