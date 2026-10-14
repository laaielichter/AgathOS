'use strict';
// AgathOS - the clock for the daily update check: every day at 23:00 Dutch time
// (Europe/Amsterdam, summer and winter time included), whatever time zone the computer uses.
// A check that was missed because the computer was off or asleep happens once, as soon as
// AgathOS runs again.
const ZONE = 'Europe/Amsterdam';
const HOUR = 23;
const RETRY_MS = 30 * 60 * 1000;         // GitHub could not be reached: look again half an hour later

let fmt = null;
// The Dutch wall clock at a moment (ms since 1970).
function parts(ms) {
  if (!fmt) fmt = new Intl.DateTimeFormat('en-GB', { timeZone: ZONE, hourCycle: 'h23', year: 'numeric', month: 'numeric', day: 'numeric', hour: 'numeric', minute: 'numeric', second: 'numeric' });
  const p = {};
  for (const x of fmt.formatToParts(new Date(ms))) p[x.type] = Number(x.value);
  return p;
}

// How far the Dutch clock is ahead of UTC at a moment, in ms (one or two hours).
function offsetMs(ms) {
  const p = parts(ms);
  return Date.UTC(p.year, p.month - 1, p.day, p.hour, p.minute, p.second) - Math.floor(ms / 1000) * 1000;
}

// The moment at which the Dutch clock shows year-month-day hour:00 (month 1 to 12).
function wall(year, month, day, hour) {
  const guess = Date.UTC(year, month - 1, day, hour, 0, 0);
  let t = guess - offsetMs(guess);
  t = guess - offsetMs(t);                // once more, now with the offset of the real moment
  return t;
}

// The day before or after a Dutch calendar day; Date.UTC rolls month and year over by itself.
function shiftDay(p, by) {
  const d = new Date(Date.UTC(p.year, p.month - 1, p.day + by));
  return [d.getUTCFullYear(), d.getUTCMonth() + 1, d.getUTCDate()];
}

// The latest 23:00 Dutch time that is not in the future.
function lastSlot(now) {
  const p = parts(now);
  let t = wall(p.year, p.month, p.day, HOUR);
  if (t > now) t = wall(...shiftDay(p, -1), HOUR);
  return t;
}

// The first 23:00 Dutch time after now.
function nextSlot(now) {
  const p = parts(now);
  let t = wall(p.year, p.month, p.day, HOUR);
  if (t <= now) t = wall(...shiftDay(p, 1), HOUR);
  return t;
}

// One check per 23:00. tick() is called every minute (and when the computer wakes up);
// it only does something when the last 23:00 has not been served yet.
class DailyCheck {
  // enabled(): is checking switched on. served()/setServed(slot): the last 23:00 that got its check (kept on disk).
  // run(): does the check and answers true when GitHub could be reached.
  constructor({ enabled, served, setServed, run, now = Date.now }) {
    Object.assign(this, { enabled, served, setServed, run, now });
    this.busy = false;
    this.retryAt = 0;
  }

  async tick() {
    if (this.busy || !this.enabled()) return false;
    const t = this.now();
    const slot = lastSlot(t);
    let served = Number(this.served()) || 0;
    if (served > t + 36 * 3600 * 1000) served = 0;      // a clock that was set wrong once: do not wait for that day
    if (served >= slot || t < this.retryAt) return false;
    this.busy = true;
    try {
      const reached = await this.run();
      if (reached) { this.setServed(slot); this.retryAt = 0; } else this.retryAt = this.now() + RETRY_MS;
    } catch (_) {
      this.retryAt = this.now() + RETRY_MS;
    } finally {
      this.busy = false;
    }
    return true;
  }
}

module.exports = { ZONE, HOUR, RETRY_MS, parts, lastSlot, nextSlot, DailyCheck };
