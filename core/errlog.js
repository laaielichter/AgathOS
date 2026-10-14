'use strict';
// AgathOS - last line of defence.
// AgathOS runs for days in the tray, and a mistake inside one watcher must not show an error box
// or stop the others. Errors nobody caught are written to a small file next to the data
// (errors.log, local only) and the program carries on. The file stays small: when it grows past
// the limit, only its newer half is kept, and the same message is written once a minute at most.
const fs = require('fs');
const path = require('path');

const MAX_BYTES = 96 * 1024;
const SAME_MS = 60 * 1000;
const seen = new Map();       // first line of a message -> last time it was written

const text = (err) => String(err && typeof err === 'object' ? (err.stack || err.message || err) : err).slice(0, 2000);

// Writes one entry. Returns true when something was written.
function record(dir, kind, err, now = Date.now()) {
  try {
    const msg = text(err);
    const key = `${kind}|${msg.split('\n')[0]}`;
    const last = seen.get(key);
    if (last !== undefined && now - last < SAME_MS) return false;
    seen.set(key, now);
    if (seen.size > 200) seen.clear();
    fs.mkdirSync(dir, { recursive: true });
    const file = path.join(dir, 'errors.log');
    fs.appendFileSync(file, `${new Date(now).toISOString()} ${kind} ${msg}\n`);
    if (fs.statSync(file).size > MAX_BYTES) {
      const keep = fs.readFileSync(file, 'utf8').slice(-Math.floor(MAX_BYTES / 2));
      fs.writeFileSync(file, keep.replace(/^[^\n]*\n/, ''));
    }
    return true;
  } catch (_) {
    return false;          // even the log may fail (disk full): never throw from here
  }
}

// Hooks the two process-wide events. A handler for 'uncaughtException' also switches off the
// error box that Electron would otherwise show. Returns a function that removes the hooks again.
function install(dir, proc = process) {
  const onError = (err) => { record(dir, 'error', err); };
  const onReject = (reason) => { record(dir, 'rejection', reason); };
  proc.on('uncaughtException', onError);
  proc.on('unhandledRejection', onReject);
  return () => { proc.removeListener('uncaughtException', onError); proc.removeListener('unhandledRejection', onReject); };
}

module.exports = { install, record, MAX_BYTES };
