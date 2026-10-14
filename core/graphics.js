'use strict';
// AgathOS - the safety net for graphics drivers.
//
// Some graphics drivers crash or draw wrong: the window flickers, or the graphics process of the browser dies again and again.
// Settings > Performance > Graphics can switch to drawing in software (no graphics card needed). That choice lives in a small file
// that is read before the browser starts, because the browser cannot change it afterwards. When the graphics process crashes three
// times within two minutes, the next start draws in software by itself and the log says so.
const fs = require('fs');
const path = require('path');

const FILE = 'graphics.json';
const MODES = ['auto', 'software'];
const WINDOW_MS = 2 * 60 * 1000;
const LIMIT = 3;
// The ways a process can end that say something about the driver. A clean exit, or a process somebody ended on purpose, does not.
const BAD = new Set(['crashed', 'abnormal-exit', 'launch-failed', 'oom', 'integrity-failure']);

const mode = (m) => (MODES.includes(m) ? m : 'auto');

// What the file says: { mode: 'auto' | 'software', why }. A missing or broken file means automatic.
function read(dir) {
  try {
    const j = JSON.parse(fs.readFileSync(path.join(dir, FILE), 'utf8'));
    return { mode: mode(j && j.mode), why: j && typeof j.why === 'string' ? j.why.slice(0, 40) : '' };
  } catch (_) {
    return { mode: 'auto', why: '' };
  }
}

function write(dir, m, why = '') {
  try {
    fs.mkdirSync(dir, { recursive: true });
    const tmp = path.join(dir, FILE + '.tmp');
    fs.writeFileSync(tmp, JSON.stringify({ mode: mode(m), why: String(why).slice(0, 40), at: Date.now() }));
    fs.renameSync(tmp, path.join(dir, FILE));
    return true;
  } catch (_) {
    return false;
  }
}

// The crashes of the graphics process in the last two minutes, with this one added when it says something about the driver.
function record(list, now, reason) {
  const keep = (Array.isArray(list) ? list : []).filter((t) => Number.isFinite(t) && now - t >= 0 && now - t < WINDOW_MS);
  if (BAD.has(reason)) keep.push(now);
  return keep;
}

const tooMany = (list) => Array.isArray(list) && list.length >= LIMIT;

module.exports = { FILE, MODES, WINDOW_MS, LIMIT, mode, read, write, record, tooMany };
