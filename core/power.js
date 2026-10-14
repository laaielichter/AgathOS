'use strict';
// AgathOS - the speed of the checks that repeat.
//
// On a laptop that runs on its battery, or on a computer that has become hot, the checks that repeat every few seconds are
// spread out. Only the repeating questions to the system wait longer. What comes by itself keeps its speed: changes in files,
// the events of Guard, the stop button, and the look at a new program when it is asked for.

// macOS says how hot the computer is: nominal, fair, serious or critical.
const THERMAL = { nominal: 1, fair: 1, serious: 3, critical: 4 };

// How many times slower the repeating checks run (1 = normal speed).
function slowdown({ saving = true, onBattery = false, thermal = 'nominal' } = {}) {
  if (saving === false) return 1;
  return Math.max(onBattery ? 2 : 1, THERMAL[thermal] || 1);
}

// Why the speed is what it is, for the window: 'normal', 'battery' or 'hot'.
function reason({ saving = true, onBattery = false, thermal = 'nominal' } = {}) {
  if (saving === false) return 'normal';
  if ((THERMAL[thermal] || 1) >= 3) return 'hot';
  return onBattery ? 'battery' : 'normal';
}

// Milliseconds between two rounds of each repeating check, for the setting "pollSeconds" and a slowdown (1 = as set).
// A check never gets slower than a fixed top, and never slower than the person set it themselves.
function intervals(pollSeconds, f = 1) {
  const base = Math.max(2, Number(pollSeconds) || 5);
  const at = (secs, top) => Math.round(Math.min(Math.max(secs, top), secs * f) * 1000);
  return {
    proc: at(base, 12),            // the list of programs
    net: at(15, 60),               // listeners and connections
    liveNet: 5000,                 // while the live view is on screen: the person is looking, so no change
    transcripts: at(8, 30),        // what agents wrote in their own logs
    minute: 60000,                 // the minute round of the intent engine
    guard: at(2.5, 10),            // the events of AgathOS Guard
    worm: at(3, 12),               // the worm watch
  };
}

// A window nobody looks at still costs a browser process (memory, and a little processor). After this long in the tray it is
// closed for real; opening it again makes a new one. The pop-up above the tray icon is smaller, so it goes sooner.
const RELEASE = { win: 10 * 60 * 1000, mini: 5 * 60 * 1000 };

// The waiting times in milliseconds. The check of the installed app shortens them with AGATHOS_RELEASE_MS (a second to an hour).
function releaseAfter(env = {}) {
  const n = Number(env.AGATHOS_RELEASE_MS);
  if (Number.isFinite(n) && n >= 1000 && n <= 3600 * 1000) return { win: Math.round(n), mini: Math.round(n) };
  return { ...RELEASE };
}

module.exports = { THERMAL, RELEASE, slowdown, reason, intervals, releaseAfter };
