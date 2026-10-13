'use strict';
// AgathOS - harmless test for the worm watch: `node test/lan-scan-sim.js`
//
// Knocks once on port 80 of 50 addresses in your own home network, the way a
// worm looks for its next victim. It sends no data and logs in nowhere: every
// knock is closed again after 8 seconds. With AgathOS running, you should get a
// "worm" alarm for node within about 10 seconds.
const net = require('net');
const os = require('os');

const COUNT = 50;
const PORT = 80;
const HOLD_MS = 8000;

function homeAddress() {
  for (const list of Object.values(os.networkInterfaces())) {
    for (const a of list || []) {
      if (a.family === 'IPv4' && !a.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address)) return a.address;
    }
  }
  return null;
}

const me = homeAddress();
if (!me) {
  console.log('No home network address found. Connect to Wi-Fi or a cable first.');
  process.exit(1);
}
const base = me.split('.').slice(0, 3).join('.');
const own = +me.split('.')[3];
const targets = [];
for (let i = 2; i < 255 && targets.length < COUNT; i++) if (i !== own) targets.push(`${base}.${i}`);

console.log(`This computer: ${me}`);
console.log(`Knocking on port ${PORT} of ${targets.length} addresses (${targets[0]} to ${targets[targets.length - 1]})...`);
let answered = 0;
for (const ip of targets) {
  const s = net.connect({ host: ip, port: PORT });
  s.on('connect', () => { answered++; });
  s.on('error', () => {});
  setTimeout(() => s.destroy(), HOLD_MS);
}
setTimeout(() => {
  console.log(`Done. ${answered} device(s) answered. AgathOS should now show a worm alarm for node.`);
  process.exit(0);
}, HOLD_MS + 500);
