'use strict';
// AgathOS - Worm watch, part 1: spots a program that sweeps your home network.
//
// A self-spreading (AI) worm has to find its next victim first. It does that by
// knocking on many devices, or on many ports of one device, in a short time.
// Normal apps almost never do that over TCP: discovery of TVs, speakers and
// printers runs over UDP (mDNS, SSDP), and a NAS or printer app talks to one device.
//
// Sources (no admin needed):
//   Windows  Get-NetTCPConnection every few seconds, including half-open
//            connections (SynSent): a knock on an empty address stays in that
//            state for seconds, so a sweep is easy to catch.
//   macOS    lsof with SYN_SENT and ESTABLISHED.
//   Guard    Sysmon network events (event 3), when AgathOS Guard runs.
const os = require('os');
const N = require('./network');

const DEFAULTS = {
  windowMs: 60000,          // look back one minute
  hostsLimit: 20,           // different devices on your network within that minute
  portsLimit: 15,           // different ports on one device within that minute
  cooldownMs: 10 * 60000,   // one alarm per program per ten minutes
};

// Ports that smart devices listen on. Shown so you can see what the scanner was after.
const DEVICE_PORTS = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'web', 443: 'web', 445: 'SMB', 554: 'camera (RTSP)', 631: 'printer', 1883: 'MQTT (smart home)',
  1925: 'Philips TV', 2323: 'Telnet', 5555: 'Android TV (ADB)', 7547: 'router (TR-069)', 8000: 'camera', 8008: 'Chromecast', 8009: 'Chromecast',
  8060: 'Roku TV', 8080: 'web', 8123: 'Home Assistant', 8443: 'web', 8883: 'MQTT (smart home)', 9100: 'printer', 34567: 'camera (DVR)', 37777: 'camera (Dahua)',
};
// Ports that mostly matter for spreading: remote login, file shares, cameras, TVs.
const SPREAD_PORTS = new Set([22, 23, 445, 554, 1883, 2323, 5555, 7547, 8883, 34567, 37777]);

// Network tools you may run on purpose. Still reported, but as "watch" instead of danger.
const KNOWN_SCANNERS = /^(nmap|zenmap|masscan|angryip|ipscan|advanced_ip_scanner|advanced ip scanner|fing|lansweeper|netscan|softperfect.*|wireshark)(\.exe)?$/i;
// Processes that are never a scanner (system plumbing that owns odd connections).
const IGNORE = /^(system|idle|smss|lsass|svchost|kernel_task|launchd|mdnsresponder)(\.exe)?$/i;

// IPv4 on the home network only. Multicast and broadcast are not devices.
function isLanTarget(ip) {
  if (!ip || !N.isPrivate(ip) || N.isLoopback(ip) || N.isAny(ip)) return false;
  if (/^(22[4-9]|23\d|24\d|25[0-5])\./.test(ip) || /^ff/i.test(ip)) return false;
  if (/\.255$/.test(ip)) return false;
  return true;
}

function ownAddresses() {
  const out = new Set();
  for (const list of Object.values(os.networkInterfaces() || {})) for (const a of list || []) out.add(a.address);
  return out;
}

class LanScanWatch {
  constructor({ onAlert, now, ...opts } = {}) {
    this.onAlert = onAlert || (() => {});
    this.now = now || Date.now;
    this.opts = { ...DEFAULTS, ...opts };
    this.seen = new Map();      // `${pid}|${name}` -> { pid, name, hits: Map(`${ip}|${port}` -> ts) }
    this.lastAlert = new Map(); // `${pid}|${name}` -> ts
    this.own = ownAddresses();
    this.ownAt = this.now();
  }

  // rows: [{ pid, ra, rp, n?, state? }]   nameOf(pid) -> process name
  observe(rows, nameOf = () => null) {
    const t = this.now();
    if (t - this.ownAt > 60000) { this.own = ownAddresses(); this.ownAt = t; }
    const touched = new Set();
    for (const r of rows || []) {
      const pid = +r.pid;
      if (!pid || pid <= 4 || pid === process.pid) continue;
      const ip = String(r.ra || '').replace(/^::ffff:/i, '');
      if (!isLanTarget(ip) || this.own.has(ip)) continue;
      const name = String(r.n || nameOf(pid) || '').trim() || `PID ${pid}`;
      if (IGNORE.test(name)) continue;
      const key = `${pid}|${name.toLowerCase()}`;
      let s = this.seen.get(key);
      if (!s) { s = { pid, name, hits: new Map() }; this.seen.set(key, s); }
      s.hits.set(`${ip}|${+r.rp || 0}`, t);
      touched.add(key);
    }
    const alerts = [];
    for (const [key, s] of this.seen) {
      for (const [hk, ts] of s.hits) if (t - ts > this.opts.windowMs) s.hits.delete(hk);
      if (!s.hits.size) { this.seen.delete(key); continue; }
      if (!touched.has(key)) continue;
      const a = this.check(key, s, t);
      if (a) alerts.push(a);
    }
    for (const a of alerts) this.onAlert(a);
    return alerts;
  }

  check(key, s, t) {
    const hosts = new Map();    // ip -> Set(port)
    for (const hk of s.hits.keys()) {
      const [ip, port] = hk.split('|');
      if (!hosts.has(ip)) hosts.set(ip, new Set());
      hosts.get(ip).add(+port);
    }
    const sweep = hosts.size >= this.opts.hostsLimit;
    let portScan = null;
    for (const [ip, ports] of hosts) if (ports.size >= this.opts.portsLimit && (!portScan || ports.size > portScan.n)) portScan = { ip, n: ports.size };
    if (!sweep && !portScan) return null;
    const last = this.lastAlert.get(key) || 0;
    if (t - last < this.opts.cooldownMs) return null;
    this.lastAlert.set(key, t);

    const allPorts = new Set();
    for (const ports of hosts.values()) for (const p of ports) allPorts.add(p);
    const kinds = [...new Set([...allPorts].map((p) => DEVICE_PORTS[p]).filter(Boolean))].slice(0, 5);
    const spread = [...allPorts].some((p) => SPREAD_PORTS.has(p));
    const known = KNOWN_SCANNERS.test(s.name);
    return {
      key: sweep ? 'worm.lanSweep' : 'worm.portScan',
      sev: known ? 'watch' : 'alarm',
      watcher: 'net',
      pid: s.pid,
      params: {
        process: s.name, pid: s.pid, hosts: hosts.size, ports: allPorts.size,
        host: portScan ? portScan.ip : '', sample: [...allPorts].sort((a, b) => a - b).slice(0, 8).join(', '),
        kinds: kinds.join(', '), spread, known,
      },
    };
  }
}

module.exports = { LanScanWatch, isLanTarget, DEVICE_PORTS, KNOWN_SCANNERS, DEFAULTS };
