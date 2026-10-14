'use strict';
// AgathOS - network view (no admin needed): open AI ports and who talks to whom.
const U = require('./util');
const C = require('./catalog');
const mac = require('./mac');
const native = require('./winnative');

const PS_CONN = `Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -eq 'Listen' -or $_.State -eq 'Established' } |
  ForEach-Object { [pscustomobject]@{ la=$_.LocalAddress; lp=$_.LocalPort; ra=$_.RemoteAddress; rp=$_.RemotePort; s="$($_.State)"; p=$_.OwningProcess } } | ConvertTo-Json -Compress`;

async function connections() {
  if (U.IS_MAC) return mac.connections();
  if (!U.IS_WIN) return [];
  // Windows is asked directly (a few milliseconds); the PowerShell commands below are the way back when that is not possible.
  const direct = await native.tcp();
  if (direct) return listenAndEstablished(direct);
  let rows = await U.ps.json(PS_CONN, 15000);
  if (rows.length) return rows.map((r) => ({ la: r.la, lp: r.lp, ra: r.ra, rp: r.rp, state: r.s, pid: r.p }));
  // Fallback: netstat works everywhere.
  const out = await U.execFileText('netstat.exe', ['-ano', '-p', 'TCP'], 10000);
  if (!out) return [];
  rows = [];
  for (const line of out.split(/\r?\n/)) {
    const m = line.trim().match(/^TCP\s+(\S+):(\d+)\s+(\S+):(\d+)\s+(\S+)\s+(\d+)$/i);
    if (!m) continue;
    const state = /LISTEN/i.test(m[5]) ? 'Listen' : /ESTABLISHED/i.test(m[5]) ? 'Established' : m[5];
    if (state !== 'Listen' && state !== 'Established') continue;
    rows.push({ la: m[1].replace(/^\[|\]$/g, ''), lp: +m[2], ra: m[3].replace(/^\[|\]$/g, ''), rp: +m[4], state, pid: +m[6] });
  }
  return rows;
}

// Outgoing connections and connection attempts (half-open, SynSent) to the home
// network only. Used by the worm watch every few seconds, so the output stays small.
const PS_ATTEMPTS = `Get-NetTCPConnection -State SynSent,Established -ErrorAction SilentlyContinue |
  Where-Object { $_.RemoteAddress -match '^(10\\.|192\\.168\\.|172\\.(1[6-9]|2\\d|3[01])\\.|169\\.254\\.)' } |
  ForEach-Object { [pscustomobject]@{ ra=$_.RemoteAddress; rp=$_.RemotePort; s="$($_.State)"; p=$_.OwningProcess } } | ConvertTo-Json -Compress`;

const HOME_NET = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.)/;
// The rows of the TCP table that the program uses: listeners and open connections.
const listenAndEstablished = (rows) => rows.filter((r) => r.state === 'Listen' || r.state === 'Established').map((r) => ({ la: r.la, lp: r.lp, ra: r.ra, rp: r.rp, state: r.state, pid: r.pid }));
// The same table for the worm watch: attempts and open connections to the home network only.
const toHomeNetwork = (rows) => rows.filter((r) => (r.state === 'SynSent' || r.state === 'Established') && HOME_NET.test(r.ra)).map((r) => ({ ra: r.ra, rp: r.rp, state: r.state, pid: r.pid }));

async function attempts() {
  if (U.IS_MAC) return mac.attempts();
  if (!U.IS_WIN) return [];
  const direct = await native.tcp();
  if (direct) return toHomeNetwork(direct);
  const rows = await U.ps.json(PS_ATTEMPTS, 8000);
  return rows.map((r) => ({ ra: r.ra, rp: r.rp, state: r.s, pid: r.p }));
}

const isLoopback = (a) => /^(127\.|::1$|0:0:0:0:0:0:0:1$)/.test(a);
const isAny = (a) => a === '0.0.0.0' || a === '::' || a === '0:0:0:0:0:0:0:0';
const isPrivate = (a) => /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|169\.254\.|fe80:|fc|fd)/i.test(a);

// AI servers that listen on the network, not only on this PC.
function aiListeners(conns, procName) {
  const out = [];
  const seen = new Set();
  for (const c of conns) {
    if (c.state !== 'Listen') continue;
    const pname = procName(c.pid) || '';
    const product = C.AI_PORTS[c.lp];
    const aiProc = /ollama|lm studio|lms\.exe|^lms$|llama-server|koboldcpp|openclaw|jan\.exe|^jan$|gpt4all|anythingllm|comfyui/i.test(pname);
    if (!product && !aiProc) continue;
    // Generic ports (3000, 5000, 8000, 8080) only count when the owner looks like an AI server.
    if (product && [3000, 5000, 8000, 8080, 8001, 3001].includes(c.lp) && !C.AI_SERVER_PROCS.test(pname)) continue;
    const key = `${c.lp}|${c.la}`;
    if (seen.has(key)) continue;
    seen.add(key);
    const exposed = !isLoopback(c.la);
    out.push({
      id: U.sha256(`port|${c.lp}`).slice(0, 16), port: c.lp, addr: c.la, pid: c.pid, process: pname,
      product: product || pname, exposed, state: exposed ? 'alarm' : 'calm',
      reasons: [exposed
        ? { key: 'port.open', params: { product: product || pname, addr: c.la, port: c.lp }, sev: 'alarm' }
        : { key: 'port.local', params: { product: product || pname, port: c.lp }, sev: 'calm' }],
    });
  }
  // One alarm per port is enough even when it listens on several addresses.
  const byPort = new Map();
  for (const l of out) { const prev = byPort.get(l.port); if (!prev || (l.exposed && !prev.exposed)) byPort.set(l.port, l); }
  return [...byPort.values()];
}

module.exports = { connections, attempts, aiListeners, isLoopback, isAny, isPrivate, listenAndEstablished, toHomeNetwork };
