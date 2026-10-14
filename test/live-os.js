'use strict';
// AgathOS - checks on the real system. Windows and macOS only: on any other system this does nothing.
//
// It opens a small server and starts a small program of its own, and then asks the watchers for them. So it shows that the
// ways of asking for programs and connections work on THIS system, with the right answers: the program that owns a port, the
// parent, the file and the command line of a program, and (Windows) that the direct way agrees with the PowerShell way.
// Called by test/run-tests.js; "node test/live-os.js" runs it alone.
const net = require('net');
const os = require('os');
const cp = require('child_process');

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const until = async (fn, ms = 10000, every = 150) => {
  const end = Date.now() + ms;
  for (;;) {
    let v = null;
    try { v = await fn(); } catch (_) { v = null; }
    if (v) return v;
    if (Date.now() > end) return null;
    await sleep(every);
  }
};
const med = (a) => [...a].sort((x, y) => x - y)[Math.floor(a.length / 2)];
const same = (a, b) => String(a || '').toLowerCase().replace(/\\/g, '/') === String(b || '').toLowerCase().replace(/\\/g, '/');
const listen = (server, host) => new Promise((resolve) => { server.once('error', () => resolve(false)); server.listen(0, host, () => resolve(true)); });

async function liveOsTests({ ok: report, say: sayOut = () => {} }) {
  const told = [];
  const say = (s) => { told.push(String(s)); sayOut(s); };
  // A failed check also writes what it saw, as an annotation in GitHub Actions (the plain result only has the name).
  const ok = (cond, name, detail) => {
    report(cond, name);
    if (!cond && detail !== undefined) {
      const text = JSON.stringify(detail).slice(0, 3000);
      say(`DETAIL ${name}: ${text}`);
      if (process.env.GITHUB_ACTIONS) console.log(`::warning title=${('Detail of ' + name).replace(/[:,\r\n]/g, ' ').slice(0, 120)}::${text.replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}`);
    }
  };
  const IS_WIN = process.platform === 'win32';
  const IS_MAC = process.platform === 'darwin';
  if (!IS_WIN && !IS_MAC) return;
  const N = require('../core/network');
  const P = require('../core/processes');
  const W = require('../core/winnative');
  const U = require('../core/util');
  const T = `this system (${process.platform} ${process.arch}): `;
  const cleanup = [];

  try {
    // ---------- a port that this test opens ----------
    const server = net.createServer((s) => { s.on('error', () => {}); s.on('data', () => {}); });
    cleanup.push(() => server.close());
    ok(await listen(server, '127.0.0.1'), T + 'the test can open a port');
    const port = server.address().port;
    const mine = await until(async () => (await N.connections()).find((r) => r.state === 'Listen' && r.lp === port && r.pid === process.pid));
    ok(!!mine, T + 'a port that this program opens is found, with this program as its owner', mine || { port, pid: process.pid });
    ok(!!mine && mine.la === '127.0.0.1' && N.isLoopback(mine.la), T + 'the address of the listener is written like the rest of the program expects (127.0.0.1)');

    // ---------- an open connection ----------
    const client = net.connect(port, '127.0.0.1');
    client.on('error', () => {});
    cleanup.push(() => client.destroy());
    await new Promise((r) => client.once('connect', r));
    const cport = client.localPort;
    const conn = await until(async () => (await N.connections()).find((r) => r.state === 'Established' && r.lp === cport && r.rp === port && r.pid === process.pid));
    ok(!!conn, T + 'an open connection of this program is found, with the right ports and owner', conn || { cport, port });

    // ---------- the home network (worm watch) ----------
    const lan = Object.values(os.networkInterfaces()).flat().find((a) => a && a.family === 'IPv4' && !a.internal && /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)/.test(a.address));
    if (lan) {
      const lanServer = net.createServer((s) => { s.on('error', () => {}); });
      cleanup.push(() => lanServer.close());
      if (await listen(lanServer, lan.address)) {
        const lanPort = lanServer.address().port;
        const lanClient = net.connect(lanPort, lan.address);
        lanClient.on('error', () => {});
        cleanup.push(() => lanClient.destroy());
        await new Promise((r) => lanClient.once('connect', r));
        const home = await until(async () => (await N.attempts()).find((r) => r.ra === lan.address && r.rp === lanPort && r.pid === process.pid && r.state === 'Established'));
        ok(!!home, T + 'a connection to the home network is found for the worm watch', home || { lan: lan.address, lanPort });
      }
    } else say('(no address of a home network on this system: the worm watch check is skipped)');

    // ---------- a program that this test starts ----------
    const marker = `agathos-marker-${process.pid}-${Date.now()}`;
    const startedAt = Date.now();
    const child = cp.spawn(process.execPath, ['-e', 'setTimeout(function(){},45000)', marker], { stdio: 'ignore', windowsHide: true });
    cleanup.push(() => { try { child.kill(); } catch (_) { /* gone */ } });
    const row = await until(async () => (await P.listProcesses()).find((r) => r.p === child.pid), 15000);
    ok(!!row, T + 'a program that this test starts is in the list of programs', child.pid);
    ok(!!row && row.pp === process.pid, T + 'the list names the right parent', row && { pp: row.pp, expected: process.pid });
    ok(!!row && typeof row.c === 'string' && row.c.includes(marker) && row.c.includes('setTimeout'), T + 'the list holds the whole command line of the program', row && row.c);
    ok(!!row && same(row.e, process.execPath), T + 'the list holds the file of the program', row && { e: row.e, expected: process.execPath });
    ok(!!row && /^node(\.exe)?$/i.test(row.n), T + 'the list holds the name of the program', row && row.n);
    ok(!!row && row.t > startedAt - 15000 && row.t < Date.now() + 5000, T + 'the list holds the start time of the program (in milliseconds since 1970)', row && { t: row.t, startedAt });
    const me = (await P.listProcesses()).find((r) => r.p === process.pid);
    // On a Mac the system only tells the file of a program that was started with its full path; "node" typed in a terminal gives no file.
    ok(!!me && (IS_MAC || same(me.e, process.execPath)) && /node/i.test(me.n) && /run-tests|live-os/.test(me.c || ''), T + 'the program that runs the tests is in the list too, with its name and command line', me);
    try { child.kill(); } catch (_) { /* gone */ }
    const gone = await until(async () => !(await P.listProcesses()).some((r) => r.p === child.pid), 15000);
    ok(!!gone, T + 'a program that has ended leaves the list');

    // ---------- speed ----------
    const timeOf = async (fn, n = 5) => { await fn(); const t = []; for (let i = 0; i < n; i++) { const s = process.hrtime.bigint(); await fn(); t.push(Number(process.hrtime.bigint() - s) / 1e6); } return med(t); };
    const pMs = await timeOf(() => P.listProcesses());
    const cMs = await timeOf(() => N.connections());
    const aMs = await timeOf(() => N.attempts());
    say(`speed: list of programs ${pMs.toFixed(1)} ms, connections ${cMs.toFixed(1)} ms, attempts ${aMs.toFixed(1)} ms`);
    ok(pMs < 400 && cMs < 400 && aMs < 400, T + 'asking for programs and connections is quick (a fraction of a second)', { pMs, cMs, aMs });

    if (IS_WIN) {
      // ---------- the direct way works, and agrees with the PowerShell way ----------
      ok(W.status().on === true, T + 'the direct way of asking Windows is in use (not the slow PowerShell commands)', W.status());
      const direct = await W.processes();
      const old = await U.ps.json(P.PS_LIST, 60000);
      ok(Array.isArray(direct) && direct.length > 20 && old.length > 20, T + 'both ways give a list of programs', { direct: direct && direct.length, old: old.length });
      if (direct && old.length) {
        const byPid = new Map(direct.map((r) => [r.p, r]));
        const settled = old.filter((o) => byPid.has(o.p) && o.t && Date.now() - o.t > 4000 && byPid.get(o.p).t && Math.abs(byPid.get(o.p).t - o.t) < 3000);
        let parent = 0; let file = 0; let cmd = 0; let name = 0;
        const bad = [];
        for (const o of settled) {
          const d = byPid.get(o.p);
          if (d.pp !== o.pp) parent++;
          if (String(o.n).toLowerCase() !== String(d.n).toLowerCase()) name++;
          if (o.e && !same(o.e, d.e)) { file++; if (bad.length < 4) bad.push({ p: o.p, old: o.e, direct: d.e }); }
          if (o.c && String(o.c).replace(/\s+/g, ' ').trim() !== String(d.c || '').replace(/\s+/g, ' ').trim()) { cmd++; if (bad.length < 8) bad.push({ p: o.p, oldC: String(o.c).slice(0, 100), directC: String(d.c || '').slice(0, 100) }); }
        }
        const n = Math.max(1, settled.length);
        say(`compared ${settled.length} programs: parent differs ${parent}, name ${name}, file ${file}, command line ${cmd}`);
        ok(settled.length > 15 && parent / n < 0.03 && name / n < 0.05 && file / n < 0.05 && cmd / n < 0.05, T + 'the direct way agrees with the PowerShell way on parent, name, file and command line of the programs', { settled: settled.length, parent, name, file, cmd, bad });
        const none = direct.filter((r) => r.p > 4 && r.t && Date.now() - r.t > 10000 && !r.c).length;
        say(`programs older than 10 s without a command line: ${none} of ${direct.length}`);
      }
      const pre = await W.tcp();
      ok(Array.isArray(pre) && pre.some((r) => r.state === 'Listen' && r.lp === port && r.pid === process.pid), T + 'the TCP table of Windows holds the port that this test opened');
      const six = net.createServer();
      cleanup.push(() => six.close());
      if (await listen(six, '::1')) {
        const p6 = six.address().port;
        const f6 = await until(async () => (await N.connections()).find((r) => r.state === 'Listen' && r.lp === p6 && r.pid === process.pid));
        ok(!!f6 && f6.la === '::1' && N.isLoopback(f6.la), T + 'an IPv6 listener is found and its address is "::1"', f6);
      }
    } else {
      // ---------- Mac: netstat gives the same listeners as lsof ----------
      const mac = require('../core/mac');
      const viaNetstat = await mac.connections();
      ok(viaNetstat.some((r) => r.state === 'Listen' && r.pid > 0) && viaNetstat.every((r) => r.pid >= 0 && Number.isInteger(r.lp)), T + 'netstat gives listeners with a program for each');
      const lsof = await new Promise((resolve) => cp.execFile('/usr/sbin/lsof', ['-nP', '-iTCP', '-sTCP:LISTEN', '-F', 'pcnT'], { timeout: 20000, maxBuffer: 16 * 1024 * 1024 }, (e, out) => resolve(String(out || ''))));
      const viaLsof = mac.parseLsof(lsof).filter((r) => r.state === 'Listen');
      const have = new Set(viaNetstat.filter((r) => r.state === 'Listen').map((r) => `${r.pid}|${r.lp}`));
      const missing = viaLsof.filter((r) => !have.has(`${r.pid}|${r.lp}`));
      say(`lsof sees ${viaLsof.length} listeners, netstat misses ${missing.length}`);
      ok(viaLsof.length === 0 || missing.length / viaLsof.length <= 0.05, T + 'netstat finds the listeners that lsof finds (same program, same port)', { lsof: viaLsof.length, missing: missing.slice(0, 5) });
    }
  } finally {
    for (const f of cleanup) { try { f(); } catch (_) { /* already closed */ } }
    // What was measured and compared, as an annotation in GitHub Actions.
    if (process.env.GITHUB_ACTIONS && told.length) console.log(`::notice title=Real system checks ${process.platform} ${process.arch}::${told.join('\n').slice(0, 5000).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A')}`);
  }
}

module.exports = liveOsTests;

if (require.main === module) {
  let pass = 0;
  let fail = 0;
  liveOsTests({ ok: (c, name, detail) => { if (c) pass++; else fail++; console.log(c ? 'PASS' : 'FAIL', name, !c && detail !== undefined ? JSON.stringify(detail) : ''); }, say: console.log })
    .then(() => { console.log(`\n${pass} passed, ${fail} failed`); require('../core/util').ps.stop(); process.exit(fail ? 1 : 0); })
    .catch((e) => { console.error(e); process.exit(1); });
}
