'use strict';
// AgathOS - tests of the direct ways of asking the system for programs and connections (Windows: core/winnative.js,
// Mac: netstat in core/mac.js). They only read made-up answers, so they run on every system. The checks that ask the
// real system are in test/live-os.js. Called by test/run-tests.js.
const W = require('../core/winnative');
const N = require('../core/network');
const M = require('../core/mac');
const { PowerShell } = require('../core/shell');

// A row of the Windows TCP table the way Windows writes it (ports and addresses in network order).
function row4(state, la, lp, ra, rp, pid) {
  const b = Buffer.alloc(24);
  b.writeUInt32LE(state, 0);
  la.split('.').forEach((x, i) => { b[4 + i] = +x; });
  b[8] = lp >> 8; b[9] = lp & 255;
  ra.split('.').forEach((x, i) => { b[12 + i] = +x; });
  b[16] = rp >> 8; b[17] = rp & 255;
  b.writeUInt32LE(pid, 20);
  return b;
}
function row6(state, la, lp, ra, rp, pid) {
  const b = Buffer.alloc(56);
  Buffer.from(la).copy(b, 0);
  b[20] = lp >> 8; b[21] = lp & 255;
  Buffer.from(ra).copy(b, 24);
  b[44] = rp >> 8; b[45] = rp & 255;
  b.writeUInt32LE(state, 48);
  b.writeUInt32LE(pid, 52);
  return b;
}
const addr6 = (...g) => { const b = Buffer.alloc(16); g.forEach((x, i) => b.writeUInt16BE(x, 2 * i)); return b; };
const table = (kind, rows, slack = 8) => {
  const n = Buffer.alloc(4);
  n.writeUInt32LE(rows.length, 0);
  return `${kind}:${Buffer.concat([n, ...rows, Buffer.alloc(slack)]).toString('base64')}`;
};

module.exports = async function nativeTests({ ok }) {
  const T = 'direct system calls: ';

  // ---------- the TCP table of Windows ----------
  const v4 = W.parseTable(table('4', [
    row4(2, '0.0.0.0', 135, '0.0.0.0', 0, 1092),
    row4(5, '192.168.1.20', 52311, '140.82.112.3', 443, 4242),
    row4(3, '10.0.0.5', 50000, '10.0.0.77', 445, 777),
    row4(11, '127.0.0.1', 8080, '127.0.0.1', 51000, 5),
  ]));
  ok(v4.length === 4, T + 'the rows of an IPv4 table are all read, and the bytes after them are not');
  ok(JSON.stringify(v4[0]) === JSON.stringify({ la: '0.0.0.0', lp: 135, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 1092 }), T + 'a listener is read with its address, port and program');
  ok(v4[1].state === 'Established' && v4[1].la === '192.168.1.20' && v4[1].lp === 52311 && v4[1].ra === '140.82.112.3' && v4[1].rp === 443 && v4[1].pid === 4242, T + 'an open connection is read in full (ports above 255 too)');
  ok(v4[2].state === 'SynSent' && v4[3].state === 'TimeWait', T + 'the states get the names the rest of the program uses (SynSent, TimeWait)');
  const v6 = W.parseTable(table('6', [
    row6(2, addr6(0, 0, 0, 0, 0, 0, 0, 0), 445, addr6(0, 0, 0, 0, 0, 0, 0, 0), 0, 4),
    row6(5, addr6(0, 0, 0, 0, 0, 0, 0, 1), 50001, addr6(0, 0, 0, 0, 0, 0, 0, 1), 8080, 99),
    row6(5, addr6(0xfe80, 0, 0, 0, 0x1234, 0, 0, 7), 50002, addr6(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1), 443, 100),
  ]));
  ok(v6.length === 3 && v6[0].la === '::' && v6[0].lp === 445 && v6[0].state === 'Listen' && v6[0].pid === 4, T + 'an IPv6 listener is read ("::" for any address)');
  ok(v6[1].la === '::1' && v6[1].ra === '::1' && v6[1].rp === 8080 && v6[1].pid === 99, T + 'the IPv6 loopback address is written "::1", which the program already knows as loopback');
  ok(v6[2].la === 'fe80::1234:0:0:7' && v6[2].ra === '2001:db8::1', T + 'IPv6 addresses are written short, with the longest run of zeros as "::"');
  ok(W.ip6(addr6(0, 0, 0, 0, 0, 0xffff, 0xc0a8, 0x0105), 0) === '::ffff:192.168.1.5', T + 'an IPv4 address inside IPv6 keeps its dotted form');
  ok(W.ip6(addr6(0x2001, 0xdb8, 0, 0, 1, 0, 0, 1), 0) === '2001:db8::1:0:0:1', T + 'with two equal runs of zeros the first one is shortened');
  ok(W.ip6(addr6(1, 2, 3, 4, 5, 6, 7, 8), 0) === '1:2:3:4:5:6:7:8', T + 'an address without zeros is written in full');
  ok(W.parseTcp(`${table('4', [row4(5, '1.2.3.4', 1, '5.6.7.8', 2, 3)])}\r\n${table('6', [row6(2, addr6(0, 0, 0, 0, 0, 0, 0, 0), 80, addr6(0, 0, 0, 0, 0, 0, 0, 0), 0, 4)])}\r\n`).length === 2, T + 'the answer with both tables gives the rows of both');
  const cut = table('4', [row4(5, '1.1.1.1', 1, '2.2.2.2', 2, 3), row4(5, '1.1.1.2', 1, '2.2.2.2', 2, 3)], 0);
  const lie = Buffer.from(cut.slice(2), 'base64');
  lie.writeUInt32LE(9, 0);
  ok(W.parseTable(`4:${lie.toString('base64')}`).length === 2, T + 'a table that claims more rows than it holds gives the rows it holds');
  ok(W.parseTable('4:').length === 0 && W.parseTable('') .length === 0 && W.parseTable('nonsense').length === 0 && W.parseTable('6:!!!').length === 0 && W.parseTcp(null).length === 0, T + 'nothing or nonsense gives no rows and no error');

  // ---------- the rows for the network view and the worm watch ----------
  const all = [...v4, ...v6];
  const seen = N.listenAndEstablished(all);
  ok(seen.length === 5 && seen.every((r) => r.state === 'Listen' || r.state === 'Established') && Object.keys(seen[0]).sort().join() === 'la,lp,pid,ra,rp,state', T + 'the network view gets listeners and open connections, in the shape it always had');
  const home = N.toHomeNetwork(all);
  ok(home.length === 1 && home[0].ra === '10.0.0.77' && home[0].rp === 445 && home[0].state === 'SynSent' && home[0].pid === 777 && Object.keys(home[0]).sort().join() === 'pid,ra,rp,state', T + 'the worm watch gets attempts and connections to the home network only');
  ok(N.toHomeNetwork([{ ra: '172.16.0.9', rp: 22, state: 'Established', pid: 1 }, { ra: '172.32.0.9', rp: 22, state: 'Established', pid: 1 }, { ra: '169.254.1.1', rp: 22, state: 'SynSent', pid: 1 }, { ra: '8.8.8.8', rp: 53, state: 'SynSent', pid: 1 }]).length === 2, T + 'the home network is 10.x, 172.16-31.x, 192.168.x and 169.254.x');

  // ---------- the list of programs of Windows ----------
  const text = [
    '0\t0\t0\t[System Process]\t\t',
    '4\t0\t0\tSystem\t\t',
    '10\t4\t1760000000000\tnode.exe\tC:\\Program Files\\nodejs\\node.exe\t"C:\\Program Files\\nodejs\\node.exe" cli.js --flag "a b"',
    '11\t10\t1760000001500\tcmd.exe\tC:\\Windows\\System32\\cmd.exe\tcmd /c echo   hi',
    'not a row',
    'x\t1\t2\tn\te\tc',
    '',
  ].join('\r\n');
  const procs = W.parseProcs(text);
  ok(procs.length === 4, T + 'lines that are no program are skipped');
  ok(procs[2].p === 10 && procs[2].pp === 4 && procs[2].n === 'node.exe' && procs[2].e === 'C:\\Program Files\\nodejs\\node.exe' && procs[2].c === '"C:\\Program Files\\nodejs\\node.exe" cli.js --flag "a b"' && procs[2].t === 1760000000000, T + 'a program has id, parent, name, file, command line and start time');
  ok(procs[1].e === null && procs[1].c === null && procs[1].t === 0, T + 'a program that Windows tells nothing about has no file and no command line (null, like before)');
  ok(Object.keys(procs[2]).sort().join() === 'c,e,n,p,pp,t', T + 'the rows have the shape of the PowerShell way, so the watcher needs no change');

  // ---------- the program that is put into PowerShell ----------
  ok(/GetExtendedTcpTable/.test(W.CS) && /CreateToolhelp32Snapshot/.test(W.CS) && /NtQueryInformationProcess/.test(W.CS) && /QueryFullProcessImageNameW/.test(W.CS), T + 'the program asks Windows for the TCP table, the list of programs, their command lines and their files');
  ok(!/\bref\s+var\b|\$"|\?\.|=>|nameof\(/.test(W.CS), T + 'the program stays within what the compiler of Windows PowerShell 5.1 understands (C# 5)');
  ok(/\\t/.test(W.CS) && !/\t/.test(W.CS.replace(/\\t/g, '')), T + 'tabs and line ends in the program are written as escapes, not as real characters');
  ok(/^\$src = @'\r?\n/.test(W.LOAD) && /\r?\n'@\r?\n/.test(W.LOAD) && /Add-Type -TypeDefinition \$src/.test(W.LOAD) && /AGATHOS-NATIVE-OK/.test(W.LOAD), T + 'the PowerShell text puts the program in a here-string and adds it once');
  ok(new PowerShell().generation === 0, T + 'the PowerShell counts how often it was started, so the program is put in again after a restart');
  W.reset();
  if (process.platform !== 'win32') ok(W.status().on === false && (await W.processes()) === null && (await W.tcp()) === null, T + 'where there is no PowerShell the direct ways give nothing, and the old ones are used');
  else ok(W.status().on === false && W.status().off === false, T + 'before the first question the direct way has not been tried yet');

  // ---------- netstat on the Mac ----------
  const modern = [
    'Active Internet connections (including servers)',
    'Proto Recv-Q Send-Q  Local Address                                 Foreign Address                               (state)          rxbytes      txbytes  rhiwat  shiwat          process:pid    state  options           gencnt    flags   flags1 usecnt rtncnt fltrs',
    'tcp4       0      0  *.22                   *.*                    LISTEN                 0            0  131072  131072          launchd:1      00180 00000006 0000000000000010 00000000 00000800      1      0 000000',
    'tcp4       0      0  192.168.64.17.49164    20.75.202.224.443      ESTABLISHED        13076         4019  131072  132432 provjobd33879045:986    00182 00000008 000000000000106c 00000080 04000900      2      0 000000',
    'tcp6       0      0  ::1.631                *.*                    LISTEN                 0            0  131072  131072          Google Chrome H:5678      00180 00000006 0000000000000010 00000000 00000800      1      0 000000',
    'tcp4       0      0  192.168.1.5.55321      192.168.1.77.445       SYN_SENT               0            0  131072  131072          worm:777      00182 00000008 000000000000106c 00000080 04000900      2      0 000000',
    'tcp4       0      0  127.0.0.1.1234         127.0.0.1.5678         TIME_WAIT              0            0  131072  131072          kernel_task:0      00182 00000008 000000000000106c 00000080 04000900      2      0 000000',
    'tcp46      0      0  *.47612                *.*                    LISTEN                 0            0  131072  131072          AgathOS:4242      00180 00000006 0000000000000010 00000000 00000800      1      0 000000',
  ].join('\n');
  const mrows = M.parseNetstat(modern);
  ok(mrows.length === 5, T + 'netstat on a Mac: listeners, open connections and attempts are read, other states (TIME_WAIT) are left out');
  ok(JSON.stringify(mrows[0]) === JSON.stringify({ la: '0.0.0.0', lp: 22, ra: '0.0.0.0', rp: 0, state: 'Listen', pid: 1, n: 'launchd' }), T + 'a listener on every address is "0.0.0.0" with its program');
  ok(mrows[1].la === '192.168.64.17' && mrows[1].lp === 49164 && mrows[1].ra === '20.75.202.224' && mrows[1].rp === 443 && mrows[1].state === 'Established' && mrows[1].pid === 986, T + 'netstat writes host.port; the port is the part after the last dot');
  ok(mrows[2].la === '::1' && mrows[2].lp === 631 && mrows[2].pid === 5678 && mrows[2].n === 'Google Chrome H', T + 'a program name with spaces and an IPv6 address are read');
  ok(mrows[3].state === 'SynSent' && mrows[3].ra === '192.168.1.77' && mrows[3].rp === 445 && mrows[3].pid === 777, T + 'an attempt (SYN_SENT) is read for the worm watch');
  ok(mrows[4].lp === 47612 && mrows[4].pid === 4242, T + 'a tcp46 socket (both IPv4 and IPv6) is read too');
  const older = [
    'Active Internet connections (including servers)',
    'Proto Recv-Q Send-Q  Local Address          Foreign Address        (state)      rhiwat shiwat    pid   epid state    options',
    'tcp4       0      0  127.0.0.1.8080         *.*                    LISTEN       131072 131072   1234      0 00100 00000006',
    'tcp6       0      0  fe80::1%lo0.1234       fe80::2%lo0.80         ESTABLISHED  131072 131072    555      0 00102 00000008',
  ].join('\n');
  const orows = M.parseNetstat(older);
  ok(orows.length === 2 && orows[0].pid === 1234 && orows[0].lp === 8080 && orows[1].la === 'fe80::1' && orows[1].rp === 80 && orows[1].pid === 555, T + 'netstat of an older macOS (pid and epid in two columns) is read too');
  ok(M.parseNetstat('').length === 0 && M.parseNetstat(null).length === 0 && M.parseNetstat('Proto Recv-Q Send-Q Local Address Foreign Address (state)\ntcp4 0 0 *.22 *.* LISTEN').length === 0 && M.parseNetstat('tcp4 0 0 *.22 *.* LISTEN 1 2 3 4 5 6').length === 0,
    T + 'netstat without the program column, or without a header, gives no rows (the Mac then uses lsof as before)');
  ok(M.splitNetstatAddr('*.*').a === '0.0.0.0' && M.splitNetstatAddr('*.*').p === 0 && M.splitNetstatAddr('10.1.2.3.8443').p === 8443 && M.splitNetstatAddr('2001:db8::5.443').a === '2001:db8::5', T + 'the addresses of netstat are split at the last dot');
};
