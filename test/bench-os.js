'use strict';
// AgathOS - how long the watchers take on this system. Information only: this never fails.
//
//   node test/bench-os.js
//
// For each way of asking the system for the list of programs and for the network connections it shows the time of
// the first call, the typical time of the next calls and the CPU time of the whole PC per call (so the work of
// helper programs counts too). In GitHub Actions the result is also written as an annotation.
const os = require('os');
const { performance } = require('perf_hooks');
const U = require('../core/util');
const mac = require('../core/mac');
const net = require('../core/network');
const { PS_LIST } = require('../core/processes');

const IS_WIN = process.platform === 'win32';
const IS_MAC = process.platform === 'darwin';
const lines = [];
const say = (s) => { lines.push(String(s)); console.log(s); };
const annotate = (level, title, text) => {
  if (!process.env.GITHUB_ACTIONS) return;
  const esc = String(text).slice(0, 6000).replace(/%/g, '%25').replace(/\r/g, '%0D').replace(/\n/g, '%0A');
  console.log(`::${level} title=${title}::${esc}`);
};
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
// Busy time of all processors together, in milliseconds.
const busy = () => os.cpus().reduce((s, c) => s + c.times.user + c.times.nice + c.times.sys + c.times.irq, 0);
const med = (a) => { const s = [...a].sort((x, y) => x - y); return s[Math.floor(s.length / 2)]; };
const fmt = (n) => (n < 10 ? n.toFixed(1) : String(Math.round(n)));

let noise = 0;   // busy ms per ms of waiting, with nothing of ours running
async function measureNoise() {
  const b0 = busy();
  const t0 = performance.now();
  await sleep(1500);
  noise = Math.max(0, (busy() - b0) / (performance.now() - t0));
}

const results = [];
async function time(name, fn, runs = 7) {
  const times = [];
  let last = null;
  let first = 0;
  let cpu = 0;
  try {
    let t = performance.now();
    last = await fn();
    first = performance.now() - t;
    const b0 = busy();
    const t0 = performance.now();
    for (let i = 0; i < runs; i++) {
      t = performance.now();
      last = await fn();
      times.push(performance.now() - t);
    }
    const wall = performance.now() - t0;
    cpu = Math.max(0, busy() - b0 - noise * wall) / runs;
  } catch (e) {
    say(`ERR  ${name}: ${e && e.message}`);
  }
  const rows = last && typeof last === 'object' && 'rows' in last ? last.rows : '-';
  const row = { name, first, median: times.length ? med(times) : 0, cpu, rows, sample: last && last.sample ? last.sample : '' };
  results.push(row);
  say(`${name.padEnd(22)} first ${fmt(first).padStart(5)} ms   next ${fmt(row.median).padStart(5)} ms   pc cpu ${fmt(cpu).padStart(5)} ms   rows ${rows}`);
  return row;
}

const head = (text, n) => String(text || '').split(/\r?\n/).filter(Boolean).slice(0, n).join(' | ');

// ---------- Windows ----------
// A small program inside PowerShell that asks Windows for the list of programs and the TCP table directly.
const CS = `
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class AgNative {
  [DllImport("iphlpapi.dll", SetLastError = true)]
  static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);
  public static string Tcp(int af) {
    int size = 0;
    GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5, 0);
    for (int i = 0; i < 5; i++) {
      int len = size + 4096;
      IntPtr buf = Marshal.AllocHGlobal(len);
      try {
        uint r = GetExtendedTcpTable(buf, ref len, false, af, 5, 0);
        if (r == 0) { byte[] b = new byte[len]; Marshal.Copy(buf, b, 0, len); return Convert.ToBase64String(b); }
        if (r != 122) return "";
        size = len;
      } finally { Marshal.FreeHGlobal(buf); }
    }
    return "";
  }
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  struct PROCESSENTRY32 {
    public uint dwSize; public uint cntUsage; public uint th32ProcessID; public IntPtr th32DefaultHeapID; public uint th32ModuleID;
    public uint cntThreads; public uint th32ParentProcessID; public int pcPriClassBase; public uint dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szExeFile;
  }
  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr h, ref PROCESSENTRY32 e);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr h, ref PROCESSENTRY32 e);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);
  public static string Procs(bool times) {
    IntPtr snap = CreateToolhelp32Snapshot(2, 0);
    if (snap == (IntPtr)(-1)) return "";
    StringBuilder sb = new StringBuilder();
    try {
      PROCESSENTRY32 e = new PROCESSENTRY32();
      e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
      if (!Process32FirstW(snap, ref e)) return "";
      do {
        long created = 0;
        if (times) {
          IntPtr h = OpenProcess(0x1000, false, e.th32ProcessID);
          if (h != IntPtr.Zero) { long x, k, u; GetProcessTimes(h, out created, out x, out k, out u); CloseHandle(h); }
        }
        sb.Append(e.th32ProcessID).Append('\\t').Append(e.th32ParentProcessID).Append('\\t').Append(created).Append('\\t').Append(e.szExeFile).Append('\\n');
      } while (Process32NextW(snap, ref e));
    } finally { CloseHandle(snap); }
    return sb.ToString();
  }
}
`;
const ADD_TYPE = `$src = @'\n${CS}\n'@\nif (-not ('AgNative' -as [type])) { try { Add-Type -TypeDefinition $src -ErrorAction Stop } catch { Write-Output ('ADDTYPE-ERROR ' + $_.Exception.Message) } }`;

const PS_CIM_SELECT = 'Get-CimInstance Win32_Process | Select-Object ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate | ConvertTo-Json -Compress';
const PS_CIM_JOIN = `$sb = New-Object System.Text.StringBuilder
foreach ($p in (Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name,CommandLine,ExecutablePath,CreationDate)) {
  [void]$sb.Append($p.ProcessId).Append("\`t").Append($p.ParentProcessId).Append("\`t").Append($p.Name).Append("\`t").Append($p.ExecutablePath).Append("\`n")
}
$sb.ToString()`;
const PS_DOTNET = '[System.Diagnostics.Process]::GetProcesses() | ForEach-Object { "$($_.Id)`t$($_.ProcessName)" }';

async function windows() {
  await time('spawn cmd.exe', async () => { await U.execFileText('cmd.exe', ['/d', '/c', 'exit'], 15000); return {}; });
  await time('ps round trip', async () => { await U.ps.run('1', 15000); return {}; });
  await time('proc cim (now)', async () => { const r = await U.ps.json(PS_LIST, 60000); return { rows: r.length }; }, 5);
  await time('proc cim select', async () => { const r = await U.ps.json(PS_CIM_SELECT, 60000); return { rows: r.length }; }, 5);
  await time('proc cim join', async () => { const t = await U.ps.run(PS_CIM_JOIN, 60000); return { rows: String(t || '').split('\n').filter(Boolean).length }; }, 5);
  await time('proc .NET', async () => { const t = await U.ps.run(PS_DOTNET, 60000); return { rows: String(t || '').split('\n').filter(Boolean).length }; });
  const t0 = performance.now();
  const added = await U.ps.run(ADD_TYPE, 120000);
  say(`add-type (compile)      ${fmt(performance.now() - t0)} ms   ${String(added || '').trim().slice(0, 300) || 'ok'}`);
  results.push({ name: 'add-type', first: performance.now() - t0, median: 0, cpu: 0, rows: '-', sample: '' });
  await time('proc toolhelp', async () => { const t = await U.ps.run('[AgNative]::Procs($false)', 30000); return { rows: String(t || '').split('\n').filter(Boolean).length, sample: head(t, 3) }; });
  await time('proc toolhelp+times', async () => { const t = await U.ps.run('[AgNative]::Procs($true)', 30000); return { rows: String(t || '').split('\n').filter(Boolean).length, sample: head(t, 3) }; });
  await time('net now: all', async () => { const r = await net.connections(); return { rows: r.length }; }, 5);
  await time('net now: attempts', async () => { const r = await net.attempts(); return { rows: r.length }; }, 5);
  await time('net netstat -ano', async () => { const t = await U.execFileText('netstat.exe', ['-ano', '-p', 'TCP'], 30000); return { rows: String(t || '').split(/\r?\n/).filter((l) => /^\s*TCP/i.test(l)).length, sample: head(t, 6) }; });
  await time('net table v4+v6', async () => {
    const t = await U.ps.run('[AgNative]::Tcp(2)\n[AgNative]::Tcp(23)', 30000);
    const parts = String(t || '').split(/\r?\n/).filter(Boolean);
    const rows = parts.reduce((s, b) => { try { return s + Buffer.from(b, 'base64').readUInt32LE(0); } catch (_) { return s; } }, 0);
    return { rows, sample: `${parts.map((b) => b.length).join('+')} base64 characters` };
  });
}

// ---------- macOS ----------
const run = (cmd, args, timeout = 30000) => U.execFileText(cmd, args, timeout);
async function macos() {
  await time('spawn true', async () => { await run('/usr/bin/true', []); return {}; });
  await time('proc ps x2 (now)', async () => { const r = await mac.listProcesses(); return { rows: r.length }; }, 5);
  await time('proc ps one', async () => { const t = await run('/bin/ps', ['-axww', '-o', 'pid=,ppid=,lstart=,comm=']); return { rows: String(t || '').split('\n').filter(Boolean).length }; }, 5);
  await time('proc ps args', async () => { const t = await run('/bin/ps', ['-axww', '-o', 'pid=,args=']); return { rows: String(t || '').split('\n').filter(Boolean).length }; }, 5);
  await time('net lsof all (now)', async () => { const r = await mac.connections(); return { rows: r.length }; }, 4);
  await time('net lsof attempts', async () => { const r = await mac.attempts(); return { rows: r.length }; }, 4);
  await time('net netstat -anv', async () => {
    const t = await run('/usr/sbin/netstat', ['-anv', '-p', 'tcp']);
    const all = String(t || '').split('\n');
    const listen = all.find((l) => /LISTEN/.test(l)) || '';
    const est = all.find((l) => /ESTABLISHED/.test(l)) || '';
    return { rows: all.filter((l) => /^tcp/.test(l)).length, sample: `${head(t, 2)} | ${listen.trim()} | ${est.trim()}` };
  }, 5);
  await time('net netstat -an', async () => { const t = await run('/usr/sbin/netstat', ['-an', '-p', 'tcp']); return { rows: String(t || '').split('\n').filter((l) => /^tcp/.test(l)).length }; }, 5);
}

(async () => {
  if (!IS_WIN && !IS_MAC) { console.log('bench-os: only for Windows and macOS'); return; }
  const cpus = os.cpus();
  say(`system: ${process.platform} ${process.arch} ${os.release()}   ${cpus.length} x ${cpus[0] && cpus[0].model}   ${(os.totalmem() / 1073741824).toFixed(1)} GB   node ${process.versions.node}`);
  await measureNoise();
  say(`rest of the PC: ${(noise * 100).toFixed(1)}% busy while nothing of ours runs`);
  if (IS_WIN) await windows(); else await macos();
  if (IS_WIN) U.ps.stop();
  const text = lines.join('\n') + '\n\nsamples:\n' + results.filter((r) => r.sample).map((r) => `${r.name}: ${r.sample}`).join('\n');
  annotate('notice', `Speed ${process.platform} ${process.arch}`, text);
})().catch((e) => { console.error(e); annotate('warning', `Speed ${process.platform}`, String(e && e.stack || e)); }).then(() => process.exit(0));
