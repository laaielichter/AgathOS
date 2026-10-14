'use strict';
// AgathOS - Windows: asking Windows directly for the list of programs and the TCP table.
//
// The PowerShell commands for this (Get-CimInstance Win32_Process, Get-NetTCPConnection) go through WMI and take 70 to 120
// milliseconds of processor time per call on a quiet PC, and they are asked every few seconds, all day. A small program inside
// the PowerShell that is already running reads the same things from Windows itself in 2 to 5 milliseconds.
// This file holds that program (as text), the way to start it and the reading of what it answers. Nothing here starts a
// program: the text is run by core/shell.js like every other script. When it cannot be used (PowerShell in a locked-down
// mode, a security program that refuses it) the callers return to the old way.
const U = require('./util');

// ---------- the program (C#, kept to what the compiler of Windows PowerShell 5.1 understands) ----------
const CS = `
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
public static class AgNative {
  [DllImport("iphlpapi.dll", SetLastError = true)]
  static extern uint GetExtendedTcpTable(IntPtr table, ref int size, bool order, int af, int cls, uint reserved);

  // The TCP table of the system, as it is, in base64 with "4:" (IPv4) or "6:" (IPv6) in front. The reading is done in Node.
  public static string Tcp(int af) {
    int rowSize = af == 2 ? 24 : 56;
    int size = 0;
    GetExtendedTcpTable(IntPtr.Zero, ref size, false, af, 5, 0);
    for (int i = 0; i < 6; i++) {
      int len = size + 4096;
      IntPtr buf = Marshal.AllocHGlobal(len);
      try {
        uint r = GetExtendedTcpTable(buf, ref len, false, af, 5, 0);
        if (r == 0) {
          int n = Marshal.ReadInt32(buf);
          int total = 4 + n * rowSize;
          if (n < 0 || total > len) return "";
          byte[] b = new byte[total];
          Marshal.Copy(buf, b, 0, total);
          return (af == 2 ? "4:" : "6:") + Convert.ToBase64String(b);
        }
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
  [StructLayout(LayoutKind.Sequential)]
  struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }

  [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr CreateToolhelp32Snapshot(uint flags, uint pid);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32FirstW(IntPtr h, ref PROCESSENTRY32 e);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool Process32NextW(IntPtr h, ref PROCESSENTRY32 e);
  [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
  [DllImport("kernel32.dll")] static extern IntPtr OpenProcess(uint access, bool inherit, uint pid);
  [DllImport("kernel32.dll")] static extern bool GetProcessTimes(IntPtr h, out long create, out long exit, out long kernel, out long user);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] static extern bool QueryFullProcessImageNameW(IntPtr h, int flags, StringBuilder name, ref int size);
  [DllImport("ntdll.dll")] static extern int NtQueryInformationProcess(IntPtr h, int cls, IntPtr buf, int len, out int ret);

  // Program, command line and start time of a program are asked once, when it is first seen; after that they come from here.
  static Dictionary<uint, string[]> seen = new Dictionary<uint, string[]>();

  static string Clean(string s) {
    if (s == null) return "";
    return s.Replace('\\t', ' ').Replace('\\r', ' ').Replace('\\n', ' ');
  }
  static string Image(IntPtr h) {
    StringBuilder sb = new StringBuilder(1024);
    int size = sb.Capacity;
    return QueryFullProcessImageNameW(h, 0, sb, ref size) ? sb.ToString() : "";
  }
  static string CommandLine(IntPtr h) {
    int need = 0;
    NtQueryInformationProcess(h, 60, IntPtr.Zero, 0, out need);
    if (need <= 0 || need > 1048576) return "";
    IntPtr buf = Marshal.AllocHGlobal(need);
    try {
      int got;
      if (NtQueryInformationProcess(h, 60, buf, need, out got) != 0) return "";
      UNICODE_STRING us = (UNICODE_STRING)Marshal.PtrToStructure(buf, typeof(UNICODE_STRING));
      if (us.Buffer == IntPtr.Zero || us.Length == 0) return "";
      return Marshal.PtrToStringUni(us.Buffer, us.Length / 2);
    } finally { Marshal.FreeHGlobal(buf); }
  }

  // One line per program: id, parent, start (milliseconds since 1970), name, file, command line. Fields are separated by a tab.
  public static string Procs() {
    IntPtr snap = CreateToolhelp32Snapshot(2, 0);
    if (snap == (IntPtr)(-1)) return "";
    StringBuilder sb = new StringBuilder(64 * 1024);
    HashSet<uint> alive = new HashSet<uint>();
    long nowFt = DateTime.UtcNow.ToFileTimeUtc();
    try {
      PROCESSENTRY32 e = new PROCESSENTRY32();
      e.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));
      if (!Process32FirstW(snap, ref e)) return "";
      do {
        uint pid = e.th32ProcessID;
        alive.Add(pid);
        long created = 0;
        string image = "";
        string cmd = "";
        IntPtr h = pid == 0 ? IntPtr.Zero : OpenProcess(0x1000, false, pid);
        if (h != IntPtr.Zero) {
          long x, k, u;
          if (!GetProcessTimes(h, out created, out x, out k, out u)) created = 0;
          string[] old;
          if (created != 0 && seen.TryGetValue(pid, out old) && old[0] == created.ToString()) { image = old[1]; cmd = old[2]; }
          else {
            image = Image(h);
            cmd = CommandLine(h);
            bool young = created != 0 && nowFt - created < 30000000L;
            if (created != 0 && !(young && cmd.Length == 0)) seen[pid] = new string[] { created.ToString(), image, cmd };
          }
          CloseHandle(h);
        }
        long ms = created > 0 ? created / 10000 - 11644473600000L : 0;
        sb.Append(pid).Append('\\t').Append(e.th32ParentProcessID).Append('\\t').Append(ms).Append('\\t')
          .Append(Clean(e.szExeFile)).Append('\\t').Append(Clean(image)).Append('\\t').Append(Clean(cmd)).Append('\\n');
      } while (Process32NextW(snap, ref e));
    } finally { CloseHandle(snap); }
    List<uint> gone = new List<uint>();
    foreach (uint key in seen.Keys) if (!alive.Contains(key)) gone.Add(key);
    foreach (uint key2 in gone) seen.Remove(key2);
    return sb.ToString();
  }
}
`;

// Adds the program to the running PowerShell once. It says "AGATHOS-NATIVE-OK" or "AGATHOS-NATIVE-ERR <why>".
const LOAD = `$src = @'\n${CS}\n'@\n`
  + "if ('AgNative' -as [type]) { Write-Output 'AGATHOS-NATIVE-OK' } else { try { Add-Type -TypeDefinition $src -ErrorAction Stop; Write-Output 'AGATHOS-NATIVE-OK' } catch { Write-Output ('AGATHOS-NATIVE-ERR ' + $_.Exception.Message) } }";
const ASK_PROCS = '[AgNative]::Procs()';
const ASK_TCP = '[AgNative]::Tcp(2)\n[AgNative]::Tcp(23)';

// ---------- reading what the program answers ----------
// The list of programs: { p, pp, n, c, e, t } like the PowerShell way (c and e are null when Windows does not tell).
function parseProcs(text) {
  const rows = [];
  for (const line of String(text || '').split('\n')) {
    const f = line.replace(/\r$/, '').split('\t');
    if (f.length < 6) continue;
    const p = Number(f[0]);
    if (!Number.isInteger(p) || p < 0) continue;
    rows.push({ p, pp: Number(f[1]) || 0, n: f[3], c: f.slice(5).join(' ') || null, e: f[4] || null, t: Number(f[2]) || 0 });
  }
  return rows;
}

// MIB_TCP_STATE, with the names Get-NetTCPConnection uses (the rest of the program compares with them).
const STATES = { 1: 'Closed', 2: 'Listen', 3: 'SynSent', 4: 'SynReceived', 5: 'Established', 6: 'FinWait1', 7: 'FinWait2', 8: 'CloseWait', 9: 'Closing', 10: 'LastAck', 11: 'TimeWait', 12: 'DeleteTCB' };

const hex = (n) => n.toString(16);
function ip4(b, o) { return `${b[o]}.${b[o + 1]}.${b[o + 2]}.${b[o + 3]}`; }
// IPv6 the short way: the longest run of zero groups becomes "::", like Windows writes it.
function ip6(b, o) {
  const g = [];
  for (let i = 0; i < 8; i++) g.push((b[o + 2 * i] << 8) | b[o + 2 * i + 1]);
  if (g.slice(0, 5).every((x) => x === 0) && g[5] === 0xffff) return `::ffff:${g[6] >> 8}.${g[6] & 255}.${g[7] >> 8}.${g[7] & 255}`;
  let best = -1;
  let bestLen = 0;
  for (let i = 0; i < 8;) {
    if (g[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && g[j] === 0) j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  if (bestLen < 2) return g.map(hex).join(':');
  return `${g.slice(0, best).map(hex).join(':')}::${g.slice(best + bestLen).map(hex).join(':')}`;
}

// One table ("4:<base64>" or "6:<base64>") into rows { la, lp, ra, rp, state, pid }. A table that is cut off gives the rows it holds.
function parseTable(line) {
  const m = /^([46]):([A-Za-z0-9+/=]*)$/.exec(String(line || '').trim());
  if (!m) return [];
  const b = Buffer.from(m[2], 'base64');
  if (b.length < 4) return [];
  const v6 = m[1] === '6';
  const size = v6 ? 56 : 24;
  const n = Math.min(b.readUInt32LE(0), Math.floor((b.length - 4) / size));
  const rows = [];
  for (let i = 0; i < n; i++) {
    const o = 4 + i * size;
    if (v6) {
      rows.push({ la: ip6(b, o), lp: (b[o + 20] << 8) | b[o + 21], ra: ip6(b, o + 24), rp: (b[o + 44] << 8) | b[o + 45], state: STATES[b.readUInt32LE(o + 48)] || String(b.readUInt32LE(o + 48)), pid: b.readUInt32LE(o + 52) });
    } else {
      rows.push({ la: ip4(b, o + 4), lp: (b[o + 8] << 8) | b[o + 9], ra: ip4(b, o + 12), rp: (b[o + 16] << 8) | b[o + 17], state: STATES[b.readUInt32LE(o)] || String(b.readUInt32LE(o)), pid: b.readUInt32LE(o + 20) });
    }
  }
  return rows;
}
const parseTcp = (text) => String(text || '').split(/\r?\n/).filter(Boolean).flatMap(parseTable);

// ---------- using it ----------
const st = { gen: -1, ok: false, off: false, why: '', loading: null, failures: 0 };

// True when the program is loaded in the running PowerShell (loaded again after the PowerShell was restarted).
function ready() {
  if (!U.IS_WIN || st.off) return Promise.resolve(false);
  if (st.ok && st.gen === U.ps.generation) return Promise.resolve(true);
  if (!st.loading) {
    st.loading = (async () => {
      try {
        const out = String(await U.ps.run(LOAD, 60000) || '');
        if (!/AGATHOS-NATIVE-OK/.test(out)) { st.off = true; st.ok = false; st.why = (out.match(/AGATHOS-NATIVE-ERR (.*)/) || [])[1] || 'no answer'; return false; }
        st.gen = U.ps.generation;
        // A check on the one program we know for sure: the PowerShell itself must come back with its file and command line.
        const rows = parseProcs(await U.ps.run(ASK_PROCS, 30000));
        const me = rows.find((r) => U.ps.proc && r.p === U.ps.proc.pid);
        st.ok = rows.length > 5 && !!me && /powershell/i.test(me.e || '') && /powershell/i.test(me.c || '');
        if (!st.ok) { st.off = true; st.why = 'self-check failed'; }
        return st.ok;
      } catch (e) {
        st.off = true; st.ok = false; st.why = String(e && e.message || e);
        return false;
      } finally { st.loading = null; }
    })();
  }
  return st.loading;
}

// The list of programs, or null when this way cannot be used (the caller then uses the old way).
async function processes() {
  if (!(await ready())) return null;
  const rows = parseProcs(await U.ps.run(ASK_PROCS, 20000));
  if (rows.length < 5) { if (++st.failures >= 3) { st.off = true; st.why = 'empty answers'; } return null; }
  st.failures = 0;
  return rows;
}

// The TCP connections and listeners (IPv4 and IPv6) as { la, lp, ra, rp, state, pid }, or null.
async function tcp() {
  if (!(await ready())) return null;
  const rows = parseTcp(await U.ps.run(ASK_TCP, 15000));
  if (!rows.length) { if (++st.failures >= 3) { st.off = true; st.why = 'empty answers'; } return null; }
  st.failures = 0;
  return rows;
}

const status = () => ({ on: st.ok && !st.off, off: st.off, why: st.why });
const reset = () => { st.gen = -1; st.ok = false; st.off = false; st.why = ''; st.loading = null; st.failures = 0; };

module.exports = { CS, LOAD, ASK_PROCS, ASK_TCP, STATES, parseProcs, parseTable, parseTcp, ip4, ip6, ready, processes, tcp, status, reset };
