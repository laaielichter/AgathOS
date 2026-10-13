'use strict';
// AgathOS - the stop button, in steps.
//  1. freeze the agent's process tree (reversible; files stay as they are)
//  2. resume
//  3. stop the tree (taskkill /T /F)
//  4. block the agent's program from the internet (needs AgathOS Guard, see guard/)
// Freezing uses NtSuspendProcess through a tiny C# helper loaded in PowerShell.
// It works without admin for your own processes.
const U = require('./util');
const mac = require('./mac');

const HELPER = `
if (-not ('AgathosNt' -as [type])) {
Add-Type -TypeDefinition @"
using System; using System.Runtime.InteropServices;
public static class AgathosNt {
  [DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
  [DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern IntPtr OpenProcess(uint a, bool i, int pid);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Suspend(int pid) { IntPtr h = OpenProcess(0x0800, false, pid); if (h == IntPtr.Zero) return -1; int r = NtSuspendProcess(h); CloseHandle(h); return r; }
  public static int Resume(int pid) { IntPtr h = OpenProcess(0x0800, false, pid); if (h == IntPtr.Zero) return -1; int r = NtResumeProcess(h); CloseHandle(h); return r; }
}
"@
}`;

// Processes we must never freeze or kill: Windows itself, the shell, AgathOS.
const PROTECTED = /^(system|smss|csrss|wininit|winlogon|services|lsass|svchost|explorer|dwm|fontdrvhost|sihost|ctfmon|runtimebroker|msmpeng|securityhealthservice|agathos|electron)\.exe$/i;

async function suspend(pids, names = {}) {
  if (U.IS_MAC) return mac.suspend(pids, names);
  const list = pids.filter((p) => p > 4 && !PROTECTED.test(names[p] || ''));
  if (!list.length || !U.IS_WIN) return { ok: false, done: [] };
  // Parent first, so it cannot start new children while we work down the tree.
  const out = await U.ps.run(`${HELPER}\n@(${list.join(',')}) | ForEach-Object { "$_=" + [AgathosNt]::Suspend($_) }`, 20000);
  const done = parseResults(out);
  return { ok: done.length > 0, done };
}

async function resume(pids) {
  if (U.IS_MAC) return mac.resume(pids);
  if (!pids.length || !U.IS_WIN) return { ok: false, done: [] };
  const out = await U.ps.run(`${HELPER}\n@(${[...pids].reverse().join(',')}) | ForEach-Object { "$_=" + [AgathosNt]::Resume($_) }`, 20000);
  const done = parseResults(out);
  return { ok: done.length > 0, done };
}

async function kill(rootPid, name, tree = []) {
  if (U.IS_MAC) return mac.kill(rootPid, name, tree);
  if (!U.IS_WIN || rootPid <= 4 || PROTECTED.test(name || '')) return { ok: false };
  const out = await U.execFileText('taskkill.exe', ['/PID', String(rootPid), '/T', '/F'], 15000);
  return { ok: out != null };
}

function parseResults(out) {
  return String(out || '').split(/\r?\n/).map((l) => l.match(/^(\d+)=(-?\d+)/)).filter((m) => m && m[2] === '0').map((m) => +m[1]);
}

module.exports = { suspend, resume, kill, PROTECTED };
