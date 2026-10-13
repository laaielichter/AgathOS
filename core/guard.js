'use strict';
// AgathOS - talks to AgathOS Guard (the optional admin helper) and installs/removes it.
// Installing needs one UAC prompt. The Guard script is copied to an admin-only folder
// in ProgramData and runs as SYSTEM through a scheduled task, so normal programs
// cannot change what runs with admin rights.
const fs = require('fs');
const path = require('path');
const http = require('http');
const U = require('./util');

const PORT = 47613;
const DIR = path.join(process.env.ProgramData || 'C:\\ProgramData', 'AgathOS', 'Guard');
const TOKEN_FILE = path.join(DIR, 'token.txt');

function token() {
  try { return fs.readFileSync(TOKEN_FILE, 'utf8').trim(); } catch (_) { return null; }
}

function call(method, p, body, timeout = 8000) {
  const t = token();
  if (!t) return Promise.resolve(null);
  const data = body ? JSON.stringify(body) : null;
  return new Promise((resolve) => {
    const req = http.request({ host: '127.0.0.1', port: PORT, path: p, method, timeout,
      headers: { 'X-AgathOS-Token': t, ...(data ? { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) } : {}) } }, (res) => {
      let d = '';
      res.setEncoding('utf8');
      res.on('data', (x) => { d += x; if (d.length > 20 * 1024 * 1024) req.destroy(); });
      res.on('end', () => { if (res.statusCode !== 200) return resolve(null); try { resolve(JSON.parse(d)); } catch (_) { resolve(null); } });
    });
    req.on('error', () => resolve(null));
    req.on('timeout', () => { req.destroy(); resolve(null); });
    req.end(data || undefined);
  });
}

const status = () => call('GET', '/status', null, 3000);
const events = (since) => call('GET', `/events?since=${since | 0}`, null, 8000).then((r) => (Array.isArray(r) ? r : r ? [r] : []));
const connections = () => call('GET', '/connections', null, 10000).then((r) => (Array.isArray(r) ? r : []));
const fwList = () => call('GET', '/firewall/list').then((r) => (Array.isArray(r) ? r : r ? [r] : []));
const fwBlock = (program, tag = 'block') => call('POST', '/firewall/block', { program, tag });
const fwUnblock = (program, tag = 'block') => call('POST', '/firewall/unblock', { program, tag });
const fwLocalOnly = (port, on) => call('POST', '/firewall/localonly', { port, on });
const procOp = (op, pids) => call('POST', `/proc/${op}`, { pids });

// ---------- install / uninstall (one UAC prompt each) ----------
function installScript(src, userSid) {
  return `
$ErrorActionPreference = 'Stop'
$dst = Join-Path $env:ProgramData 'AgathOS\\Guard'
New-Item -ItemType Directory -Force -Path $dst | Out-Null
# Lock the folder first (admins + SYSTEM write, the user may only read), then copy into it.
& icacls.exe $dst /reset /T /Q | Out-Null
& icacls.exe $dst /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' ${U.psq('*' + userSid + ':(OI)(CI)RX')} /Q | Out-Null
Copy-Item -LiteralPath ${U.psq(src)} -Destination (Join-Path $dst 'agathos-guard.ps1') -Force
$tok = ([Guid]::NewGuid().ToString('N') + [Guid]::NewGuid().ToString('N'))
Set-Content -LiteralPath (Join-Path $dst 'token.txt') -Value $tok -NoNewline -Encoding ASCII
# Remember the old logging settings so uninstall can put them back.
$state = @{}
$state.cmdline = (Get-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -ErrorAction SilentlyContinue).ProcessCreationIncludeCmdLine_Enabled
$state.audit = (& auditpol.exe /get /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /r | Select-Object -Last 1)
$state.dns = (Get-WinEvent -ListLog 'Microsoft-Windows-DNS-Client/Operational' -ErrorAction SilentlyContinue).IsEnabled
$state.secsize = (Get-WinEvent -ListLog 'Security').MaximumSizeInBytes
$state | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $dst 'previous-settings.json')
# Deep logging: process creation with full command line, DNS lookups per process.
& auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:enable | Out-Null
New-Item -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Force | Out-Null
Set-ItemProperty -Path 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value 1 -Type DWord
& wevtutil.exe sl 'Microsoft-Windows-DNS-Client/Operational' /e:true | Out-Null
if ($state.secsize -lt 67108864) { & wevtutil.exe sl Security /ms:67108864 | Out-Null }
$ps = Join-Path $env:SystemRoot 'System32\\WindowsPowerShell\\v1.0\\powershell.exe'
$a = New-ScheduledTaskAction -Execute $ps -Argument ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -WindowStyle Hidden -File "' + (Join-Path $dst 'agathos-guard.ps1') + '"')
$t = New-ScheduledTaskTrigger -AtStartup
$p = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$s = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -StartWhenAvailable
Register-ScheduledTask -TaskName 'AgathOS Guard' -Action $a -Trigger $t -Principal $p -Settings $s -Force | Out-Null
Start-ScheduledTask -TaskName 'AgathOS Guard'
`;
}

const UNINSTALL = `
$ErrorActionPreference = 'SilentlyContinue'
$dst = Join-Path $env:ProgramData 'AgathOS\\Guard'
Stop-ScheduledTask -TaskName 'AgathOS Guard'
Unregister-ScheduledTask -TaskName 'AgathOS Guard' -Confirm:$false
Get-CimInstance Win32_Process -Filter "Name='powershell.exe'" | Where-Object { $_.CommandLine -like '*agathos-guard.ps1*' } | Invoke-CimMethod -MethodName Terminate | Out-Null
Get-NetFirewallRule -Group 'AgathOS' | Remove-NetFirewallRule
$prev = Get-Content -LiteralPath (Join-Path $dst 'previous-settings.json') -Raw | ConvertFrom-Json
if ($prev) {
  if ($null -eq $prev.cmdline) { Remove-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled }
  else { Set-ItemProperty 'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit' -Name ProcessCreationIncludeCmdLine_Enabled -Value $prev.cmdline -Type DWord }
  if ($prev.audit -and $prev.audit -notmatch 'Success') { & auditpol.exe /set /subcategory:'{0CCE922B-69AE-11D9-BED3-505054503030}' /success:disable | Out-Null }
  if ($prev.dns -eq $false) { & wevtutil.exe sl 'Microsoft-Windows-DNS-Client/Operational' /e:false | Out-Null }
}
Remove-Item -LiteralPath $dst -Recurse -Force
`;

function runElevated(script) {
  if (!U.IS_WIN) return Promise.resolve(false);
  const enc = Buffer.from(script, 'utf16le').toString('base64');
  // Start-Process -Verb RunAs shows the UAC prompt; -Wait so we know when it is done.
  const outer = `try { $p = Start-Process -FilePath powershell.exe -Verb RunAs -WindowStyle Hidden -Wait -PassThru -ArgumentList '-NoProfile','-ExecutionPolicy','Bypass','-EncodedCommand','${enc}'; Write-Output ("exit=" + $p.ExitCode) } catch { Write-Output 'cancelled' }`;
  // A separate PowerShell, so the shared one keeps polling while the UAC prompt waits.
  return U.execFileText('powershell.exe', ['-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-Command', outer], 300000)
    .then((out) => /exit=0/.test(out || ''));
}

async function install(appDir) {
  const src = path.join(appDir, 'guard', 'agathos-guard.ps1');
  const sid = ((await U.ps.run('[Security.Principal.WindowsIdentity]::GetCurrent().User.Value', 5000)) || '').trim();
  if (!/^S-1-5-[\d-]+$/.test(sid)) return false;
  const ok = await runElevated(installScript(src, sid));
  if (!ok) return false;
  for (let i = 0; i < 20; i++) { if (await status()) return true; await new Promise((r) => setTimeout(r, 1000)); }
  return false;
}

const uninstall = () => runElevated(UNINSTALL);
const installed = () => U.exists(TOKEN_FILE);

module.exports = { status, events, connections, fwList, fwBlock, fwUnblock, fwLocalOnly, procOp, install, uninstall, installed, PORT };
