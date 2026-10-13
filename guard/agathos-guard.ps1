<#
  AgathOS Guard - the optional admin helper of AgathOS.

  What it does (only on this PC, nothing goes online):
   * deep Windows logging: every new process with its full command line (Security 4688 or Sysmon 1),
     DNS lookups per process (DNS-Client 3008 or Sysmon 22), network connections (Sysmon 3),
     file deletes (Sysmon 23/26) and firewall rule changes made by other programs
   * live firewall: block one program from the internet, make an AI server local-only,
     "AI lockdown" for several programs at once
   * freeze, resume or stop processes that run with admin rights

  It runs as SYSTEM through the scheduled task "AgathOS Guard" and only listens on
  127.0.0.1. Every request needs the token in token.txt (readable by admins and by
  the user who installed it). The script lives in an admin-only folder, so a normal
  program cannot change what runs with admin rights.
#>
param([int]$Port = 47613)

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
$Dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$Token = (Get-Content -LiteralPath (Join-Path $Dir 'token.txt') -Raw).Trim()
$Version = '0.2.0'
if (-not $Token) { exit 1 }

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
}

# ---------------- event sources ----------------
$Sysmon = [bool](Get-WinEvent -ListLog 'Microsoft-Windows-Sysmon/Operational' -ErrorAction SilentlyContinue)
$FwLog = 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall'
$Sources = @()
if ($Sysmon) {
  $Sources += @{ log = 'Microsoft-Windows-Sysmon/Operational'; ids = @(1, 3, 22, 23, 26) }
} else {
  $Sources += @{ log = 'Security'; ids = @(4688) }
  $Sources += @{ log = 'Microsoft-Windows-DNS-Client/Operational'; ids = @(3008) }
}
$Sources += @{ log = $FwLog; ids = @(2004, 2005, 2006, 2052, 2097, 2099) }

$Last = @{}
foreach ($s in $Sources) {
  $e = Get-WinEvent -LogName $s.log -MaxEvents 1 -ErrorAction SilentlyContinue
  $Last[$s.log] = if ($e) { [int64]$e.RecordId } else { 0 }
}

$Events = New-Object System.Collections.Generic.List[object]
$Seq = 0
$Started = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()

function Add-Ev($obj) {
  $script:Seq++
  $obj | Add-Member -NotePropertyName seq -NotePropertyValue $script:Seq -Force
  $script:Events.Add($obj)
  if ($script:Events.Count -gt 4000) { $script:Events.RemoveRange(0, $script:Events.Count - 4000) }
}

function Hex($v) { if ($v -match '^0x') { [Convert]::ToInt32($v, 16) } else { [int]$v } }

function Poll-Events {
  foreach ($s in $Sources) {
    $ids = ($s.ids | ForEach-Object { "EventID=$_" }) -join ' or '
    $xp = "*[System[($ids) and (EventRecordID>$($Last[$s.log]))]]"
    $list = @(Get-WinEvent -LogName $s.log -FilterXPath $xp -MaxEvents 800 -ErrorAction SilentlyContinue | Sort-Object RecordId)
    foreach ($e in $list) {
      $Last[$s.log] = [int64]$e.RecordId
      $x = [xml]$e.ToXml()
      $d = @{}
      foreach ($n in $x.Event.EventData.Data) { $d[$n.Name] = $n.'#text' }
      $ts = [DateTimeOffset]::new($e.TimeCreated).ToUnixTimeMilliseconds()
      $epid = [int]$x.Event.System.Execution.ProcessID
      switch ($e.Id) {
        4688 { Add-Ev ([pscustomobject]@{ type='proc'; ts=$ts; pid=(Hex $d.NewProcessId); ppid=(Hex $d.ProcessId); image=$d.NewProcessName; cmd=$d.CommandLine; parentImage=$d.ParentProcessName; user=$d.SubjectUserName }) }
        3008 { if ($d.QueryStatus -eq '0' -and $d.QueryName) { Add-Ev ([pscustomobject]@{ type='dns'; ts=$ts; pid=$epid; name=$d.QueryName; result=$d.QueryResults }) } }
        1    { Add-Ev ([pscustomobject]@{ type='proc'; ts=$ts; pid=[int]$d.ProcessId; ppid=[int]$d.ParentProcessId; image=$d.Image; cmd=$d.CommandLine; parentImage=$d.ParentImage; user=$d.User }) }
        3    { Add-Ev ([pscustomobject]@{ type='net'; ts=$ts; pid=[int]$d.ProcessId; image=$d.Image; ip=$d.DestinationIp; host=$d.DestinationHostname; port=[int]$d.DestinationPort }) }
        22   { Add-Ev ([pscustomobject]@{ type='dns'; ts=$ts; pid=[int]$d.ProcessId; image=$d.Image; name=$d.QueryName; result=$d.QueryResults }) }
        { $_ -in 23, 26 } { Add-Ev ([pscustomobject]@{ type='del'; ts=$ts; pid=[int]$d.ProcessId; image=$d.Image; file=$d.TargetFilename }) }
        { $_ -in 2004, 2097 } { if ($d.RuleName -notlike 'AgathOS*') { Add-Ev ([pscustomobject]@{ type='fw'; ts=$ts; op='added'; rule=$d.RuleName; app=$d.ApplicationPath; by=$d.ModifyingApplication; dir=$d.Direction; action=$d.Action }) } }
        { $_ -in 2005, 2099 } { if ($d.RuleName -notlike 'AgathOS*') { Add-Ev ([pscustomobject]@{ type='fw'; ts=$ts; op='changed'; rule=$d.RuleName; app=$d.ApplicationPath; by=$d.ModifyingApplication }) } }
        { $_ -in 2006, 2052 } { if ($d.RuleName -notlike 'AgathOS*') { Add-Ev ([pscustomobject]@{ type='fw'; ts=$ts; op='deleted'; rule=$d.RuleName; by=$d.ModifyingApplication }) } }
      }
    }
  }
}

# ---------------- actions ----------------
function Safe-Name($s) { ($s -replace '[^\w .\-()]', '').Substring(0, [Math]::Min(60, ($s -replace '[^\w .\-()]', '').Length)) }

function Fw-Block($program, $tag) {
  if (-not ($program -match '\.exe$') -or -not (Test-Path -LiteralPath $program -PathType Leaf)) { return @{ ok = $false; error = 'program' } }
  $name = "AgathOS $tag " + (Safe-Name ([IO.Path]::GetFileName($program)))
  if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $name -Group 'AgathOS' -Direction Outbound -Program $program -Action Block -Profile Any | Out-Null
  }
  @{ ok = $true; rule = $name }
}

function Fw-Unblock($program, $tag) {
  $rules = Get-NetFirewallRule -Group 'AgathOS' -ErrorAction SilentlyContinue
  if ($program) { $rules = $rules | Where-Object { $_.DisplayName -eq ("AgathOS $tag " + (Safe-Name ([IO.Path]::GetFileName($program)))) } }
  elseif ($tag) { $rules = $rules | Where-Object { $_.DisplayName -like "AgathOS $tag *" } }
  $n = @($rules).Count
  $rules | Remove-NetFirewallRule
  @{ ok = $true; removed = $n }
}

function Fw-LocalOnly($port, $on) {
  $p = [int]$port
  if ($p -lt 1 -or $p -gt 65535) { return @{ ok = $false; error = 'port' } }
  $name = "AgathOS local-only $p"
  if ($on) {
    # Windows Firewall does not filter loopback, so this blocks the network but keeps 127.0.0.1 working.
    if (-not (Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue)) {
      New-NetFirewallRule -DisplayName $name -Group 'AgathOS' -Direction Inbound -Protocol TCP -LocalPort $p -Action Block -Profile Any | Out-Null
    }
  } else { Get-NetFirewallRule -DisplayName $name -ErrorAction SilentlyContinue | Remove-NetFirewallRule }
  @{ ok = $true; rule = $name }
}

function Fw-List {
  @(Get-NetFirewallRule -Group 'AgathOS' -ErrorAction SilentlyContinue | ForEach-Object {
    $app = ($_ | Get-NetFirewallApplicationFilter).Program
    $port = ($_ | Get-NetFirewallPortFilter).LocalPort
    [pscustomobject]@{ name = $_.DisplayName; dir = "$($_.Direction)"; enabled = "$($_.Enabled)"; program = $app; port = "$port" } })
}

function Conns {
  $names = @{}
  Get-Process | ForEach-Object { $names[$_.Id] = $_.ProcessName }
  @(Get-NetTCPConnection -ErrorAction SilentlyContinue | Where-Object { $_.State -in 'Listen', 'Established' } | ForEach-Object {
    [pscustomobject]@{ la = $_.LocalAddress; lp = $_.LocalPort; ra = $_.RemoteAddress; rp = $_.RemotePort; s = "$($_.State)"; p = $_.OwningProcess; n = $names[[int]$_.OwningProcess] } })
}

$Protected = '^(System|smss|csrss|wininit|winlogon|services|lsass|svchost|explorer|dwm|MsMpEng|SecurityHealthService)$'
function Proc-Op($op, $pids) {
  $done = @()
  foreach ($p in $pids) {
    $p = [int]$p
    if ($p -le 4 -or $p -eq $PID) { continue }
    $pr = Get-Process -Id $p -ErrorAction SilentlyContinue
    if (-not $pr -or $pr.ProcessName -match $Protected) { continue }
    switch ($op) {
      'suspend' { if ([AgathosNt]::Suspend($p) -eq 0) { $done += $p } }
      'resume'  { if ([AgathosNt]::Resume($p) -eq 0) { $done += $p } }
      'kill'    { & taskkill.exe /PID $p /T /F | Out-Null; $done += $p }
    }
  }
  @{ ok = $done.Count -gt 0; done = $done }
}

# ---------------- HTTP on 127.0.0.1 ----------------
function Reply($ctx, $obj, $code = 200) {
  $json = $obj | ConvertTo-Json -Depth 5 -Compress
  if ($null -eq $json) { $json = '[]' }
  $buf = [Text.Encoding]::UTF8.GetBytes($json)
  $ctx.Response.StatusCode = $code
  $ctx.Response.ContentType = 'application/json'
  $ctx.Response.OutputStream.Write($buf, 0, $buf.Length)
  $ctx.Response.Close()
}

function Handle($ctx) {
  $req = $ctx.Request
  if ($req.Headers['X-AgathOS-Token'] -ne $Token -or $req.RemoteEndPoint.Address.ToString() -notmatch '^(127\.0\.0\.1|::1)$') { Reply $ctx @{ error = 'denied' } 403; return }
  $body = @{}
  if ($req.HasEntityBody) {
    $r = New-Object IO.StreamReader($req.InputStream, [Text.Encoding]::UTF8)
    $raw = $r.ReadToEnd()
    if ($raw.Length -lt 65536) { try { $body = $raw | ConvertFrom-Json } catch {} }
  }
  $path = $req.Url.AbsolutePath
  switch ($path) {
    '/status' { Reply $ctx @{ ok = $true; version = $Version; sysmon = $Sysmon; started = $Started; seq = $Seq; elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) }; return }
    '/events' {
      $since = [int64]($req.QueryString['since'])
      Reply $ctx @($Events | Where-Object { $_.seq -gt $since } | Select-Object -Last 1500); return }
    '/connections' { Reply $ctx (Conns); return }
    '/firewall/list' { Reply $ctx (Fw-List); return }
    '/firewall/block' { Reply $ctx (Fw-Block $body.program ($(if ($body.tag) { Safe-Name $body.tag } else { 'block' }))); return }
    '/firewall/unblock' { Reply $ctx (Fw-Unblock $body.program ($(if ($body.tag) { Safe-Name $body.tag } else { 'block' }))); return }
    '/firewall/localonly' { Reply $ctx (Fw-LocalOnly $body.port ([bool]$body.on)); return }
    '/proc/suspend' { Reply $ctx (Proc-Op 'suspend' @($body.pids)); return }
    '/proc/resume' { Reply $ctx (Proc-Op 'resume' @($body.pids)); return }
    '/proc/kill' { Reply $ctx (Proc-Op 'kill' @($body.pids)); return }
    default { Reply $ctx @{ error = 'unknown' } 404 }
  }
}

$listener = New-Object Net.HttpListener
$listener.Prefixes.Add("http://127.0.0.1:$Port/")
try { $listener.Start() } catch { exit 2 }

$lastPoll = [DateTime]::MinValue
while ($listener.IsListening) {
  $task = $listener.GetContextAsync()
  while (-not $task.AsyncWaitHandle.WaitOne(500)) {
    if (([DateTime]::UtcNow - $lastPoll).TotalSeconds -ge 2) { Poll-Events; $lastPoll = [DateTime]::UtcNow }
  }
  try { Handle $task.Result } catch { try { Reply $task.Result @{ error = 'failed' } 500 } catch {} }
}
