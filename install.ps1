# AgathOS - per-user install from this folder. No admin rights needed.
#  1. copies the app to %LOCALAPPDATA%\Programs\AgathOS
#  2. installs Electron there (npm install)
#  3. adds shortcuts with the AgathOS icon to the desktop and the Start menu
#  4. registers an uninstaller in Settings > Apps
#  5. starts AgathOS (the welcome screen asks for your language and options)
$ErrorActionPreference = 'Stop'
$src = $PSScriptRoot
$dst = Join-Path $env:LOCALAPPDATA 'Programs\AgathOS'

function Say($t) { Write-Host "  $t" }
Write-Host ''
Write-Host '  AgathOS - install' -ForegroundColor Yellow
Write-Host ''

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
  Say 'Node.js is needed first: https://nodejs.org (LTS). Install it, then run install.bat again.'
  exit 1
}

# A running AgathOS from an earlier install would lock its files.
Get-CimInstance Win32_Process -Filter "Name='electron.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath -like "$dst\*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }

Say "Copying to $dst ..."
New-Item -ItemType Directory -Force -Path $dst | Out-Null
$items = 'main.js', 'preload.js', 'package.json', 'LICENSE', 'README.md', 'uninstall.ps1', 'core', 'guard', 'src'
foreach ($i in $items) {
  $p = Join-Path $src $i
  if (Test-Path $p) { Copy-Item -LiteralPath $p -Destination $dst -Recurse -Force }
}

Say 'Installing Electron (one time, about 100 MB)...'
Push-Location $dst
try { & npm install --no-audit --no-fund --loglevel=error; if ($LASTEXITCODE -ne 0) { throw 'npm install failed' } }
finally { Pop-Location }

$exe = Join-Path $dst 'node_modules\electron\dist\electron.exe'
$ico = Join-Path $dst 'src\icon.ico'
if (-not (Test-Path $exe)) { Say 'Electron was not installed. Check your internet connection and try again.'; exit 1 }

Say 'Adding shortcuts...'
$shell = New-Object -ComObject WScript.Shell
$startMenu = Join-Path ([Environment]::GetFolderPath('Programs')) 'AgathOS.lnk'
$desktop = Join-Path ([Environment]::GetFolderPath('Desktop')) 'AgathOS.lnk'
foreach ($lnk in $desktop, $startMenu) {
  $s = $shell.CreateShortcut($lnk)
  $s.TargetPath = $exe
  $s.Arguments = '"' + $dst + '"'
  $s.WorkingDirectory = $dst
  $s.IconLocation = "$ico,0"
  $s.Description = 'AgathOS - the good daemon for your local AI agents'
  $s.Save()
}

Say 'Registering the uninstaller...'
$version = (Get-Content (Join-Path $dst 'package.json') -Raw | ConvertFrom-Json).version
$key = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AgathOS'
New-Item -Path $key -Force | Out-Null
$un = 'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "' + (Join-Path $dst 'uninstall.ps1') + '"'
Set-ItemProperty -Path $key -Name DisplayName -Value 'AgathOS'
Set-ItemProperty -Path $key -Name DisplayVersion -Value $version
Set-ItemProperty -Path $key -Name Publisher -Value 'AgathOS contributors'
Set-ItemProperty -Path $key -Name DisplayIcon -Value $ico
Set-ItemProperty -Path $key -Name InstallLocation -Value $dst
Set-ItemProperty -Path $key -Name UninstallString -Value $un
Set-ItemProperty -Path $key -Name NoModify -Value 1 -Type DWord
Set-ItemProperty -Path $key -Name NoRepair -Value 1 -Type DWord

Write-Host ''
Say 'Done. AgathOS is on your desktop and in the Start menu. Starting it now...'
Start-Process -FilePath $exe -ArgumentList ('"' + $dst + '"') -WorkingDirectory $dst
