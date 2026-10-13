# AgathOS - removes the per-user install made by install.ps1.
# Your AgathOS log and settings in %APPDATA%\AgathOS stay, unless you delete that folder yourself.
# AgathOS Guard (if you installed it) is removed from inside the app: Network > AgathOS Guard > Remove.
$dst = Join-Path $env:LOCALAPPDATA 'Programs\AgathOS'
Set-Location $env:TEMP
Get-CimInstance Win32_Process -Filter "Name='electron.exe'" -ErrorAction SilentlyContinue |
  Where-Object { $_.ExecutablePath -like "$dst\*" } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue }
Start-Sleep -Milliseconds 800
foreach ($lnk in (Join-Path ([Environment]::GetFolderPath('Desktop')) 'AgathOS.lnk'), (Join-Path ([Environment]::GetFolderPath('Programs')) 'AgathOS.lnk')) {
  Remove-Item -LiteralPath $lnk -Force -ErrorAction SilentlyContinue
}
Remove-ItemProperty -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name 'electron.app.AgathOS' -ErrorAction SilentlyContinue
Remove-Item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\AgathOS' -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -LiteralPath $dst -Recurse -Force -ErrorAction SilentlyContinue
if (Get-ScheduledTask -TaskName 'AgathOS Guard' -ErrorAction SilentlyContinue) {
  Write-Host 'AgathOS Guard is still installed. To remove it, run as admin: schtasks /Delete /TN "AgathOS Guard" /F'
}
Write-Host 'AgathOS is removed.'
