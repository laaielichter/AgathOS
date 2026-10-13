@echo off
rem AgathOS - builds the Windows installer (dist\AgathOS-Setup-<version>.exe).
rem Needs Node.js (https://nodejs.org). The first build downloads the build tools.
cd /d "%~dp0"
where node >nul 2>nul
if errorlevel 1 (
  echo Node.js is needed first: https://nodejs.org
  pause
  exit /b 1
)
if not exist node_modules\electron (
  echo Installing Electron...
  call npm install
  if errorlevel 1 goto fail
)
echo Building the installer, this takes a few minutes...
call npx --yes electron-builder@26 --win nsis --x64
if errorlevel 1 goto fail
echo.
echo Done. The installer is in the "dist" folder.
start "" "%~dp0dist"
pause
exit /b 0
:fail
echo.
echo Building failed. The messages above say why.
pause
exit /b 1
