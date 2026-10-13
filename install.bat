@echo off
rem AgathOS - quick install without building: copies AgathOS to your user folder,
rem installs Electron and adds AgathOS to the desktop and the Start menu.
rem No admin rights needed. Needs Node.js (https://nodejs.org).
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
if errorlevel 1 pause
