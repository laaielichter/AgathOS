@echo off
title AgathOS
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 (
  echo.
  echo  Node.js was not found.
  echo  Install it first from https://nodejs.org  ^(choose LTS^)
  echo  Then run this file again.
  echo.
  pause
  exit /b 1
)

if not exist "node_modules\electron" (
  echo.
  echo  First start: AgathOS is being set up.
  echo  This takes a few minutes and prints a lot of text. That is normal.
  echo.
  call npm install
  if errorlevel 1 (
    echo.
    echo  Setup failed. Copy the red text above and open an issue on GitHub.
    pause
    exit /b 1
  )
)

call npm start
