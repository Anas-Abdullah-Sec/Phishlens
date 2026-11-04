@echo off
title PhishLens
cd /d "%~dp0"
if not exist "%~dp0python\python.exe" (
  echo.
  echo Please extract the whole zip first: right-click it, choose Extract All,
  echo then open PhishLens.bat from the extracted folder.
  echo.
  pause
  exit /b 1
)
"%~dp0python\python.exe" -m phishlens gui
echo.
echo PhishLens has stopped. You can close this window.
pause >nul
