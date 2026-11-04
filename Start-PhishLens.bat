@echo off
title PhishLens
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel%==0 (
  py -m phishlens gui
  goto :done
)
where python >nul 2>nul
if %errorlevel%==0 (
  python -m phishlens gui
  goto :done
)
echo.
echo PhishLens needs Python 3.9 or newer.
echo Opening the download page. Tick "Add Python to PATH" on the first screen,
echo install it, then run this file again.
start "" https://www.python.org/downloads/
:done
echo.
pause
