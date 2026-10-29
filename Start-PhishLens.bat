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
echo Install it from https://www.python.org/downloads/
echo and tick "Add Python to PATH" on the first screen. Then run this file again.
:done
echo.
pause
