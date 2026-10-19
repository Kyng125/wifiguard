@echo off
REM WiFiGuard: one-click start on Windows. Double-click this file.
REM First run creates a private Python environment here (needs internet once), then starts the dashboard demo.
setlocal
cd /d "%~dp0"

set "PY="
where py >nul 2>nul && set "PY=py -3"
if not defined PY where python >nul 2>nul && set "PY=python"
if not defined PY (
  echo Python 3.10 or newer is required but was not found.
  echo Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH", then run this again.
  pause
  exit /b 1
)

if not exist ".venv\Scripts\python.exe" (
  echo Creating the Python environment ^(first run only^)...
  %PY% -m venv .venv
  if errorlevel 1 (
    echo Could not create the environment. Check that Python 3.10 or newer is installed.
    pause
    exit /b 1
  )
)

".venv\Scripts\python.exe" -m pip install --quiet --disable-pip-version-check -r requirements.txt
if errorlevel 1 (
  echo Installing the requirements failed. The first run needs an internet connection.
  pause
  exit /b 1
)

echo.
echo Starting WiFiGuard. Open http://127.0.0.1:5000 in your browser.
echo.
".venv\Scripts\python.exe" run.py --demo %*
echo.
echo WiFiGuard has stopped.
pause
