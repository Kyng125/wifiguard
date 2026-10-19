#!/usr/bin/env bash
# WiFiGuard: one-command start on macOS and Linux.  ./start.sh
# First run creates a private Python environment here (needs internet once), then starts the dashboard demo.
set -e
cd "$(dirname "$0")"
PY=$(command -v python3 || command -v python || true)
[ -n "$PY" ] || { echo "Python 3.10 or newer is required but was not found."; exit 1; }
[ -x .venv/bin/python ] || { echo "Creating the Python environment (first run only)..."; "$PY" -m venv .venv; }
.venv/bin/python -m pip install --quiet --disable-pip-version-check -r requirements.txt
echo
echo "Starting WiFiGuard. Open http://127.0.0.1:5000 in your browser."
exec .venv/bin/python run.py --demo "$@"
