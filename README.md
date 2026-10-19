# WiFiGuard backend

Flask JSON API over SQLite for the Wi-Fi Security Enhancement System (wireless intrusion detection and
monitoring). Phases 1 and 2 are complete (database, event manager, authentication, the JSON API, the packet processor and
the four detection rules). Phase 3 is **replay mode**: the engine runs in the background from recorded traffic, so the whole
system works on any laptop with no wireless adapter. Live capture is kept as a backup plan (`docs/live-capture-backup.md`).

**v1.5.1:** text-only fix. The descriptions of the ARP, rogue access point and unrecognised device rules (shown on the Detection Rules page) now describe what the detectors actually do. No behaviour, API shape or database change.

## Quick start

**Windows:** install Python 3.10 or newer from python.org (tick "Add python.exe to PATH"), then double-click `start.bat`.
The first run creates a private environment (internet needed once per laptop), asks you to choose an administrator
username and password, loads the demo data and starts the demo. Open http://127.0.0.1:5000.

**macOS / Linux:** `./start.sh`

Both run `python run.py --demo`: demo data if the database is empty, then normal activity replayed in a loop, so the
dashboard shows a running engine. To move WiFiGuard to another laptop, copy the folder without `.venv` and run `start.bat` there. The data lives in
`instance/`; for a clean move use `flask --app wifiguard backup` on the old laptop and `restore` on the new one (docs/deployment.md).

Without the scripts:

```bash
python -m venv .venv && . .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python run.py --demo                                 # or: python run.py (API and dashboard only)
pip install -r requirements-dev.txt && python -m pytest
```

Other commands (`flask --app wifiguard <command>`; on Windows `python -m flask --app wifiguard <command>`):
`init-db`, `create-admin`, `seed-demo [--reset]`, `purge`, `replay-pcap FILE`, `list-aps`, `authorise-ap`,
`authorise-observed`, `remove-ap`, `engine-status`, for Chapter 4 `evaluate run`, `evaluate sweep`, `evaluate export`, and for
deployment `check-config`, `make-cert`, `backup`, `restore`, `unlock-login`, `rotate-secret-key`.

`seed-demo --reset` replaces existing data (the admin account and settings are kept). Demo data is for
exploring and demonstrating only; do not leave it in a database used for the evaluation.

## Using it

1. **Authorise your access points first.** Until at least one is authorised the unrecognised-device rule is silent and
   lookalike networks look rogue. `list-aps`, then `authorise-ap` or `authorise-observed` (docs/engine.md). The dashboard API
   reports this as a warning. The demo data already has authorised access points.
2. **Run the engine.** `run.py --demo` starts it. Control it through `/api/engine/*` (start, stop, trigger a scenario).
3. **Trigger an attack on cue** (signed-in session, header `X-WifiGuard-Client: 1`): `POST /api/engine/trigger {"scenario": "deauth"}`.
   The other scenarios are `arp_conflict`, `rogue_ap` and `unknown_device`. A UI for this does not exist yet.

## Configuration (environment variables)

| Variable | Default | Purpose |
| --- | --- | --- |
| `WIFIGUARD_DB` | `instance/wifiguard.db` | SQLite file |
| `WIFIGUARD_INSTANCE` | `./instance` | Folder for the database and the generated secret key |
| `WIFIGUARD_SECRET_KEY` / `WIFIGUARD_SECRET_KEY_FILE` | generated, stored in `instance/secret_key` (mode 600) | Signs session cookies; at least 32 characters, refused otherwise. The `_FILE` form reads it from a file |
| `WIFIGUARD_HOST` / `WIFIGUARD_PORT` | `127.0.0.1` / `5000` | Bind address. Keep it on localhost unless you add TLS |
| `WIFIGUARD_TLS_CERT` / `WIFIGUARD_TLS_KEY` | unset | Serve HTTPS directly (or use `run.py --cert --key`); `flask --app wifiguard make-cert` makes a lab certificate |
| `WIFIGUARD_COOKIE_SECURE` | on when TLS is configured, else off | Set `1` behind an HTTPS reverse proxy |
| `WIFIGUARD_TRUST_PROXY` | `0` | Number of reverse proxies whose `X-Forwarded-*` headers to believe |
| `WIFIGUARD_HSTS_SECONDS` | `0` (off) | `Strict-Transport-Security` max-age on HTTPS responses; see docs/deployment.md before enabling |
| `WIFIGUARD_ALLOW_HTTP` | unset | `1` lets `run.py --production` serve plain HTTP on a network address |
| `WIFIGUARD_FRONTEND_DIST` | `./frontend/dist` | Built React app, served with single-page-app fallback |
| `WIFIGUARD_REPLAY_DIR` | `./samples/pcaps` | Recorded scenarios the engine replays; drop your own `.pcap` files here |
| `WIFIGUARD_ADMIN_USER` / `WIFIGUARD_ADMIN_PASSWORD` | unset | Create the administrator without a prompt on first `run.py --demo` |
| `WIFIGUARD_CSP` | self + Google Fonts | Content-Security-Policy header |

## Layout

```
wifiguard/
  __init__.py       app factory, security headers, serves the built frontend
  schema.sql        14 tables (7 from the report, 7 added); see the comments in the file
  defaults.py       default settings and the four rule definitions
  security.py       password hashing, login lockout (stored in the database), CSRF header check, session guard
  config.py         environment settings, secret key handling, TLS and proxy checks, deployment warnings
  maintenance.py    backup, restore, server pid file;  tlscert.py  self-signed lab certificate
  services/         events (alert manager), inventory (derived status), monitor, reports, settings, oui
  api/              one module per area; every route is under /api
  seed_demo.py      demo dataset matching the frontend sample data
  engine/           packet processor, four detection rules, pipeline, synthetic frames (Phase 2);
                    sources (paced replay) and runtime (background engine thread) (Phase 3)
  evaluation/       Chapter 4 tooling: varied traffic, trial harness, CSV and methodology export (Phase 4)
  cli.py            init-db, create-admin, seed-demo, purge, replay-pcap, list-aps, authorise-ap, evaluate,
                    backup, restore, make-cert, check-config, unlock-login, rotate-secret-key, ...
run.py              starts everything; --demo for the one-command demo
start.bat / start.sh   one-command start with a private Python environment
frontend/dist/      built dashboard (Prompts 1 and 1b), served by Flask; see frontend/README.md
tools/              make_sample_pcaps.py
samples/pcaps/      fabricated frames for the five scenarios
tests/              225 tests (pytest; need scapy)
docs/api.md         endpoint contract and notes for the frontend
docs/engine.md      how the engine works, replay mode, authorising access points, decisions to review
docs/evaluation.md   running the five-scenario evaluation, reading the results, the live lab recording protocol
docs/deployment.md   TLS, secret key, lockout, backup/restore/upgrade, production server, Windows checklist
docs/live-capture-backup.md   the original live-capture plan, not built
```

## Design decisions

- **Single process.** Matches Chapter 3. The engine thread lives in the web server process: bind to localhost, keep the
  reloader off, run one worker. (If live capture is added, a privileged capture process separate from the web process is
  the stronger design and is a candidate for Chapter 5.)
- **SQLite in WAL mode** so the capture side can write while Flask reads. All timestamps are UTC ISO-8601 text;
  the UI converts to the configured time zone.
- **Derived, not stored:** device status, Offline, vendor, IP (from ARP), AP status and the rogue-AP reason. This
  keeps the schema shallow (Section 3.9) and means status is always consistent with the inventories.
- **Detection never writes to the database directly.** It will hand matches to `services/events.create_event`,
  which applies severity, merges repeats inside the cool-down and writes the timeline (Section 3.6.4).
- **Authentication:** one administrator, scrypt password hashes, HttpOnly SameSite=Lax session cookie, sliding
  session timeout, login lockout after 5 failures, and a required `X-WifiGuard-Client: 1` header on every
  non-GET request as CSRF protection (CORS is deliberately not enabled).
- **No payloads, ever.** The schema has no place to store packet contents.

## Detection engine

`wifiguard/engine/` holds the packet processor, the four rules and replay mode. One-off check without the server:
`python tools/make_sample_pcaps.py`, then `flask --app wifiguard replay-pcap samples/pcaps/deauth.pcap`. Details, replay
behaviour and the decisions to review are in `docs/engine.md`.

**Replay is not live capture.** Frames are fabricated or recorded earlier, so replay shows the rules work on known input and
makes demos repeatable; it does not show that capture works on real hardware or keeps up with a busy network. Say so in the report.

## Frontend pairing

The frontend's `src/api/types.ts` is the contract; `tests/test_contract.py` guards it. The built Dashboard ships in `frontend/dist/` and is served at `/`. For development run the UI with `VITE_USE_MOCK=false` (dev proxy). Fields added after contract v1 are listed in `docs/api.md`; the Dashboard does not show the new warnings yet.

## Known limits

- Only tested on Linux (Python 3.13). Windows is expected to work (nothing here is Linux specific) but has not been run:
  see the Windows checklist below. Scapy may print a warning about Npcap/libpcap on Windows; replay does not need it.
- A fresh laptop needs internet once to install the three requirements (Flask, psutil, scapy).
- The login lockout covers sign-in only (5 failures per address and name, 20 per address, 5 minutes). There is one administrator, no multi-factor sign-in, and no audit log.
- Everything in docs/deployment.md has been run on Linux only; the Windows checklist there has not been run.
- Device and AP lists are built in Python and paginated afterwards: fine for a small institution, not for thousands of devices.
- `ownerLabel` exists only for authorised devices (the report's `authorised_devices` table).
- Vendor lookup uses Scapy's OUI database when Scapy is installed, otherwise it is blank.
- The built-in Flask server is for a single administrator in a lab, as Section 3.6.6 states.

## Roadmap

1. Phase 1 (done): schema, event manager, auth, API, seed, tests.
2. Phase 2 (done): packet processor and the four detection rules, tested with synthetic frames and pcaps (see `docs/engine.md`).
3. Phase 3 (done, changed): portable replay mode: paced replay of recorded scenarios through the same engine, the runtime
   snapshot writer and frame feed, engine start/stop/trigger API, authorisation tools and setup warnings. **Original Phase 3**
   (monitor mode, channel handling, live capture thread) is kept as a backup in `docs/live-capture-backup.md`.
4. Phase 4 (done): evaluation harness for the five scenarios (simulated trials, seeded and varied), threshold sweep, CSV and
   methodology export, and a recording protocol for live lab trials (`docs/evaluation.md`). It deliberately contains no
   tool that transmits attack frames.
5. Phase 5 (partly done): persistent login lockout, secret key handling, TLS and secure-cookie settings, a production server
   (`run.py --production`), backup, restore and upgrade procedure, and a Windows verification list (`docs/deployment.md`).
   Not done, and not needed for a single-administrator deployment: multi-factor sign-in, a general rate limiter, an
   administrator audit log, encryption of the database or backups at rest, privilege separation for live capture.

## Beyond one laptop

For anything other than localhost on one machine, read `docs/deployment.md`. In short: install `requirements-production.txt`,
make a certificate (`make-cert`), and start with
`python run.py --production --cert instance/tls/wifiguard.crt --key instance/tls/wifiguard.key`
(with `WIFIGUARD_HOST=0.0.0.0` to accept connections from the network). Production mode refuses to serve plain HTTP on a
network address. `flask --app wifiguard check-config` lists anything unsafe about the current settings.

## Evaluation for Chapter 4

```bash
flask --app wifiguard evaluate run --save          # five scenarios x 10 trials into the Reports test-run log
flask --app wifiguard evaluate sweep               # deauthentication threshold calibration table
flask --app wifiguard evaluate export              # test_runs.csv (Appendix B), metrics.md, methodology.md
```

These are simulated trials: they verify the rules and their built-in delay, not over-the-air performance. Read
`docs/evaluation.md` before quoting any figure.

## Windows checklist (first run on a new laptop)

1. `python --version` shows 3.10 or newer (from a Command Prompt). If not, install Python and tick "Add python.exe to PATH".
2. Double-click `start.bat`. Expect: environment created, packages installed, an administrator prompt, "Demo data loaded", then
   "Engine replaying 'baseline'" and the address.
3. Open http://127.0.0.1:5000, sign in. The Dashboard should show the engine as running, a packet rate above zero, and the
   capture sources as `replay: baseline` and `replay: ARP`.
4. Quick check of the engine: in a second Command Prompt in this folder, `.venv\Scripts\python -m flask --app wifiguard engine-status`.
5. If anything fails, copy the full text of the window and report it. Likely trouble spots: Python not on PATH, a firewall or
   antivirus blocking port 5000 (`set WIFIGUARD_PORT=5050` before starting), or a scapy warning that can be ignored.

## Ethics

For authorised, defensive monitoring of networks you own or have written permission to monitor (report Section 3.14).
