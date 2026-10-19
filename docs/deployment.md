# Deploying WiFiGuard beyond a single laptop

The demo (`start.bat` / `start.sh`) is built for one person on one machine. This page is for when WiFiGuard is reachable
by other people or left running: encrypted connections, a secret key you control, login lockout, backups, and a
production web server. Everything here is a setting or a command; nothing needs code changes.

**Evidence note.** Everything below was run on Linux (Python 3.13): the TLS server, the secure cookie, the lockout across a
restart, backup and restore. **None of it has been run on Windows.** The Windows checklist near the end says what to check.

## 1. Choose a setup

| Setup | When | How |
| --- | --- | --- |
| **A. Laptop demo** | Seminar, one person, `127.0.0.1` | `start.bat`. Nothing on this page is needed. |
| **B. Lab server, TLS built in** | A machine others on the LAN open in a browser | `python run.py --production --cert ... --key ...` with `WIFIGUARD_HOST=0.0.0.0` |
| **C. Behind an HTTPS reverse proxy** | You already run Caddy, nginx or IIS, or want a real certificate (Let's Encrypt) | WiFiGuard on `127.0.0.1` over HTTP, `WIFIGUARD_TRUST_PROXY=1`, `WIFIGUARD_COOKIE_SECURE=1` |

Install the extras for B and C: `pip install -r requirements-production.txt`
(`cheroot` is the production server; `cryptography` is only for making a lab certificate).

**One process only.** The detection engine runs in the server process. Never start two copies against the same
`instance/` folder, and never run several worker processes: each would analyse every frame.

## 2. TLS (HTTPS)

Without TLS the administrator's password and session cookie cross the network readable by anyone on it.

### Setup B: certificate on WiFiGuard itself

1. Make a certificate (lab use). Add every name or IP address people will type:
   ```
   flask --app wifiguard make-cert --host wifiguard.lab --host 192.168.1.20
   ```
   It writes `instance/tls/wifiguard.crt` and `.key` and prints the certificate's SHA-256 fingerprint.
2. Start it:
   ```
   set WIFIGUARD_HOST=0.0.0.0
   python run.py --demo --production --cert instance\tls\wifiguard.crt --key instance\tls\wifiguard.key
   ```
   (Linux/macOS: `export WIFIGUARD_HOST=0.0.0.0`.) You can use `WIFIGUARD_TLS_CERT` and `WIFIGUARD_TLS_KEY` instead of the flags.
3. Open `https://<name>:5000`. A self-signed certificate makes the browser warn on first visit. Compare the fingerprint shown in
   the browser's certificate details with the one `make-cert` printed, then accept. A certificate from a real authority
   avoids the warning: pass its files to `--cert` and `--key` (use the full chain in the `--cert` file).

TLS 1.2 is the minimum. In production mode WiFiGuard **refuses to listen on a network address over plain HTTP** unless you
set `WIFIGUARD_TRUST_PROXY` (Setup C) or `WIFIGUARD_ALLOW_HTTP=1` (a network you fully control; not recommended).
Self-signed certificates last 365 days; renew with `make-cert --force` and restart.

### Setup C: behind a reverse proxy

The proxy holds the certificate and forwards to WiFiGuard on `127.0.0.1:5000`.

```
WIFIGUARD_HOST=127.0.0.1          (the default; keep it, so only the proxy can connect)
WIFIGUARD_TRUST_PROXY=1           (number of proxies in front)
WIFIGUARD_COOKIE_SECURE=1
```

The proxy must send `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host`. Caddy does this by default
(`reverse_proxy 127.0.0.1:5000`); nginx needs `proxy_set_header X-Forwarded-For $remote_addr; proxy_set_header
X-Forwarded-Proto $scheme; proxy_set_header X-Forwarded-Host $host;`.

`WIFIGUARD_TRUST_PROXY` makes WiFiGuard believe those headers. If it listens on a public address, anyone can forge
`X-Forwarded-For` and defeat the login lockout; `flask --app wifiguard check-config` warns about this.

## 3. Cookies, HSTS and the settings that go with TLS

| Variable | Default | Meaning |
| --- | --- | --- |
| `WIFIGUARD_TLS_CERT` / `WIFIGUARD_TLS_KEY` | unset | Serve HTTPS directly. Set both or neither. |
| `WIFIGUARD_COOKIE_SECURE` | on when TLS is configured here, otherwise off | The browser only sends the session cookie over HTTPS. **Set `1` yourself in Setup C**, because WiFiGuard cannot tell the proxy serves HTTPS. If you set `0` with TLS on, check-config flags it. |
| `WIFIGUARD_TRUST_PROXY` | `0` | How many proxies' `X-Forwarded-*` headers to believe. |
| `WIFIGUARD_HSTS_SECONDS` | `0` (off) | Sends `Strict-Transport-Security` on HTTPS responses. See below. |
| `WIFIGUARD_ALLOW_HTTP` | unset | `1` lets `--production` serve plain HTTP on a network address. |

The session cookie is also `HttpOnly` and `SameSite=Lax`, and every state-changing request needs the `X-WifiGuard-Client: 1`
header (these were already in place).

**HSTS is off by default on purpose.** A browser that sees it refuses plain HTTP for that host name for the whole period, on
*every port*. With a self-signed lab certificate, turning it on for `localhost` would also break any other tool you run on
`http://localhost`, and a lapsed certificate would lock you out of the page. Set `WIFIGUARD_HSTS_SECONDS=31536000` only once
the certificate is a real, auto-renewing one.

Check your settings at any time: `flask --app wifiguard check-config`.

## 4. Secret key

The key signs session cookies. Anyone holding it can forge a signed-in session, so it must not be guessable, committed to
Git, or copied into a backup. It is chosen in this order:

1. `WIFIGUARD_SECRET_KEY` (the value itself);
2. `WIFIGUARD_SECRET_KEY_FILE` (path to a file holding it, for secrets managers, Docker/Kubernetes secrets, systemd credentials);
3. `instance/secret_key`, created on first run: 64 random hex characters, readable only by its owner on Linux/macOS.

Keys shorter than 32 characters are refused at start-up, with a one-line way to generate a good one:
`python -c "import secrets; print(secrets.token_hex(32))"`.

- **Rotate** (suspected leak, or someone with access left): `flask --app wifiguard rotate-secret-key`, then restart. Everyone is
  signed out. If the key comes from an environment variable or key file, change it there instead; the command refuses to act.
- **Backups do not contain the key**, deliberately. After a restore on a new machine everyone simply signs in again.
- **On Windows** the owner-only file mode is not applied. The file inherits the folder's permissions; keep `instance\` inside
  your own user profile (not a shared folder), or use `WIFIGUARD_SECRET_KEY_FILE` pointing at a location only you can read.
- Changing the key does not touch passwords or data.

## 5. Login lockout

After 5 wrong passwords for the same name from the same address, sign-in is refused for 5 minutes (HTTP 429 with the seconds to
wait), **even for the correct password**. Separately, one address that fails 20 times across any names is locked out.

- Failures are stored in the database (`login_failures`), so **a restart no longer clears a lockout**, and two processes
  would share it. Rows older than five minutes are deleted as new ones arrive.
- A correct sign-in clears that name's counter.
- **If you lock yourself out:** `flask --app wifiguard unlock-login` clears every lockout immediately (run it on the server).
- Behind a proxy the address is the *client's*, only if `WIFIGUARD_TRUST_PROXY` is right. If it is 0, everyone shares the
  proxy's address and one person's mistakes can lock everyone out.
- This is brute-force protection for one administrator, not a full rate limiter: it does not limit other endpoints and there is
  no multi-factor sign-in.

## 6. Backup, restore, upgrade

### Backup

```
flask --app wifiguard backup                 (writes instance/backups/wifiguard-backup-<UTC time>Z.zip)
flask --app wifiguard backup --keep 14       (afterwards deletes the oldest of these beyond 14)
flask --app wifiguard backup --out D:\safe\wg.zip
```

Safe while the server is running (SQLite's online backup gives a consistent copy). The zip holds the database, the saved
evaluation runs (`instance/evaluation/run-*.json`) and a manifest. It does **not** hold the secret key or TLS files.
It does hold the administrator's password hash and your network's MAC addresses, so keep it somewhere private. A backup that
lives only on the same disk protects against mistakes, not against the disk failing: copy it elsewhere.

### Restore

1. **Stop the server.** Restore refuses while it detects a running server (`--force` overrides, only if you are certain).
2. `flask --app wifiguard restore <backup.zip>`. It shows what the backup contains, asks, saves the current database as
   `wifiguard-pre-restore-...zip` in `instance/backups/`, checks the backup's integrity and schema version, then replaces the database.
   A damaged, foreign or newer-version backup is refused and nothing changes.
3. Start the server.

### Upgrade to a new version

1. `flask --app wifiguard backup`
2. Stop the server.
3. Replace the program folder with the new version **but keep `instance/`** (your database, key and backups live there).
4. `pip install -r requirements.txt` (and `requirements-production.txt` if used).
5. Start it. Missing tables and default settings are added automatically. If anything is wrong: stop, reinstall the old
   folder, and `restore` the backup from step 1.

Limit: there are no column-level migrations yet (all schema changes so far only add tables). A future version that needs one will
raise the schema number; older code refuses to open a database from a newer version rather than risk damaging it.

### Scheduling (retention and backups)

Alert history grows. `flask --app wifiguard purge` removes closed alerts and samples older than the retention setting. Neither
command runs by itself. Schedule them with the same environment the server uses:

- Windows (Task Scheduler, daily): program `C:\path\to\wifiguard\.venv\Scripts\flask.exe`, arguments
  `--app wifiguard backup --keep 14`, start in the program folder. A second task for `purge`.
- Linux (`crontab -e`): `15 2 * * * cd /opt/wifiguard && .venv/bin/flask --app wifiguard backup --keep 14 && .venv/bin/flask --app wifiguard purge`

## 7. Running it as a service

The built-in Flask server (`python run.py` without `--production`) is for the demo: one administrator, one machine. Use
`--production` for anything shared. To keep it running after logout or reboot, use your platform's service manager
(a systemd unit or Windows Task Scheduler "at startup" task / NSSM). Start with the flags above and a fixed `WIFIGUARD_INSTANCE`.
Stop it with Ctrl+C or a normal service stop so the pid file is removed. A stale pid file is harmless (it is ignored once the
process is gone).

## 8. Windows checklist (not yet run on Windows)

Work through this once on the target laptop and note any failure:

1. `start.bat` creates `.venv`, installs, and the dashboard opens at `http://127.0.0.1:5000`; the engine shows as running.
2. `flask --app wifiguard check-config` prints the settings (activate with `.venv\Scripts\activate` first, or call `.venv\Scripts\flask.exe`).
3. `.venv\Scripts\pip install -r requirements-production.txt` succeeds (`cheroot` and `cryptography` ship Windows wheels).
4. `flask --app wifiguard make-cert --host localhost` writes the two files.
5. `python run.py --demo --production --cert instance\tls\wifiguard.crt --key instance\tls\wifiguard.key` serves
   `https://localhost:5000` (expect the self-signed warning). The browser must show the page and sign-in works.
6. Five wrong passwords give "too many attempts"; stop and restart the server; the correct password is **still** refused; `unlock-login` fixes it.
7. `flask --app wifiguard backup`, stop the server, `restore` that file, start again: the dashboard shows the same alerts.
8. Windows Firewall: the first run on `0.0.0.0` prompts to allow Python on private networks. Allow private, not public.
9. Scapy may print a warning about Npcap/libpcap at start. Replay does not need it.

## 9. Hardening checklist

- [ ] TLS on (Setup B or C), `check-config` shows no warnings
- [ ] Strong administrator password (at least 8 characters is enforced; use a long passphrase)
- [ ] Secret key is random, not in version control, not shared
- [ ] `instance/` folder readable only by the account running WiFiGuard
- [ ] Backups scheduled and copied off the machine; a restore tested at least once
- [ ] Only the proxy can reach WiFiGuard in Setup C (bind `127.0.0.1`, firewall the port)
- [ ] `WIFIGUARD_HSTS_SECONDS` set once the certificate is a real one
- [ ] Windows and OS updates; `pip install -U -r requirements.txt` after a Flask security release

## 10. What this does not cover

Multiple administrators or roles, multi-factor sign-in, rate limiting of endpoints other than sign-in, an audit log of
administrator actions, encrypting the database or backups at rest, and privilege separation for live capture (a capture
process needs elevated rights; if live capture is ever built, keep it in a separate process from the web server, see
`docs/live-capture-backup.md`). These are candidates for the report's future-work section.
