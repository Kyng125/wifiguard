"""Phase 5: persistent login lockout, secret key handling, TLS and cookie settings, backup and restore."""
import json
import os
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from wifiguard import config as cfgmod
from wifiguard import create_app, db, maintenance, security
from wifiguard.seed_demo import seed

HEADER = {"X-WifiGuard-Client": "1"}


def make_app(tmp_path, **overrides):
    cfg = {"DATABASE": str(tmp_path / "test.db"), "INSTANCE_DIR": str(tmp_path), "SECRET_KEY": "k" * 40,
           "TESTING": True, "FRONTEND_DIST": str(tmp_path / "no-dist"), "LOGIN_MAX_FAILURES": 3}
    cfg.update(overrides)
    app = create_app(cfg)
    conn = db.connect(app.config["DATABASE"])
    if not conn.execute("SELECT 1 FROM admin_users").fetchone():
        security.create_admin(conn, "admin", "correct-horse")
    conn.close()
    return app


def login(client, user="admin", password="correct-horse", **kw):
    headers = {**HEADER, **kw.pop("headers", {})}
    return client.post("/api/auth/login", json={"username": user, "password": password}, headers=headers, **kw)


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ("WIFIGUARD_SECRET_KEY", "WIFIGUARD_SECRET_KEY_FILE", "WIFIGUARD_TLS_CERT", "WIFIGUARD_TLS_KEY",
                 "WIFIGUARD_COOKIE_SECURE", "WIFIGUARD_TRUST_PROXY", "WIFIGUARD_HSTS_SECONDS", "WIFIGUARD_HOST"):
        monkeypatch.delenv(name, raising=False)


# ------------------------------------------------------------------------------------------------ login lockout

def test_lockout_survives_a_restart(tmp_path):
    first = make_app(tmp_path)
    for _ in range(3):
        assert login(first.test_client(), password="bad-bad-bad").status_code == 401
    second = make_app(tmp_path)                                   # a new process would build a new app on the same database
    r = login(second.test_client())                               # even the right password is refused
    assert r.status_code == 429 and r.get_json()["error"]["details"]["retryAfterSeconds"] > 0


def test_lockout_expires(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    client = app.test_client()
    clock = [1_000_000.0]
    monkeypatch.setattr(security, "_now", lambda: clock[0])
    for _ in range(3):
        login(client, password="bad-bad-bad")
    assert login(client).status_code == 429
    clock[0] += 200
    r = login(client)
    assert r.status_code == 429 and 90 <= r.get_json()["error"]["details"]["retryAfterSeconds"] <= 101   # 300 - 200
    clock[0] += 101
    assert login(client).status_code == 200


def test_retry_after_counts_to_the_failure_that_lifts_the_lock(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    client = app.test_client()
    clock = [5_000.0]
    monkeypatch.setattr(security, "_now", lambda: clock[0])
    for _ in range(4):                                            # 4 failures, one second apart; the limit is 3
        login(client, password="bad-bad-bad")
        clock[0] += 1
    wait = login(client).get_json()["error"]["details"]["retryAfterSeconds"]
    # failures at t=0..3 (now t=4). The count drops below 3 when the failure at t=1 expires, at t=301: 297 s away.
    assert 296 <= wait <= 298


def test_success_clears_that_names_counter(tmp_path):
    client = make_app(tmp_path).test_client()
    for _ in range(2):
        login(client, password="bad-bad-bad")
    assert login(client).status_code == 200
    for _ in range(2):                                            # would be the 3rd and 4th without the reset
        assert login(client, password="bad-bad-bad").status_code == 401
    assert login(client).status_code == 200


def test_each_address_has_its_own_counter(tmp_path):
    client = make_app(tmp_path).test_client()
    for _ in range(3):
        login(client, password="bad-bad-bad")
    assert login(client).status_code == 429
    assert login(client, environ_base={"REMOTE_ADDR": "10.0.0.9"}).status_code == 200


def test_one_address_cannot_walk_through_usernames(tmp_path):
    client = make_app(tmp_path, LOGIN_MAX_FAILURES_PER_ADDRESS=4).test_client()
    for i in range(4):
        assert login(client, user=f"guess{i}", password="whatever-1").status_code == 401
    r = login(client, user="never-tried-before", password="whatever-1")
    assert r.status_code == 429                                   # a new name does not reset the address-wide counter
    assert login(client, environ_base={"REMOTE_ADDR": "10.0.0.9"}).status_code == 200


def test_old_failures_are_pruned(tmp_path, monkeypatch):
    app = make_app(tmp_path)
    client = app.test_client()
    clock = [100.0]
    monkeypatch.setattr(security, "_now", lambda: clock[0])
    login(client, password="bad-bad-bad")
    clock[0] += 1000
    login(client, password="bad-bad-bad")
    conn = db.connect(app.config["DATABASE"])
    assert conn.execute("SELECT COUNT(*) FROM login_failures").fetchone()[0] == 2     # only the new one (x2 counters)
    conn.close()


def test_unlock_login_command(tmp_path):
    app = make_app(tmp_path)
    client = app.test_client()
    for _ in range(3):
        login(client, password="bad-bad-bad")
    assert login(client).status_code == 429
    result = app.test_cli_runner().invoke(args=["unlock-login"])
    assert result.exit_code == 0 and "Cleared 6" in result.output       # 3 failures x 2 counters
    assert login(client).status_code == 200


# ------------------------------------------------------------------------------------------------ secret key

def test_generated_key_is_strong_private_and_reused(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_INSTANCE", str(tmp_path))
    first = cfgmod.load_config()["SECRET_KEY"]
    assert len(first) == 64
    assert cfgmod.load_config()["SECRET_KEY"] == first
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "secret_key").stat().st_mode) == 0o600


@pytest.mark.skipif(os.name != "posix", reason="file modes")
def test_loose_key_file_permissions_are_tightened(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_INSTANCE", str(tmp_path))
    (tmp_path / "secret_key").write_text("a" * 64)
    (tmp_path / "secret_key").chmod(0o644)
    cfgmod.load_config()
    assert stat.S_IMODE((tmp_path / "secret_key").stat().st_mode) == 0o600


def test_short_keys_are_refused(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_INSTANCE", str(tmp_path))
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY", "changeme")
    with pytest.raises(cfgmod.ConfigError, match="too short"):
        cfgmod.load_config()
    monkeypatch.delenv("WIFIGUARD_SECRET_KEY")
    (tmp_path / "secret_key").write_text("abc")
    with pytest.raises(cfgmod.ConfigError, match="too short"):
        cfgmod.load_config()


def test_key_from_environment_and_from_file(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_INSTANCE", str(tmp_path))
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY", "e" * 40)
    assert cfgmod.load_config()["SECRET_KEY"] == "e" * 40
    assert not (tmp_path / "secret_key").exists()                 # nothing is written when the key is supplied
    monkeypatch.delenv("WIFIGUARD_SECRET_KEY")
    key_file = tmp_path / "elsewhere.key"
    key_file.write_text("f" * 40 + "\n")
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY_FILE", str(key_file))
    assert cfgmod.load_config()["SECRET_KEY"] == "f" * 40
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY_FILE", str(tmp_path / "missing.key"))
    with pytest.raises(cfgmod.ConfigError, match="cannot be read"):
        cfgmod.load_config()
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY", "e" * 40)
    with pytest.raises(cfgmod.ConfigError, match="only one"):
        cfgmod.load_config()


def test_rotation_signs_everyone_out(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_INSTANCE", str(tmp_path))
    monkeypatch.setenv("WIFIGUARD_DB", str(tmp_path / "w.db"))
    before = create_app({"TESTING": True})
    client = before.test_client()
    conn = db.connect(before.config["DATABASE"])
    security.create_admin(conn, "admin", "correct-horse")
    conn.close()
    assert login(client).status_code == 200
    cookie = client.get_cookie("wifiguard_session")
    assert client.get("/api/auth/session", headers=HEADER).status_code == 200

    result = before.test_cli_runner().invoke(args=["rotate-secret-key", "--yes"])
    assert result.exit_code == 0, result.output
    after = create_app({"TESTING": True})
    assert after.config["SECRET_KEY"] != before.config["SECRET_KEY"]
    stale = after.test_client()
    stale.set_cookie("wifiguard_session", cookie.value)
    assert stale.get("/api/auth/session", headers=HEADER).status_code == 401


def test_rotation_refuses_when_the_key_is_supplied_by_environment(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_SECRET_KEY", "e" * 40)
    app = make_app(tmp_path)
    result = app.test_cli_runner().invoke(args=["rotate-secret-key", "--yes"])
    assert result.exit_code != 0 and "environment variable" in result.output


# ------------------------------------------------------------------------------------------- TLS and cookies

def test_defaults_are_plain_http_with_a_non_secure_cookie(tmp_path):
    app = make_app(tmp_path)
    assert not cfgmod.tls_enabled(app.config) and app.config["SESSION_COOKIE_SECURE"] is False
    assert "Secure" not in login(app.test_client()).headers["Set-Cookie"]
    assert "Strict-Transport-Security" not in app.test_client().get("/api/ping").headers


def test_configuring_tls_makes_the_cookie_secure(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_TLS_CERT", "c.pem")
    monkeypatch.setenv("WIFIGUARD_TLS_KEY", "k.pem")
    app = make_app(tmp_path, SECRET_KEY="k" * 40)
    assert app.config["SESSION_COOKIE_SECURE"] is True
    cookie = login(app.test_client(), base_url="https://localhost").headers["Set-Cookie"]
    assert "Secure" in cookie and "HttpOnly" in cookie


def test_explicit_cookie_setting_wins_and_is_flagged(tmp_path, monkeypatch):
    monkeypatch.setenv("WIFIGUARD_TLS_CERT", "c.pem")
    monkeypatch.setenv("WIFIGUARD_TLS_KEY", "k.pem")
    monkeypatch.setenv("WIFIGUARD_COOKIE_SECURE", "0")
    cfg = cfgmod.load_config({"SECRET_KEY": "k" * 40})
    assert cfg["SESSION_COOKIE_SECURE"] is False
    assert any("COOKIE_SECURE=0" in w for w in cfgmod.deployment_warnings(cfg))


def test_certificate_without_key_is_an_error(monkeypatch):
    monkeypatch.setenv("WIFIGUARD_TLS_CERT", "c.pem")
    with pytest.raises(cfgmod.ConfigError, match="both"):
        cfgmod.load_config({"SECRET_KEY": "k" * 40})


def test_bad_flag_values_are_reported(monkeypatch):
    monkeypatch.setenv("WIFIGUARD_COOKIE_SECURE", "maybe")
    with pytest.raises(cfgmod.ConfigError, match="WIFIGUARD_COOKIE_SECURE"):
        cfgmod.load_config({"SECRET_KEY": "k" * 40})


def test_command_line_certificate_applies_the_same_rule(monkeypatch):
    cfg = cfgmod.load_config({"SECRET_KEY": "k" * 40})
    cfgmod.apply_tls(cfg, "c.pem", "k.pem")
    assert cfgmod.tls_enabled(cfg) and cfg["SESSION_COOKIE_SECURE"] is True
    with pytest.raises(cfgmod.ConfigError):
        cfgmod.apply_tls(cfgmod.load_config({"SECRET_KEY": "k" * 40}), "c.pem", None)


def test_missing_certificate_files_are_reported():
    cfg = cfgmod.load_config({"SECRET_KEY": "k" * 40, "TLS_CERT": "/nope/c.pem", "TLS_KEY": "/nope/k.pem"})
    with pytest.raises(cfgmod.ConfigError, match="not found"):
        cfgmod.check_tls_files(cfg)


def test_hsts_is_sent_only_over_https_and_only_when_enabled(tmp_path):
    app = make_app(tmp_path, HSTS_SECONDS=86400)
    client = app.test_client()
    assert client.get("/api/ping", base_url="https://localhost").headers["Strict-Transport-Security"] == "max-age=86400"
    assert "Strict-Transport-Security" not in client.get("/api/ping").headers


def test_forwarded_headers_are_ignored_unless_a_proxy_is_trusted(tmp_path):
    client = make_app(tmp_path).test_client()
    for i in range(3):                                            # an attacker varying X-Forwarded-For gains nothing
        login(client, password="bad-bad-bad", headers={"X-Forwarded-For": f"203.0.113.{i}", **HEADER})
    assert login(client, headers={"X-Forwarded-For": "203.0.113.200", **HEADER}).status_code == 429


def test_trusted_proxy_supplies_the_client_address_and_scheme(tmp_path):
    app = make_app(tmp_path, TRUST_PROXY=1, HSTS_SECONDS=60)
    client = app.test_client()
    forwarded = {"X-Forwarded-For": "203.0.113.5", "X-Forwarded-Proto": "https", **HEADER}
    for _ in range(3):
        login(client, password="bad-bad-bad", headers=forwarded)
    assert login(client, headers=forwarded).status_code == 429
    other = {**forwarded, "X-Forwarded-For": "203.0.113.6"}
    r = login(client, headers=other)
    assert r.status_code == 200 and r.headers["Strict-Transport-Security"] == "max-age=60"   # scheme seen as https


def test_deployment_warnings():
    base = cfgmod.load_config({"SECRET_KEY": "k" * 40})
    assert cfgmod.deployment_warnings(base) == []
    open_http = {**base, "HOST": "0.0.0.0"}
    assert any("plain HTTP" in w for w in cfgmod.deployment_warnings(open_http))
    assert not any("plain HTTP" in w for w in cfgmod.deployment_warnings({**open_http, "TLS_CERT": "c", "TLS_KEY": "k"}))
    proxied_open = {**open_http, "TRUST_PROXY": 1}
    assert any("forge" in w for w in cfgmod.deployment_warnings(proxied_open))
    assert any("not marked Secure" in w for w in cfgmod.deployment_warnings({**base, "TRUST_PROXY": 1}))


def test_check_config_command(tmp_path):
    app = make_app(tmp_path, HOST="0.0.0.0")
    out = app.test_cli_runner().invoke(args=["check-config"]).output
    assert "0.0.0.0" in out and "plain HTTP" in out and "Secret key from" in out


# ---------------------------------------------------------------------------------------- schema protection

def test_database_from_a_newer_version_is_refused(tmp_path):
    app = make_app(tmp_path)
    conn = db.connect(app.config["DATABASE"])
    conn.execute("UPDATE schema_version SET version = 99")
    conn.commit()
    conn.close()
    with pytest.raises(RuntimeError, match="newer WiFiGuard"):
        make_app(tmp_path)


# --------------------------------------------------------------------------------------------- backup and restore

@pytest.fixture
def populated(tmp_path):
    app = make_app(tmp_path)
    with app.app_context():
        seed(reset=True)
    (tmp_path / "evaluation").mkdir()
    (tmp_path / "evaluation" / "run-20261001-test.json").write_text('{"trials": 1}')
    return app


def count(app, table):
    conn = db.connect(app.config["DATABASE"])
    try:
        return conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    finally:
        conn.close()


def test_backup_contains_data_but_not_the_secret_key(populated, tmp_path):
    (tmp_path / "secret_key").write_text("s" * 64)
    made = maintenance.backup(populated.config["DATABASE"], str(tmp_path))
    with zipfile.ZipFile(made["path"]) as archive:
        names = set(archive.namelist())
        manifest = json.loads(archive.read("manifest.json"))
    assert names == {"wifiguard.db", "manifest.json", "evaluation/run-20261001-test.json"}
    assert manifest["counts"]["security_events"] == count(populated, "security_events") > 0
    assert manifest["schemaVersion"] == db.SCHEMA_VERSION and manifest["appVersion"]
    assert "s" * 64 not in Path(made["path"]).read_bytes().decode("latin-1")
    if os.name == "posix":
        assert stat.S_IMODE(Path(made["path"]).stat().st_mode) == 0o600


def test_backup_is_taken_while_the_database_is_in_use(populated, tmp_path):
    holder = db.connect(populated.config["DATABASE"])
    holder.execute("BEGIN")
    holder.execute("INSERT INTO device_notes (mac_address, text, created_at) VALUES ('AA:BB:CC:00:00:01', 'x', 'now')")
    try:
        made = maintenance.backup(populated.config["DATABASE"], str(tmp_path))     # the open write transaction is not in it
    finally:
        holder.rollback()
        holder.close()
    assert made["manifest"]["counts"]["security_events"] > 0


def test_backup_does_not_carry_lockouts(tmp_path):
    app = make_app(tmp_path)
    for _ in range(3):
        login(app.test_client(), password="bad-bad-bad")
    made = maintenance.backup(app.config["DATABASE"], str(tmp_path))
    with zipfile.ZipFile(made["path"]) as archive:
        archive.extract("wifiguard.db", tmp_path / "x")
    import sqlite3
    assert sqlite3.connect(tmp_path / "x" / "wifiguard.db").execute("SELECT COUNT(*) FROM login_failures").fetchone()[0] == 0


def test_backup_never_overwrites(populated, tmp_path):
    target = tmp_path / "mine.zip"
    maintenance.backup(populated.config["DATABASE"], str(tmp_path), out=str(target))
    with pytest.raises(maintenance.MaintenanceError, match="already exists"):
        maintenance.backup(populated.config["DATABASE"], str(tmp_path), out=str(target))


def test_keep_prunes_only_old_backups(populated, tmp_path):
    folder = tmp_path / "backups"
    folder.mkdir()
    for stamp in ("20260101-000000", "20260102-000000", "20260103-000000"):
        (folder / f"wifiguard-backup-{stamp}Z.zip").write_bytes(b"old")
    (folder / "wifiguard-pre-restore-20260101-000000Z.zip").write_bytes(b"keep me")
    (folder / "notes.txt").write_text("keep me too")
    made = maintenance.backup(populated.config["DATABASE"], str(tmp_path), keep=2)
    assert made["removed"] == ["wifiguard-backup-20260101-000000Z.zip", "wifiguard-backup-20260102-000000Z.zip"]
    left = sorted(p.name for p in folder.iterdir())
    assert "wifiguard-pre-restore-20260101-000000Z.zip" in left and "notes.txt" in left and len(left) == 4


def test_restore_round_trip(populated, tmp_path):
    database = populated.config["DATABASE"]
    original = count(populated, "security_events")
    made = maintenance.backup(database, str(tmp_path))
    conn = db.connect(database)
    conn.execute("DELETE FROM event_log")
    conn.execute("DELETE FROM security_events")
    conn.commit()
    conn.close()
    assert count(populated, "security_events") == 0
    (tmp_path / "evaluation" / "run-20261001-test.json").unlink()

    done = maintenance.restore(database, str(tmp_path), made["path"])
    assert count(populated, "security_events") == original
    assert Path(done["safetyBackup"]).is_file() and "pre-restore" in done["safetyBackup"]
    assert done["evaluationRunsRestored"] == 1 and (tmp_path / "evaluation" / "run-20261001-test.json").is_file()
    assert login(make_app(tmp_path).test_client()).status_code == 200      # the restored database still works


def test_restore_command_round_trip(populated, tmp_path):
    runner = populated.test_cli_runner()
    out = runner.invoke(args=["backup"]).output
    assert "Backup written" in out and "alerts" in out
    archive = next((tmp_path / "backups").glob("wifiguard-backup-*.zip"))
    result = runner.invoke(args=["restore", str(archive), "--yes"])
    assert result.exit_code == 0 and "Restored" in result.output and "pre-restore" in result.output


def test_restore_refuses_bad_archives(populated, tmp_path):
    database = populated.config["DATABASE"]
    junk = tmp_path / "junk.zip"
    junk.write_bytes(b"not a zip")
    with pytest.raises(maintenance.MaintenanceError, match="Could not read"):
        maintenance.restore(database, str(tmp_path), str(junk))

    other = tmp_path / "other.zip"
    with zipfile.ZipFile(other, "w") as z:
        z.writestr("hello.txt", "hi")
    with pytest.raises(maintenance.MaintenanceError, match="not a WiFiGuard backup"):
        maintenance.restore(database, str(tmp_path), str(other))

    newer = tmp_path / "newer.zip"
    with zipfile.ZipFile(newer, "w") as z:
        z.writestr("wifiguard.db", b"x")
        z.writestr("manifest.json", json.dumps({"app": "wifiguard", "schemaVersion": 99}))
    with pytest.raises(maintenance.MaintenanceError, match="newer WiFiGuard"):
        maintenance.restore(database, str(tmp_path), str(newer))

    damaged = tmp_path / "damaged.zip"
    with zipfile.ZipFile(damaged, "w") as z:
        z.writestr("wifiguard.db", b"this is not a sqlite database at all" * 50)
        z.writestr("manifest.json", json.dumps({"app": "wifiguard", "schemaVersion": 1}))
    before = count(populated, "security_events")
    with pytest.raises(maintenance.MaintenanceError, match="cannot be opened|damaged"):
        maintenance.restore(database, str(tmp_path), str(damaged))
    assert count(populated, "security_events") == before            # a refused restore changes nothing


def test_restore_ignores_archive_members_with_unsafe_names(populated, tmp_path):
    made = maintenance.backup(populated.config["DATABASE"], str(tmp_path))
    evil = tmp_path / "evil.zip"
    with zipfile.ZipFile(made["path"]) as source, zipfile.ZipFile(evil, "w") as target:
        for item in source.namelist():
            target.writestr(item, source.read(item))
        target.writestr("evaluation/../../escaped.json", "{}")
        target.writestr("../escaped2.json", "{}")
    maintenance.restore(populated.config["DATABASE"], str(tmp_path), str(evil))
    assert not (tmp_path.parent / "escaped2.json").exists() and not (tmp_path / "escaped.json").exists()


def test_restore_waits_for_the_server_to_stop(populated, tmp_path):
    made = maintenance.backup(populated.config["DATABASE"], str(tmp_path))
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)  # run.py"])
    try:
        maintenance.pidfile_path(str(tmp_path)).write_text(str(child.pid))
        assert maintenance.running_server_pid(str(tmp_path)) == child.pid
        with pytest.raises(maintenance.MaintenanceError, match="appears to be running"):
            maintenance.restore(populated.config["DATABASE"], str(tmp_path), made["path"])
        maintenance.restore(populated.config["DATABASE"], str(tmp_path), made["path"], force=True)
    finally:
        child.kill()
        child.wait()
    maintenance.pidfile_path(str(tmp_path)).write_text(str(child.pid))        # now dead: a stale pid file does not block
    assert maintenance.running_server_pid(str(tmp_path)) is None
    maintenance.restore(populated.config["DATABASE"], str(tmp_path), made["path"])


def test_a_pid_belonging_to_another_program_does_not_block(populated, tmp_path):
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
    try:
        maintenance.pidfile_path(str(tmp_path)).write_text(str(child.pid))
        assert maintenance.running_server_pid(str(tmp_path)) is None
    finally:
        child.kill()
        child.wait()


# ------------------------------------------------------------------------------------------ certificate and TLS

cryptography = pytest.importorskip("cryptography")


def test_make_cert_writes_a_usable_certificate(tmp_path):
    from cryptography import x509
    from wifiguard import tlscert
    made = tlscert.make_self_signed(str(tmp_path / "tls"), ["wifiguard.lab", "192.168.1.20"])
    cert = x509.load_pem_x509_certificate(Path(made["cert"]).read_bytes())
    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert "wifiguard.lab" in san.get_values_for_type(x509.DNSName) and "localhost" in san.get_values_for_type(x509.DNSName)
    assert any(str(ip) == "192.168.1.20" for ip in san.get_values_for_type(x509.IPAddress))
    assert len(made["fingerprint"].split(":")) == 32
    if os.name == "posix":
        assert stat.S_IMODE(Path(made["key"]).stat().st_mode) == 0o600
    with pytest.raises(cfgmod.ConfigError, match="already exists"):
        tlscert.make_self_signed(str(tmp_path / "tls"), [])
    tlscert.make_self_signed(str(tmp_path / "tls"), [], force=True)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")      # the test deliberately offers the deprecated TLS 1.1
def test_https_end_to_end_with_the_production_server(tmp_path):
    """A real TLS handshake against the real production server, using the certificate make-cert produced."""
    import socket
    import ssl
    import threading
    import urllib.request
    pytest.importorskip("cheroot")
    from cheroot.ssl.builtin import BuiltinSSLAdapter
    from cheroot.wsgi import Server
    from wifiguard import tlscert

    made = tlscert.make_self_signed(str(tmp_path / "tls"), [])
    app = make_app(tmp_path, TLS_CERT=made["cert"], TLS_KEY=made["key"], SESSION_COOKIE_SECURE=True, HSTS_SECONDS=60)
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    server = Server(("127.0.0.1", port), app, numthreads=4)
    adapter = BuiltinSSLAdapter(made["cert"], made["key"])
    adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
    server.ssl_adapter = adapter
    thread = threading.Thread(target=server.safe_start, daemon=True)
    thread.start()
    try:
        server.ready or server.serve  # noqa: B018 - touch; readiness is polled below
        import time
        for _ in range(100):
            if server.ready:
                break
            time.sleep(0.05)
        assert server.ready
        trust = ssl.create_default_context(cafile=made["cert"])
        with urllib.request.urlopen(f"https://localhost:{port}/api/ping", context=trust, timeout=5) as r:
            assert json.loads(r.read()) == {"ok": True}
            assert r.headers["Strict-Transport-Security"] == "max-age=60"
        request = urllib.request.Request(
            f"https://localhost:{port}/api/auth/login", method="POST", headers={**HEADER, "Content-Type": "application/json"},
            data=json.dumps({"username": "admin", "password": "correct-horse"}).encode())
        with urllib.request.urlopen(request, context=trust, timeout=5) as r:
            cookie = r.headers["Set-Cookie"]
        assert "Secure" in cookie and "HttpOnly" in cookie
        old = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        old.check_hostname = False
        old.verify_mode = ssl.CERT_NONE
        old.maximum_version = ssl.TLSVersion.TLSv1_1
        try:
            with urllib.request.urlopen(f"https://localhost:{port}/api/ping", context=old, timeout=5):
                refused = False
        except (ssl.SSLError, OSError, ValueError):
            refused = True
        assert refused, "TLS 1.1 must not be accepted"
    finally:
        server.stop()
