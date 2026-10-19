"""Backup, restore and the server's pid file.

A backup is one zip file holding a consistent copy of the database (taken with SQLite's online backup, so it is safe
while the server is running), the saved evaluation runs, and a manifest. It deliberately does NOT hold the secret key:
backups get copied around, and the key only signs session cookies, so a restored system simply makes everyone sign in again.
The database does contain the administrator's password hash and the network's MAC addresses, so treat a backup as sensitive.
"""
import atexit
import json
import os
import re
import sqlite3
import tempfile
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .db import SCHEMA_VERSION

DB_MEMBER = "wifiguard.db"
MANIFEST_MEMBER = "manifest.json"
EVALUATION_MEMBER = re.compile(r"^evaluation/run-[A-Za-z0-9._-]+\.json$")
MAX_DB_BYTES = 2 * 1024 ** 3
COUNTED_TABLES = ("security_events", "observed_devices", "observed_access_points", "authorised_access_points",
                  "authorised_devices", "test_runs", "admin_users")


class MaintenanceError(RuntimeError):
    """Something the person running the command can fix; the message says what."""


def default_backup_dir(instance_dir: str) -> Path:
    return Path(instance_dir) / "backups"


# ------------------------------------------------------------------------------------------------------- pid file

def pidfile_path(instance_dir: str) -> Path:
    return Path(instance_dir) / "server.pid"


def write_pidfile(instance_dir: str) -> Path:
    """Record that a server is running from this instance folder; removed on a normal exit."""
    path = pidfile_path(instance_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(str(os.getpid()))

    def _remove() -> None:
        try:
            if path.read_text().strip() == str(os.getpid()):
                path.unlink()
        except OSError:
            pass
    atexit.register(_remove)
    return path


def running_server_pid(instance_dir: str) -> int | None:
    """The pid of a running WiFiGuard server using this instance folder, or None. A stale file (crash, reboot, the
    number reused by an unrelated program) does not count."""
    path = pidfile_path(instance_dir)
    try:
        pid = int(path.read_text().strip())
    except (OSError, ValueError):
        return None
    if pid == os.getpid():
        return None
    try:
        import psutil
        if not psutil.pid_exists(pid):
            return None
        command = " ".join(psutil.Process(pid).cmdline()).lower()
    except Exception:                                   # noqa: BLE001 - without psutil, assume stale rather than block
        return None
    return pid if ("run.py" in command or "wifiguard" in command) else None


# ------------------------------------------------------------------------------------------------------- backup

def _utc_stamp() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


def _counts(conn: sqlite3.Connection) -> dict:
    out = {}
    for table in COUNTED_TABLES:
        try:
            out[table] = conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
        except sqlite3.Error:
            pass
    return out


def backup(database: str, instance_dir: str, out: str | None = None, keep: int | None = None,
           prefix: str = "wifiguard-backup") -> dict:
    """Write a backup zip. `out` is a file path or a folder (default instance/backups). `keep`, if given, deletes the oldest
    backups in that folder beyond that many (only files named like this command's own, never anything else)."""
    if not Path(database).is_file():
        raise MaintenanceError(f"There is no database at {database} to back up.")
    if out and not Path(out).is_dir() and Path(out).suffix.lower() == ".zip":
        target = Path(out)
    else:
        folder = Path(out) if out else default_backup_dir(instance_dir)
        stamp, n = _utc_stamp(), 1
        target = folder / f"{prefix}-{stamp}Z.zip"
        while target.exists():                          # two backups in the same second: never overwrite, number the second
            n += 1
            target = folder / f"{prefix}-{stamp}-{n}Z.zip"
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        raise MaintenanceError(f"{target} already exists. Choose another name; backups are never overwritten.")

    with tempfile.TemporaryDirectory(dir=target.parent) as work:
        copy = Path(work) / DB_MEMBER
        source = sqlite3.connect(database, timeout=10)
        dest = sqlite3.connect(copy)
        try:
            source.backup(dest)                         # consistent even while the server is writing
            if _has_table(dest, "login_failures"):
                dest.execute("DELETE FROM login_failures")     # lockouts belong to the running system, not the backup
            dest.commit()
            if dest.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                raise MaintenanceError("The database failed its integrity check, so it was not backed up. "
                                       "Do not overwrite older backups; see docs/deployment.md.")
            counts = _counts(dest)
            schema = dest.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
            dest.execute("PRAGMA journal_mode = DELETE")
        finally:
            dest.close()
            source.close()
        evaluation = sorted((Path(instance_dir) / "evaluation").glob("run-*.json"))
        manifest = {"app": "wifiguard", "appVersion": __version__, "schemaVersion": schema,
                    "createdAt": datetime.now(timezone.utc).isoformat(timespec="seconds"),
                    "counts": counts, "evaluationRuns": [p.name for p in evaluation],
                    "note": "The secret key is intentionally not included."}
        partial = target.with_suffix(".zip.partial")
        try:
            with zipfile.ZipFile(partial, "w", zipfile.ZIP_DEFLATED) as archive:
                archive.write(copy, DB_MEMBER)
                for path in evaluation:
                    archive.write(path, f"evaluation/{path.name}")
                archive.writestr(MANIFEST_MEMBER, json.dumps(manifest, indent=2))
            os.replace(partial, target)
        finally:
            partial.unlink(missing_ok=True)
    if os.name == "posix":
        target.chmod(0o600)
    removed = _prune(target.parent, prefix, keep) if keep else []
    return {"path": str(target), "bytes": target.stat().st_size, "manifest": manifest, "removed": removed}


def _has_table(conn: sqlite3.Connection, name: str) -> bool:
    return conn.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (name,)).fetchone() is not None


def _prune(folder: Path, prefix: str, keep: int) -> list[str]:
    files = sorted(folder.glob(f"{prefix}-*Z.zip"))       # the UTC stamp makes name order the same as age order
    doomed = files[:-keep] if keep > 0 else []
    for path in doomed:
        path.unlink(missing_ok=True)
    return [p.name for p in doomed]


# ------------------------------------------------------------------------------------------------------ restore

def read_manifest(archive_path: str) -> dict:
    try:
        with zipfile.ZipFile(archive_path) as archive:
            names = set(archive.namelist())
            if DB_MEMBER not in names or MANIFEST_MEMBER not in names:
                raise MaintenanceError("That is not a WiFiGuard backup (it has no database or manifest).")
            manifest = json.loads(archive.read(MANIFEST_MEMBER))
    except (zipfile.BadZipFile, json.JSONDecodeError, OSError) as exc:
        raise MaintenanceError(f"Could not read {archive_path} as a WiFiGuard backup: {exc}") from None
    if manifest.get("app") != "wifiguard":
        raise MaintenanceError("That is not a WiFiGuard backup.")
    return manifest


def restore(database: str, instance_dir: str, archive_path: str, force: bool = False) -> dict:
    """Replace the database with the one in a backup. The current database is first saved as a pre-restore backup.
    The server must be stopped: it keeps the database open and would keep writing to the old file."""
    manifest = read_manifest(archive_path)
    schema = manifest.get("schemaVersion")
    if not isinstance(schema, int) or schema > SCHEMA_VERSION:
        raise MaintenanceError(f"This backup is from a newer WiFiGuard (schema {schema}); this version understands "
                               f"{SCHEMA_VERSION}. Install the newer version first.")
    pid = running_server_pid(instance_dir)
    if pid and not force:
        raise MaintenanceError(f"WiFiGuard appears to be running (process {pid}). Stop it first, then restore. "
                               "(--force skips this check, only if you are sure that process is not using this database.)")
    db_path = Path(database)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=db_path.parent) as work:
        staged = Path(work) / DB_MEMBER
        with zipfile.ZipFile(archive_path) as archive:
            info = archive.getinfo(DB_MEMBER)
            if info.file_size > MAX_DB_BYTES:
                raise MaintenanceError("The database inside this backup is implausibly large; refusing to unpack it.")
            with archive.open(info) as src, open(staged, "wb") as dst:
                while chunk := src.read(1024 * 1024):
                    dst.write(chunk)
            evaluation = [n for n in archive.namelist() if EVALUATION_MEMBER.match(n)]
            conn = sqlite3.connect(staged)
            try:
                if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
                    raise MaintenanceError("The database inside this backup is damaged, so nothing was changed.")
                if not _has_table(conn, "admin_users") or not _has_table(conn, "schema_version"):
                    raise MaintenanceError("The database inside this backup is not a WiFiGuard database.")
            except sqlite3.DatabaseError as exc:
                raise MaintenanceError(f"The database inside this backup cannot be opened: {exc}") from None
            finally:
                conn.close()
            safety = None
            if db_path.is_file():
                safety = backup(database, instance_dir, prefix="wifiguard-pre-restore")["path"]
            for sidecar in (f"{database}-wal", f"{database}-shm"):
                Path(sidecar).unlink(missing_ok=True)
            try:
                os.replace(staged, db_path)
            except PermissionError:
                raise MaintenanceError("The database file is in use. Stop WiFiGuard (and anything else using it), "
                                       "then try again.") from None
            restored_runs = 0
            target = Path(instance_dir) / "evaluation"
            for member in evaluation:
                destination = target / Path(member).name
                if destination.exists():
                    continue
                target.mkdir(parents=True, exist_ok=True)
                destination.write_bytes(archive.read(member))
                restored_runs += 1
    return {"manifest": manifest, "safetyBackup": safety, "evaluationRunsRestored": restored_runs}
