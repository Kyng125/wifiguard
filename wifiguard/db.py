"""SQLite access. One connection per request; WAL mode so the capture side can write while Flask reads."""
import sqlite3
from pathlib import Path

from flask import current_app, g

from . import timeutil
from .defaults import DEFAULT_SETTINGS

SCHEMA_VERSION = 1


def connect(path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    conn.execute("PRAGMA busy_timeout = 5000")
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    return conn


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect(current_app.config["DATABASE"])
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db(conn: sqlite3.Connection) -> None:
    """Create tables and insert missing default settings. Safe to run repeatedly."""
    schema = (Path(__file__).parent / "schema.sql").read_text()
    conn.executescript(schema)
    stored = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()[0]
    if stored is None:
        conn.execute("INSERT INTO schema_version (version) VALUES (?)", (SCHEMA_VERSION,))
    elif stored > SCHEMA_VERSION:
        # Going back to older code after an upgrade: refuse rather than let it misread or damage newer data.
        raise RuntimeError(f"This database was written by a newer WiFiGuard (schema {stored}; this version understands "
                           f"{SCHEMA_VERSION}). Install the newer version, or restore a backup made before the upgrade.")
    stamp = timeutil.iso()
    conn.executemany(
        "INSERT OR IGNORE INTO system_settings (setting_name, setting_value, updated_at) VALUES (?, ?, ?)",
        [(k, v, stamp) for k, v in DEFAULT_SETTINGS.items()],
    )
    conn.commit()


def rows(sql: str, args=()) -> list[dict]:
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def row(sql: str, args=()) -> dict | None:
    r = get_db().execute(sql, args).fetchone()
    return dict(r) if r else None


def scalar(sql: str, args=()):
    r = get_db().execute(sql, args).fetchone()
    return r[0] if r else None
