"""Authentication helpers: password hashing, login throttling, CSRF header check, session guard."""
import time
from datetime import timedelta

from flask import current_app, g, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from . import db, timeutil
from .errors import ApiError
from .validators import invalid

CLIENT_HEADER = "X-WifiGuard-Client"
# Used to equalise timing when the username does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


def _now() -> float:
    """Wall-clock seconds. Failures are stored in the database, so the clock must mean the same thing after a restart."""
    return time.time()


def throttle_keys(username: str) -> list[tuple[str, int]]:
    """The counters one sign-in attempt feeds, each with its limit: this address trying this name, and this address
    trying anything. The second stops one machine from walking through many usernames."""
    ip = request.remote_addr or "unknown"
    cfg = current_app.config
    return [(f"{ip}|{username.lower()}", cfg["LOGIN_MAX_FAILURES"]), (ip, cfg["LOGIN_MAX_FAILURES_PER_ADDRESS"])]


def lockout_remaining(keys: list[tuple[str, int]]) -> int:
    """Seconds until sign-in is allowed again for these counters (0 when it is allowed now)."""
    window = current_app.config["LOGIN_LOCKOUT_SECONDS"]
    now = _now()
    conn = db.get_db()
    wait = 0.0
    for key, limit in keys:
        times = [r[0] for r in conn.execute(
            "SELECT at FROM login_failures WHERE key = ? AND at > ? ORDER BY at", (key, now - window))]
        if len(times) >= limit:
            # the lock lifts when enough old failures have aged out to bring the count below the limit
            wait = max(wait, times[len(times) - limit] + window - now)
    return int(wait) + 1 if wait > 0 else 0


def record_failure(keys: list[tuple[str, int]]) -> None:
    conn = db.get_db()
    now = _now()
    conn.executemany("INSERT INTO login_failures (key, at) VALUES (?, ?)", [(key, now) for key, _limit in keys])
    conn.execute("DELETE FROM login_failures WHERE at < ?", (now - current_app.config["LOGIN_LOCKOUT_SECONDS"],))
    conn.commit()


def clear_failures(keys: list[tuple[str, int]]) -> None:
    """A correct password clears the counter for that address and name. The address-wide counter is left to age out."""
    conn = db.get_db()
    conn.execute("DELETE FROM login_failures WHERE key = ?", (keys[0][0],))
    conn.commit()


def clear_all_failures(conn) -> int:
    """Unlock every address (flask unlock-login). Takes a plain connection so the command can run without a request."""
    cur = conn.execute("DELETE FROM login_failures")
    conn.commit()
    return cur.rowcount


def validate_password(password) -> str:
    minimum = current_app.config["MIN_PASSWORD_LENGTH"]
    if not isinstance(password, str) or len(password) < minimum:
        raise invalid("password", f"Password must be at least {minimum} characters.")
    if len(password) > 128:
        raise invalid("password", "Password must be at most 128 characters.")
    return password


def create_admin(conn, username: str, password: str, reset: bool = False) -> None:
    existing = conn.execute("SELECT id FROM admin_users WHERE username = ? COLLATE NOCASE", (username,)).fetchone()
    hashed = generate_password_hash(password)
    if existing and not reset:
        raise ValueError("That administrator already exists. Use --reset to change the password.")
    if existing:
        conn.execute("UPDATE admin_users SET password_hash = ? WHERE id = ?", (hashed, existing["id"]))
    else:
        conn.execute(
            "INSERT INTO admin_users (username, password_hash, created_at) VALUES (?, ?, ?)",
            (username, hashed, timeutil.iso()),
        )
    conn.commit()


def verify_login(username: str, password: str) -> dict | None:
    user = db.row("SELECT * FROM admin_users WHERE username = ? COLLATE NOCASE", (username,))
    ok = check_password_hash(user["password_hash"] if user else _DUMMY_HASH, password)
    return user if (user and ok) else None


def start_session(user: dict, timeout_minutes: int) -> None:
    session.clear()
    session["uid"] = user["id"]
    session.permanent = True
    current_app.permanent_session_lifetime = timedelta(minutes=timeout_minutes)


def require_client_header() -> None:
    """CSRF defence: mutating requests must carry a custom header, which a cross-site form cannot set
    and a cross-origin script cannot send without a CORS preflight (CORS is not enabled)."""
    if request.method not in ("GET", "HEAD", "OPTIONS") and request.headers.get(CLIENT_HEADER) != "1":
        raise ApiError(403, "csrf_header_missing", f"Missing required header {CLIENT_HEADER}: 1.")


def require_login() -> None:
    uid = session.get("uid")
    user = db.row("SELECT id, username FROM admin_users WHERE id = ?", (uid,)) if uid else None
    if not user:
        session.clear()
        raise ApiError(401, "unauthenticated", "Sign in required.")
    g.user = user
