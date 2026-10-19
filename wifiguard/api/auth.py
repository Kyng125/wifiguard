from flask import g, jsonify, session

from .. import db, security, timeutil
from ..errors import ApiError
from ..services import settings as st
from ..validators import json_body, text
from . import bp


@bp.post("/auth/login")
def login():
    data = json_body()
    username = text(data, "username", 64)
    password = data.get("password")
    if not isinstance(password, str) or not password:
        raise ApiError(422, "validation_error", "Password is required.", {"field": "password"})
    keys = security.throttle_keys(username)
    wait = security.lockout_remaining(keys)
    if wait:
        resp = jsonify({"error": {"code": "too_many_attempts", "message": "Too many failed sign-ins. Try again later.",
                                  "details": {"retryAfterSeconds": wait}}})
        resp.status_code = 429
        resp.headers["Retry-After"] = str(wait)
        return resp
    user = security.verify_login(username, password)
    if not user:
        security.record_failure(keys)
        raise ApiError(401, "invalid_credentials", "Incorrect username or password.")
    security.clear_failures(keys)
    security.start_session(user, st.get_int("session_timeout_minutes"))
    db.get_db().execute("UPDATE admin_users SET last_login_at = ? WHERE id = ?", (timeutil.iso(), user["id"]))
    db.get_db().commit()
    return {"user": {"username": user["username"]}}


@bp.post("/auth/logout")
def logout():
    session.clear()
    return {"ok": True}


@bp.get("/auth/session")
def get_session():
    return {"user": {"username": g.user["username"]}}


@bp.post("/auth/password")
def change_password():
    data = json_body()
    current = data.get("currentPassword")
    new = security.validate_password(data.get("newPassword"))
    user = security.verify_login(g.user["username"], current if isinstance(current, str) else "")
    if not user:
        raise ApiError(403, "invalid_credentials", "Current password is incorrect.")
    security.create_admin(db.get_db(), user["username"], new, reset=True)
    return {"ok": True}
