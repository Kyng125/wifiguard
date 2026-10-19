from wifiguard import security


def test_ping_is_public(anon):
    assert anon.get("/api/ping").get_json() == {"ok": True}


def test_endpoints_require_login(anon):
    for path in ("/api/alerts", "/api/devices", "/api/overview", "/api/settings", "/api/auth/session"):
        r = anon.get(path)
        assert r.status_code == 401, path
        assert r.get_json()["error"]["code"] == "unauthenticated"


def test_unknown_api_path_is_json_404(anon):
    r = anon.get("/api/nope")
    assert r.status_code == 404 and r.get_json()["error"]["code"] == "not_found"


def test_login_success_and_session(anon):
    r = anon.login()
    assert r.status_code == 200 and r.get_json() == {"user": {"username": "admin"}}
    assert anon.get("/api/auth/session").get_json()["user"]["username"] == "admin"
    cookie = r.headers["Set-Cookie"]
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie


def test_login_failure_is_generic(anon):
    for user, pw in (("admin", "wrong-pass"), ("nobody", "whatever1")):
        r = anon.login(user, pw)
        assert r.status_code == 401 and r.get_json()["error"]["code"] == "invalid_credentials"


def test_login_lockout_after_repeated_failures(anon):
    for _ in range(3):
        assert anon.login("admin", "bad-bad-bad").status_code == 401
    r = anon.login("admin", "correct-horse")  # even the right password is refused while locked
    assert r.status_code == 429 and "Retry-After" in r.headers
    assert r.get_json()["error"]["details"]["retryAfterSeconds"] > 0


def test_logout_ends_session(api):
    assert api.post("/api/auth/logout").status_code == 200
    assert api.get("/api/auth/session").status_code == 401


def test_mutations_need_the_client_header(app, api):
    raw = app.test_client()
    raw.post("/api/auth/login", json={"username": "admin", "password": "correct-horse"}, headers=security_header())
    r = raw.post("/api/auth/logout")  # no custom header
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "csrf_header_missing"


def security_header():
    return {security.CLIENT_HEADER: "1"}


def test_change_password(api):
    assert api.post("/api/auth/password", {"currentPassword": "nope", "newPassword": "new-password-1"}).status_code == 403
    assert api.post("/api/auth/password", {"currentPassword": "correct-horse", "newPassword": "short"}).status_code == 422
    assert api.post("/api/auth/password", {"currentPassword": "correct-horse", "newPassword": "new-password-1"}).status_code == 200
    api.post("/api/auth/logout")
    assert api.login(password="correct-horse").status_code == 401
    assert api.login(password="new-password-1").status_code == 200


def test_error_shape_has_no_internals(api):
    r = api.post("/api/alerts/EV-0001/notes", {"text": ""})
    body = r.get_json()
    assert set(body) == {"error"} and "traceback" not in str(body).lower()
