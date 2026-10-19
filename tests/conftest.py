import pytest

from wifiguard import create_app, db, security
from wifiguard.seed_demo import seed

HEADER = {"X-WifiGuard-Client": "1"}


class Api:
    """Test client that sends the required CSRF header and parses JSON."""

    def __init__(self, app):
        self.app = app
        self.client = app.test_client()

    def _call(self, method, path, **kw):
        headers = {**HEADER, **kw.pop("headers", {})}
        return getattr(self.client, method)(path, headers=headers, **kw)

    def get(self, path, **kw): return self._call("get", path, **kw)
    def post(self, path, json=None, **kw): return self._call("post", path, json=json, **kw)
    def put(self, path, json=None, **kw): return self._call("put", path, json=json, **kw)
    def patch(self, path, json=None, **kw): return self._call("patch", path, json=json, **kw)
    def delete(self, path, **kw): return self._call("delete", path, **kw)

    def login(self, username="admin", password="correct-horse"):
        return self.post("/api/auth/login", {"username": username, "password": password})


@pytest.fixture
def app(tmp_path):
    app = create_app({
        "DATABASE": str(tmp_path / "test.db"), "INSTANCE_DIR": str(tmp_path), "SECRET_KEY": "test-key",
        "TESTING": True, "FRONTEND_DIST": str(tmp_path / "no-dist"), "LOGIN_MAX_FAILURES": 3,
    })
    conn = db.connect(app.config["DATABASE"])
    security.create_admin(conn, "admin", "correct-horse")
    conn.close()
    return app


@pytest.fixture
def api(app):
    client = Api(app)
    assert client.login().status_code == 200
    return client


@pytest.fixture
def anon(app):
    return Api(app)


@pytest.fixture
def seeded(app, api):
    with app.app_context():
        seed(reset=True)
    return api
