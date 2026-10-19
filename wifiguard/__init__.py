"""WiFiGuard backend: Flask JSON API over SQLite for the wireless intrusion detection dashboard."""
__version__ = "1.5.1"

from datetime import timedelta
from pathlib import Path

from flask import Flask, jsonify, request, send_from_directory
from werkzeug.middleware.proxy_fix import ProxyFix

from . import db
from .config import load_config
from .errors import register_error_handlers


def create_app(overrides: dict | None = None) -> Flask:
    app = Flask(__name__, static_folder=None)
    app.config.update(load_config(overrides))
    Path(app.config["DATABASE"]).parent.mkdir(parents=True, exist_ok=True)
    if app.config["TRUST_PROXY"]:
        # Believe X-Forwarded-For/-Proto/-Host from this many proxies, so the login lockout sees the real client address
        # and the Secure cookie and HSTS logic see the real scheme. Only safe when the proxy is the sole way in.
        n = app.config["TRUST_PROXY"]
        app.wsgi_app = ProxyFix(app.wsgi_app, x_for=n, x_proto=n, x_host=n)

    conn = db.connect(app.config["DATABASE"])
    try:
        db.init_db(conn)
        row = conn.execute("SELECT setting_value FROM system_settings WHERE setting_name = 'session_timeout_minutes'").fetchone()
        app.permanent_session_lifetime = timedelta(minutes=int(row[0]))
    finally:
        conn.close()

    app.teardown_appcontext(db.close_db)
    register_error_handlers(app)

    from .api import bp
    app.register_blueprint(bp)

    from . import cli
    cli.register(app)

    @app.after_request
    def _security_headers(resp):
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "no-referrer")
        resp.headers.setdefault("Content-Security-Policy", app.config["CONTENT_SECURITY_POLICY"])
        if app.config["HSTS_SECONDS"] and request.is_secure:
            resp.headers.setdefault("Strict-Transport-Security", f"max-age={app.config['HSTS_SECONDS']}")
        if resp.mimetype == "application/json":
            resp.headers.setdefault("Cache-Control", "no-store")
        return resp

    # Serve the built React frontend (single-page app) when present.
    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def frontend(path):
        dist = Path(app.config["FRONTEND_DIST"])
        if not dist.is_dir():
            return jsonify({"message": "WiFiGuard API is running. The frontend has not been built into "
                                       f"{dist}. See README."}), 200
        target = (dist / path).resolve()
        if path and target.is_file() and dist.resolve() in target.parents:
            return send_from_directory(dist, path)
        return send_from_directory(dist, "index.html")

    return app
