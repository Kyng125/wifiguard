"""Start WiFiGuard: the API, the dashboard, and (optionally) the replayed detection engine, in one process.

    python run.py                  API and dashboard only
    python run.py --demo           load the demo data if the database is empty, create the administrator if there
                                   is none, then replay normal activity so the dashboard is alive
    python run.py --replay NAME    start the engine replaying scenario NAME in the background (see docs/engine.md)
    python run.py --production     serve with a production-grade server (needs requirements-production.txt); refuses to
                                   listen on the network without TLS or a trusted proxy (see docs/deployment.md)
    python run.py --cert F --key F serve over HTTPS with this certificate (make one with: flask --app wifiguard make-cert)

Works the same on Windows, macOS and Linux; nothing here needs administrator rights or a wireless adapter.
Keep it to a single process: the engine thread lives inside it, and a second process would analyse every frame twice.
The built-in server suits one administrator on a lab or demo machine; see README for hardening notes.
"""
import argparse
import getpass
import os
import sys

if sys.version_info < (3, 10):
    sys.exit(f"WiFiGuard needs Python 3.10 or newer; this is {sys.version.split()[0]}.")

from wifiguard import config as cfgmod, create_app, db, maintenance, security  # noqa: E402
from wifiguard.services import engine_control  # noqa: E402

try:
    app = create_app()
except cfgmod.ConfigError as exc:
    sys.exit(f"Configuration problem: {exc}")


def ensure_admin() -> bool:
    """Make sure someone can sign in. Returns False if no administrator exists and none could be created."""
    conn = db.connect(app.config["DATABASE"])
    try:
        if conn.execute("SELECT COUNT(*) FROM admin_users").fetchone()[0]:
            return True
        username = os.environ.get("WIFIGUARD_ADMIN_USER")
        password = os.environ.get("WIFIGUARD_ADMIN_PASSWORD")
        if not (username and password):
            if not sys.stdin.isatty():
                print("No administrator exists yet. Set WIFIGUARD_ADMIN_USER and WIFIGUARD_ADMIN_PASSWORD, "
                      "or run: flask --app wifiguard create-admin")
                return False
            print("\nFirst run: create the administrator account for the dashboard.")
            username = input("Username [admin]: ").strip() or "admin"
            minimum = app.config["MIN_PASSWORD_LENGTH"]
            while True:
                password = getpass.getpass(f"Password (at least {minimum} characters): ")
                if len(password) < minimum:
                    print(f"Too short, use at least {minimum} characters.")
                elif password != getpass.getpass("Repeat the password: "):
                    print("The passwords did not match.")
                else:
                    break
        security.create_admin(conn, username, password)
        print(f"Administrator '{username}' created.")
        return True
    finally:
        conn.close()


def load_demo_data() -> None:
    from wifiguard.seed_demo import seed
    with app.app_context():
        try:
            counts = seed(reset=False)
        except RuntimeError:
            print("The database already has data, so the demo dataset was not loaded. "
                  "The bundled scenarios are written for the demo dataset; use "
                  "'flask --app wifiguard seed-demo --reset' to replace your data with it.")
        else:
            print("Demo data loaded: " + ", ".join(f"{k}={v}" for k, v in counts.items()))


def serve(production: bool, threads: int) -> None:
    """Run the web server until Ctrl+C. Production mode uses cheroot (pure Python, so it works on Windows too)."""
    cfg = app.config
    host, port, tls = cfg["HOST"], cfg["PORT"], cfgmod.tls_enabled(cfg)
    cfgmod.check_tls_files(cfg)
    for warning in cfgmod.deployment_warnings(cfg):
        print(f"Warning: {warning}\n", file=sys.stderr)
    open_to_network = not cfgmod.is_loopback(host)
    if production and open_to_network and not tls and not cfg["TRUST_PROXY"] and os.environ.get("WIFIGUARD_ALLOW_HTTP") != "1":
        sys.exit(f"Refusing to serve plain HTTP on {host} in production mode. Use --cert and --key (or WIFIGUARD_TLS_CERT and "
                 "WIFIGUARD_TLS_KEY), or set WIFIGUARD_TRUST_PROXY=1 behind an HTTPS reverse proxy. "
                 "WIFIGUARD_ALLOW_HTTP=1 overrides this on a network you fully control.")
    scheme = "https" if tls else "http"
    maintenance.write_pidfile(cfg["INSTANCE_DIR"])
    print(f"\nWiFiGuard is running at {scheme}://{host}:{port}  (Ctrl+C to stop)\n")
    if not production:
        ssl_context = (cfg["TLS_CERT"], cfg["TLS_KEY"]) if tls else None
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True, ssl_context=ssl_context)
        return
    try:
        from cheroot.wsgi import Server
    except ImportError:
        sys.exit("Production mode needs the cheroot package. Run: pip install -r requirements-production.txt")
    server = Server((host, port), app, numthreads=threads, server_name="WiFiGuard")
    server.max_request_body_size = 1024 * 1024        # the API only ever receives small JSON bodies
    if tls:
        import ssl
        from cheroot.ssl.builtin import BuiltinSSLAdapter
        adapter = BuiltinSSLAdapter(cfg["TLS_CERT"], cfg["TLS_KEY"])
        adapter.context.minimum_version = ssl.TLSVersion.TLSv1_2
        server.ssl_adapter = adapter
    try:
        server.start()
    except KeyboardInterrupt:
        pass
    finally:
        server.stop()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--demo", action="store_true", help="load demo data if empty and replay normal activity")
    parser.add_argument("--replay", metavar="NAME", help="start replaying this scenario in the background")
    parser.add_argument("--production", action="store_true", help="serve with cheroot instead of Flask's development server")
    parser.add_argument("--cert", metavar="FILE", help="TLS certificate (PEM); with --key serves HTTPS")
    parser.add_argument("--key", metavar="FILE", help="TLS private key (PEM)")
    parser.add_argument("--threads", type=int, default=10, help="production mode: request-handling threads (default 10)")
    args = parser.parse_args()
    try:
        cfgmod.apply_tls(app.config, args.cert, args.key)
    except cfgmod.ConfigError as exc:
        sys.exit(str(exc))

    background = args.replay or ("baseline" if args.demo else None)
    if args.demo:
        if not ensure_admin():
            sys.exit(1)
        load_demo_data()
    if background:
        runtime = engine_control.get_runtime(app)
        try:
            runtime.start(background, loop=True, speed=1.0)
        except KeyError:
            names = ", ".join(s["id"] for s in runtime.scenarios())
            sys.exit(f"No scenario called '{background}' in {app.config['REPLAY_DIR']}. Available: {names or 'none'}.")
        except ImportError:
            sys.exit("Replay needs the scapy package. Run: pip install -r requirements.txt")
        print(f"Engine replaying '{background}'. Trigger attacks from the API: POST /api/engine/trigger.")
    try:
        serve(args.production, args.threads)
    except cfgmod.ConfigError as exc:
        sys.exit(str(exc))

if __name__ == "__main__":
    main()
