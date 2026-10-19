"""Configuration from environment variables, with safe local defaults.

Everything a deployment needs to change is an environment variable (documented in README and docs/deployment.md).
Problems that would make the server unsafe or unable to start raise ConfigError with a message that says what to do.
"""
import logging
import os
import secrets
import stat
from pathlib import Path

log = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
MIN_SECRET_KEY_LENGTH = 32
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}


class ConfigError(RuntimeError):
    """A setting is missing, malformed or unsafe. The message is written for the person running the server."""


# --------------------------------------------------------------------------------------------- environment helpers

def _flag(name: str) -> bool | None:
    """True/False when the variable is set to a recognisable value, None when unset."""
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return None
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be 1 or 0, not '{raw}'.")


def _int(name: str, default: int, minimum: int = 0) -> int:
    raw = os.environ.get(name)
    if raw is None or raw.strip() == "":
        return default
    try:
        value = int(raw)
    except ValueError:
        raise ConfigError(f"{name} must be a whole number, not '{raw}'.") from None
    if value < minimum:
        raise ConfigError(f"{name} must be at least {minimum}.")
    return value


# ------------------------------------------------------------------------------------------------------- secret key

def new_secret_key() -> str:
    return secrets.token_hex(32)


def _checked(key: str, where: str) -> str:
    key = key.strip()
    if len(key) < MIN_SECRET_KEY_LENGTH:
        raise ConfigError(
            f"The secret key in {where} is too short ({len(key)} characters; at least {MIN_SECRET_KEY_LENGTH} are needed). "
            "Generate one with:  python -c \"import secrets; print(secrets.token_hex(32))\"")
    return key


def _write_new_key_file(path: Path, key: str) -> None:
    """Create the file readable only by its owner from the first byte (no moment where it is world-readable).
    On Windows the mode bits are ignored; the file inherits the folder's permissions, see docs/deployment.md."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(key + "\n")


def secret_key_source() -> str:
    """Where the key comes from: 'env', 'file-env' or 'instance'. Used by rotate-secret-key to know what it may change."""
    if os.environ.get("WIFIGUARD_SECRET_KEY"):
        return "env"
    if os.environ.get("WIFIGUARD_SECRET_KEY_FILE"):
        return "file-env"
    return "instance"


def _secret_key(instance_dir: Path) -> str:
    """The key that signs session cookies. In order: WIFIGUARD_SECRET_KEY, the file named by WIFIGUARD_SECRET_KEY_FILE,
    instance/secret_key (created on first run). It is never written to a log, a response or a backup."""
    env = os.environ.get("WIFIGUARD_SECRET_KEY")
    key_path = os.environ.get("WIFIGUARD_SECRET_KEY_FILE")
    if env and key_path:
        raise ConfigError("Set only one of WIFIGUARD_SECRET_KEY and WIFIGUARD_SECRET_KEY_FILE.")
    if env:
        return _checked(env, "WIFIGUARD_SECRET_KEY")
    if key_path:
        try:
            return _checked(Path(key_path).read_text(), key_path)
        except OSError as exc:
            raise ConfigError(f"WIFIGUARD_SECRET_KEY_FILE points to {key_path}, which cannot be read: {exc.strerror}.") from None
    instance_dir.mkdir(parents=True, exist_ok=True)
    key_file = instance_dir / "secret_key"
    try:
        _write_new_key_file(key_file, new_secret_key())
    except FileExistsError:
        pass                                    # created earlier, or by a process that started a moment before this one
    if os.name == "posix" and key_file.stat().st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        key_file.chmod(0o600)
        log.warning("%s was readable by other users; it is now restricted to its owner.", key_file)
    return _checked(key_file.read_text(), str(key_file))


def rotate_secret_key(instance_dir: Path) -> None:
    """Replace instance/secret_key with a fresh key. Everyone is signed out, because old cookies no longer verify."""
    if secret_key_source() != "instance":
        raise ConfigError("The secret key is supplied by an environment variable or key file, not by instance/secret_key. "
                          "Change the value there instead.")
    instance_dir.mkdir(parents=True, exist_ok=True)
    target = instance_dir / "secret_key"
    staging = instance_dir / "secret_key.new"
    staging.unlink(missing_ok=True)
    _write_new_key_file(staging, new_secret_key())
    os.replace(staging, target)


# ------------------------------------------------------------------------------------------------------------ main

def load_config(overrides: dict | None = None) -> dict:
    instance_dir = Path(os.environ.get("WIFIGUARD_INSTANCE", BASE_DIR / "instance"))
    tls_cert = os.environ.get("WIFIGUARD_TLS_CERT") or None
    tls_key = os.environ.get("WIFIGUARD_TLS_KEY") or None
    if bool(tls_cert) != bool(tls_key):
        raise ConfigError("Set both WIFIGUARD_TLS_CERT and WIFIGUARD_TLS_KEY, or neither.")
    secure_cookie = _flag("WIFIGUARD_COOKIE_SECURE")
    cfg = {
        "INSTANCE_DIR": str(instance_dir),
        "DATABASE": os.environ.get("WIFIGUARD_DB", str(instance_dir / "wifiguard.db")),
        "HOST": os.environ.get("WIFIGUARD_HOST", "127.0.0.1"),
        "PORT": _int("WIFIGUARD_PORT", 5000, 1),
        "FRONTEND_DIST": os.environ.get("WIFIGUARD_FRONTEND_DIST", str(BASE_DIR / "frontend" / "dist")),
        # Recorded scenarios replayed by the engine (docs/engine.md). Drop your own .pcap files in here to replay them.
        "REPLAY_DIR": os.environ.get("WIFIGUARD_REPLAY_DIR", str(BASE_DIR / "samples" / "pcaps")),
        # --- transport security (docs/deployment.md)
        "TLS_CERT": tls_cert,
        "TLS_KEY": tls_key,
        # Number of reverse proxies in front of the server whose X-Forwarded-* headers to believe (0 = none).
        "TRUST_PROXY": _int("WIFIGUARD_TRUST_PROXY", 0),
        # Strict-Transport-Security max-age in seconds, sent only on HTTPS responses. 0 (default) = not sent.
        "HSTS_SECONDS": _int("WIFIGUARD_HSTS_SECONDS", 0),
        "SESSION_COOKIE_NAME": "wifiguard_session",
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        # Unset: the cookie is marked Secure exactly when the server itself terminates TLS. Set 1 behind an HTTPS proxy.
        "SESSION_COOKIE_SECURE": bool(tls_cert) if secure_cookie is None else secure_cookie,
        "SECURE_COOKIE_EXPLICIT": secure_cookie is not None,
        "LOGIN_MAX_FAILURES": 5,                  # per address and username
        "LOGIN_MAX_FAILURES_PER_ADDRESS": 20,     # per address, whatever name is tried
        "LOGIN_LOCKOUT_SECONDS": 300,
        "MIN_PASSWORD_LENGTH": 8,
        "CONTENT_SECURITY_POLICY": os.environ.get(
            "WIFIGUARD_CSP",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
            "font-src 'self' data: https://fonts.gstatic.com; frame-ancestors 'none'",
        ),
    }
    if overrides:
        cfg.update(overrides)
    if "SECRET_KEY" not in cfg:
        cfg["SECRET_KEY"] = _secret_key(Path(cfg["INSTANCE_DIR"]))
    return cfg


def tls_enabled(cfg: dict) -> bool:
    return bool(cfg.get("TLS_CERT") and cfg.get("TLS_KEY"))


def is_loopback(host: str) -> bool:
    return host in LOOPBACK_HOSTS


def apply_tls(cfg: dict, cert: str | None, key: str | None) -> None:
    """Use a certificate given on the command line (run.py --cert/--key). Same rule as the environment variables."""
    if not (cert or key):
        return
    if not (cert and key):
        raise ConfigError("Give both --cert and --key, or neither.")
    cfg["TLS_CERT"], cfg["TLS_KEY"] = cert, key
    if not cfg.get("SECURE_COOKIE_EXPLICIT"):
        cfg["SESSION_COOKIE_SECURE"] = True


def check_tls_files(cfg: dict) -> None:
    """Fail early, with a plain message, if the certificate or key cannot be read."""
    for label, path in (("certificate", cfg.get("TLS_CERT")), ("private key", cfg.get("TLS_KEY"))):
        if path and not os.path.isfile(path):
            raise ConfigError(f"The TLS {label} file was not found: {path}")
    if os.name == "posix" and cfg.get("TLS_KEY") and os.stat(cfg["TLS_KEY"]).st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        log.warning("The TLS private key %s is readable by other users. Run: chmod 600 %s", cfg["TLS_KEY"], cfg["TLS_KEY"])


def deployment_warnings(cfg: dict) -> list[str]:
    """Things that are legal but unsafe for the way the server is being run. Printed at start-up and by check-config."""
    out = []
    host, tls, proxies = cfg["HOST"], tls_enabled(cfg), cfg["TRUST_PROXY"]
    if not is_loopback(host) and not tls and not proxies:
        out.append(f"Listening on {host} over plain HTTP: the administrator's password and session cookie cross the network "
                   "unencrypted. Configure TLS (WIFIGUARD_TLS_CERT and WIFIGUARD_TLS_KEY) or put an HTTPS reverse proxy in front.")
    if proxies and not is_loopback(host):
        out.append(f"WIFIGUARD_TRUST_PROXY is set but the server listens on {host}. Anyone who can reach it directly can forge "
                   "X-Forwarded-For and defeat the login lockout. Bind to 127.0.0.1 so only the proxy can connect.")
    if proxies and not cfg["SESSION_COOKIE_SECURE"]:
        out.append("Behind a proxy but the session cookie is not marked Secure. Set WIFIGUARD_COOKIE_SECURE=1 once the proxy serves HTTPS.")
    if tls and not cfg["SESSION_COOKIE_SECURE"]:
        out.append("TLS is on but WIFIGUARD_COOKIE_SECURE=0 sends the session cookie over any connection. Remove that setting.")
    if (tls or proxies) and not cfg["HSTS_SECONDS"]:
        out.append("HSTS is off (WIFIGUARD_HSTS_SECONDS=0). Turn it on (31536000) once the certificate is real and stable; "
                   "a browser remembers it for that long, for every port on this host name.")
    return out

