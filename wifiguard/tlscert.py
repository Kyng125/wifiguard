"""Self-signed certificate for a lab deployment (`flask --app wifiguard make-cert`).

A self-signed certificate encrypts the connection but nobody vouches for it, so browsers warn on first visit. That is
acceptable for a lab machine you control if you compare the fingerprint this prints; for anything else use a certificate
from a real authority (docs/deployment.md). Needs the optional `cryptography` package (requirements-production.txt).
"""
import datetime
import ipaddress
import os
from pathlib import Path

from .config import ConfigError

VALID_DAYS = 365


def _names(hosts: list[str]):
    from cryptography import x509
    names, seen = [], set()
    for host in ["localhost", "127.0.0.1", *hosts]:
        if host in seen:
            continue
        seen.add(host)
        try:
            names.append(x509.IPAddress(ipaddress.ip_address(host)))
        except ValueError:
            names.append(x509.DNSName(host))
    return names


def make_self_signed(folder: str, hosts: list[str], force: bool = False) -> dict:
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509.oid import NameOID
    except ImportError:
        raise ConfigError("Making a certificate needs the cryptography package: pip install -r requirements-production.txt "
                          "(or use openssl; see docs/deployment.md).") from None
    out = Path(folder)
    cert_path, key_path = out / "wifiguard.crt", out / "wifiguard.key"
    if (cert_path.exists() or key_path.exists()) and not force:
        raise ConfigError(f"{cert_path} or {key_path} already exists. Use --force to replace them.")
    out.mkdir(parents=True, exist_ok=True)

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, hosts[0] if hosts else "localhost"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "WiFiGuard (self-signed)")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=VALID_DAYS))
            .add_extension(x509.SubjectAlternativeName(_names(hosts)), critical=False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))

    key_pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    key_path.unlink(missing_ok=True)
    fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)      # owner-only from the first byte
    with os.fdopen(fd, "wb") as handle:
        handle.write(key_pem)
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    fingerprint = cert.fingerprint(hashes.SHA256()).hex(":").upper()
    return {"cert": str(cert_path), "key": str(key_path), "fingerprint": fingerprint,
            "expires": (now + datetime.timedelta(days=VALID_DAYS)).date().isoformat(),
            "names": [n.value if hasattr(n, "value") and not isinstance(n.value, ipaddress._BaseAddress) else str(n.value)
                      for n in _names(hosts)]}
