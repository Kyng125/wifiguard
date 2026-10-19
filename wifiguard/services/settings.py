"""Typed access to system_settings."""
from .. import db, timeutil
from ..defaults import DEFAULT_SETTINGS


def get(name: str) -> str:
    value = db.scalar("SELECT setting_value FROM system_settings WHERE setting_name = ?", (name,))
    return value if value is not None else DEFAULT_SETTINGS[name]


def get_int(name: str) -> int:
    return int(get(name))


def get_bool(name: str) -> bool:
    return get(name) == "1"


def get_all() -> dict:
    values = dict(DEFAULT_SETTINGS)
    values.update({r["setting_name"]: r["setting_value"] for r in db.rows("SELECT setting_name, setting_value FROM system_settings")})
    return values


def set_many(mapping: dict) -> None:
    conn = db.get_db()
    stamp = timeutil.iso()
    conn.executemany(
        "INSERT INTO system_settings (setting_name, setting_value, updated_at) VALUES (?, ?, ?) "
        "ON CONFLICT(setting_name) DO UPDATE SET setting_value = excluded.setting_value, updated_at = excluded.updated_at",
        [(k, str(v), stamp) for k, v in mapping.items()],
    )
    conn.commit()


def rule_params(rule_id: str) -> dict:
    out = {"enabled": get_bool(f"rule.{rule_id}.enabled"), "cooldownSeconds": get_int(f"rule.{rule_id}.cooldown_seconds")}
    if rule_id == "deauth":
        out["threshold"] = get_int("rule.deauth.threshold")
        out["windowSeconds"] = get_int("rule.deauth.window_seconds")
    return out
