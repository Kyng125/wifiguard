"""Input validation helpers. Every failure raises ApiError(422/400) with a field name."""
import re
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from flask import request

from .errors import ApiError

MAC_RE = re.compile(r"^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.-]{1,15}$")

ALERT_STATUSES = ("new", "investigating", "resolved", "false_positive")
SEVERITIES = ("critical", "high", "medium", "info")
CATEGORIES = ("deauth_flood", "arp_conflict", "rogue_ap", "unauthorised_device")
SECURITY_MODES = ("Open", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3", "Unknown")
SCENARIOS = (
    "normal_baseline",
    "deauth",
    "arp_conflict",
    "rogue_ap",
    "unknown_device",
)


def invalid(field: str, message: str, status: int = 422) -> ApiError:
    return ApiError(status, "validation_error", message, {"field": field})


def json_body() -> dict:
    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        raise ApiError(400, "invalid_json", "Request body must be a JSON object.")
    return data


def normalise_mac(value, field: str = "macAddress", allow_multicast: bool = False) -> str:
    if not isinstance(value, str) or not MAC_RE.match(value.strip()):
        raise invalid(field, "Must be a MAC address like AA:BB:CC:DD:EE:FF.")
    mac = value.strip().upper().replace("-", ":")
    if not allow_multicast and int(mac[:2], 16) & 1:
        raise invalid(field, "Multicast and broadcast addresses cannot be used here.")
    return mac


def is_randomised(mac: str) -> bool:
    """Locally administered bit set: typical of randomised (private) addresses."""
    return bool(int(mac[:2], 16) & 2)


def text(data: dict, name: str, max_len: int, required: bool = True, default: str | None = None):
    value = data.get(name, default)
    if value is None or (isinstance(value, str) and value.strip() == ""):
        if required:
            raise invalid(name, "This field is required.")
        return default
    if not isinstance(value, str):
        raise invalid(name, "Must be text.")
    value = value.strip()
    if len(value) > max_len:
        raise invalid(name, f"Must be at most {max_len} characters.")
    return value


def integer(value, name: str, low: int, high: int) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)) or int(value) != value:
        raise invalid(name, "Must be a whole number.")
    value = int(value)
    if not low <= value <= high:
        raise invalid(name, f"Must be between {low} and {high}.")
    return value


def one_of(value, name: str, allowed: tuple):
    if value not in allowed:
        raise invalid(name, f"Must be one of: {', '.join(allowed)}.")
    return value


def interface_name(value, name: str) -> str:
    if not isinstance(value, str) or not IFACE_RE.match(value):
        raise invalid(name, "Must be a valid interface name (letters, digits, _ . -; max 15).")
    return value


def timezone_name(value, name: str = "timezone") -> str:
    try:
        ZoneInfo(value)
    except (ZoneInfoNotFoundError, ValueError, TypeError, OSError):
        raise invalid(name, "Must be a valid IANA time zone, e.g. Africa/Lagos.")
    return value


def channel_list(value, name: str = "channels") -> str:
    """Accepts '6' or '1,6,11'; returns a normalised comma list."""
    if isinstance(value, list):
        parts = value
    elif isinstance(value, str):
        parts = [p for p in value.replace(" ", "").split(",") if p]
    else:
        parts = []
    if not parts:
        raise invalid(name, "At least one channel is required.")
    out = []
    for part in parts:
        try:
            ch = int(part)
        except (TypeError, ValueError):
            raise invalid(name, "Channels must be whole numbers.")
        if not 1 <= ch <= 177:
            raise invalid(name, "Channels must be between 1 and 177.")
        if ch not in out:
            out.append(ch)
    if len(out) > 12:
        raise invalid(name, "At most 12 channels.")
    return ",".join(str(c) for c in out)


def page_params(default_size: int = 25, max_size: int = 100) -> tuple[int, int]:
    try:
        page = int(request.args.get("page", 1))
        size = int(request.args.get("pageSize", default_size))
    except ValueError:
        raise invalid("page", "page and pageSize must be whole numbers.", 400)
    if page < 1 or size < 1 or size > max_size:
        raise invalid("pageSize", f"page must be >= 1 and pageSize 1-{max_size}.", 400)
    return page, size
