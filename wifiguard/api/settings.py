from datetime import timedelta

from flask import current_app

from ..services import settings as st
from ..validators import (channel_list, integer, interface_name, invalid, json_body, one_of, text, timezone_name)
from . import bp


def _view() -> dict:
    s = st.get_all()
    return {
        "general": {"systemName": s["system_name"], "institutionalSsid": s["institutional_ssid"],
                    "timezone": s["timezone"], "refreshIntervalSeconds": int(s["refresh_interval_seconds"])},
        "monitoring": {"monitorInterface": s["monitor_interface"], "arpInterface": s["arp_interface"],
                       "channels": [int(c) for c in s["channels"].split(",")], "channelMode": s["channel_mode"],
                       "channelDwellMs": int(s["channel_dwell_ms"])},
        "alerts": {"severityByCategory": {k.split(".", 1)[1]: v for k, v in s.items() if k.startswith("severity.")}},
        "security": {"sessionTimeoutMinutes": int(s["session_timeout_minutes"])},
        "data": {"retentionDays": int(s["retention_days"])},
    }


# group -> key -> (setting name, validator). Anything not listed here is rejected, which includes the
# read-only `alerts` group (severities are fixed in this version).
def _name(v, key):
    return text({"v": v}, "v", 60 if key == "systemName" else 32)


EDITABLE = {
    "general": {
        "systemName": ("system_name", lambda v, k: _name(v, k)),
        "institutionalSsid": ("institutional_ssid", lambda v, k: _name(v, k)),
        "timezone": ("timezone", lambda v, k: timezone_name(v)),
        "refreshIntervalSeconds": ("refresh_interval_seconds", lambda v, k: integer(v, k, 2, 60)),
    },
    "monitoring": {
        "monitorInterface": ("monitor_interface", lambda v, k: interface_name(v, k)),
        "arpInterface": ("arp_interface", lambda v, k: interface_name(v, k)),
        "channels": ("channels", lambda v, k: channel_list(v)),
        "channelMode": ("channel_mode", lambda v, k: one_of(v, k, ("locked", "hopping"))),
        "channelDwellMs": ("channel_dwell_ms", lambda v, k: integer(v, k, 100, 2000)),
    },
    "security": {
        "sessionTimeoutMinutes": ("session_timeout_minutes", lambda v, k: integer(v, k, 5, 480)),
    },
    "data": {
        "retentionDays": ("retention_days", lambda v, k: integer(v, k, 1, 365)),
    },
}


@bp.get("/settings")
def get_settings():
    return _view()


@bp.put("/settings")
def save_settings():
    """Partial update using the same nested shape that GET returns, e.g.
    {"general": {"timezone": "Africa/Lagos"}, "monitoring": {"channels": [1, 6, 11]}}."""
    data = json_body()
    updates = {}
    for group, values in data.items():
        if group not in EDITABLE:
            raise invalid(group, "Unknown or read-only settings group.")
        if not isinstance(values, dict) or not values:
            raise invalid(group, "Must be an object with at least one setting.")
        for key, value in values.items():
            if key not in EDITABLE[group]:
                raise invalid(f"{group}.{key}", "Unknown setting.")
            name, check = EDITABLE[group][key]
            updates[name] = check(value, key)
    if not updates:
        raise invalid("body", "Nothing to update.")
    merged_mode = updates.get("channel_mode", st.get("channel_mode"))
    merged_channels = updates.get("channels", st.get("channels"))
    if merged_mode == "hopping" and len(merged_channels.split(",")) < 2:
        raise invalid("monitoring.channels", "Channel hopping needs at least two channels.")
    st.set_many(updates)
    if "session_timeout_minutes" in updates:
        current_app.permanent_session_lifetime = timedelta(minutes=int(updates["session_timeout_minutes"]))
    return _view()
