"""Runtime state written by the engine runtime (replay mode now; live capture later) and read by the API."""
from datetime import timedelta

from .. import db, timeutil
from . import engine_control
from . import settings as st

STALE_AFTER_SECONDS = 30


def latest_snapshot() -> dict | None:
    return db.row("SELECT * FROM monitor_snapshots ORDER BY id DESC LIMIT 1")


SERIES_POINTS = 13


def packet_series(points: int = SERIES_POINTS) -> list[int]:
    """Recent packets-per-second readings, oldest first, for the dashboard sparkline."""
    rows = db.rows("SELECT packets_per_sec FROM monitor_snapshots ORDER BY id DESC LIMIT ?", (points,))
    return [r["packets_per_sec"] for r in reversed(rows)]


def state() -> dict:
    snap = latest_snapshot()
    fresh = bool(snap) and timeutil.parse(snap["at"]) >= timeutil.now() - timedelta(seconds=STALE_AFTER_SECONDS)
    if not snap:
        engine = monitor = arp = "unknown"
    elif fresh:
        engine, monitor, arp = snap["engine_state"], snap["monitor_state"], snap["arp_state"]
    else:
        engine, monitor, arp = "stopped", "unknown", "unknown"
    return {"snapshot": snap, "fresh": fresh, "engine": engine, "monitor": monitor, "arp": arp}


def warnings() -> list[dict]:
    """Setup problems that make the engine silent or noisy. Shown on the Dashboard and in `flask engine-status`."""
    out = []
    authorised_aps = db.scalar("SELECT COUNT(*) FROM authorised_access_points")
    if not authorised_aps:
        out.append({
            "code": "no_authorised_aps", "severity": "warning",
            "message": "No access point is authorised yet. The unrecognised-device rule is inactive because there is no "
                       "network of yours to watch, and every access point advertising your network name will raise a "
                       "rogue-access-point alert. Authorise your access points first.",
        })
    elif st.get_bool("rule.unauthorised_device.enabled") and not db.scalar("SELECT COUNT(*) FROM observed_devices") \
            and not db.scalar("SELECT COUNT(*) FROM authorised_devices"):
        out.append({
            "code": "no_device_baseline", "severity": "info",
            "message": "No clients have been seen yet. The first time each client appears on your access points it raises "
                       "an unrecognised-device alert, so expect one alert per client until you authorise them.",
        })
    return out


def status() -> dict:
    s = state()
    snap = s["snapshot"] or {}
    channels = [int(c) for c in st.get("channels").split(",")]
    runtime = engine_control.existing_runtime()
    replay = runtime.status() if runtime else None
    replaying = bool(replay and replay["running"] and s["fresh"])
    if replaying:
        playing = [replay["background"]] if replay["background"] else []
        playing += [n for n in replay["triggered"] if n not in playing]
        label = "replay: " + (", ".join(playing) or "idle")
        monitor_name, arp_name, mode = label, "replay: ARP", "replay"
        source = {"kind": "replay", "background": replay["background"], "triggered": replay["triggered"],
                  "loop": replay["loop"], "speed": replay["speed"]}
    else:
        monitor_name, arp_name, mode = st.get("monitor_interface"), st.get("arp_interface"), None
        source = {"kind": "none"}
    return {
        "sources": [
            {"name": monitor_name, "role": "monitor", "mode": mode or "monitor", "state": s["monitor"],
             "channel": snap.get("current_channel") if s["fresh"] else None},
            {"name": arp_name, "role": "arp", "mode": mode or "managed", "state": s["arp"], "channel": None},
        ],
        "detectionEngine": s["engine"],
        "packetsCaptured": snap.get("packets_total", 0),
        "packetsPerSecond": snap.get("packets_per_sec", 0) if s["fresh"] else 0,
        "frameMix": {
            "management": snap.get("mgmt_count", 0),
            "data": snap.get("data_count", 0),
            "arp": snap.get("arp_count", 0),
        },
        "channels": channels,
        "channelMode": st.get("channel_mode"),
        "updatedAt": snap.get("at"),
        "source": source,
        "warnings": warnings(),
    }


def feed(since_id: int, limit: int) -> dict:
    items = db.rows(
        "SELECT id, at, frame_type, subtype, source, destination, bssid, channel, flag_event_id "
        "FROM frame_samples WHERE id > ? ORDER BY id DESC LIMIT ?", (since_id, limit),
    )
    from .events import display_id
    out = [{
        "id": r["id"], "time": r["at"], "type": r["frame_type"], "subtype": r["subtype"], "source": r["source"],
        "destination": r["destination"], "bssid": r["bssid"], "channel": r["channel"],
        "flag": display_id(r["flag_event_id"]) if r["flag_event_id"] else None,
    } for r in items]
    return {"items": out, "lastId": max([r["id"] for r in items], default=since_id)}
