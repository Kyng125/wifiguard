from flask import request

from .. import db, timeutil
from ..errors import ApiError
from ..services import events, inventory
from ..services import settings as st
from ..validators import (SECURITY_MODES, integer, invalid, json_body, normalise_mac, one_of, text)
from . import bp


def _bssid(value) -> str:
    return normalise_mac(value, "bssid")


@bp.get("/access-points")
def list_access_points():
    items = inventory.all_access_points()
    status = request.args.get("status")
    if status and status not in ("authorised", "suspected_rogue", "neighbouring", "offline"):
        raise invalid("status", "Unknown status.", 400)
    return {"items": inventory.filter_access_points(items, status, request.args.get("q")),
            "summary": inventory.access_points_summary(items)}


@bp.post("/access-points/authorised")
def add_authorised_ap():
    data = json_body()
    ssid = text(data, "ssid", 32)
    bssid = normalise_mac(data.get("bssid"), "bssid")
    channel = integer(data["channel"], "channel", 1, 177) if data.get("channel") is not None else None
    mode = one_of(data["securityMode"], "securityMode", SECURITY_MODES) if data.get("securityMode") else None
    location = text(data, "location", 80, required=False)
    return inventory.authorise_access_point(ssid, bssid, channel, mode, location), 201


@bp.post("/access-points/authorise-all")
def authorise_all_access_points():
    """Bulk-authorise observed access points. Optional body: {"ssids": [...], "bssids": [...]}.

    Without a body the scope is the institutional SSID only (never neighbouring networks). See
    inventory.plan_bulk_authorisation for the safety rule. Returns {authorised, skipped}.
    """
    data = request.get_json(silent=True) or {}
    ssids = data.get("ssids") or []
    bssids = data.get("bssids") or []
    if not isinstance(ssids, list) or not all(isinstance(s, str) and len(s) <= 32 for s in ssids):
        raise invalid("ssids", "ssids must be a list of network names (32 characters at most).")
    if not isinstance(bssids, list):
        raise invalid("bssids", "bssids must be a list of MAC addresses.")
    bssids = [normalise_mac(b, "bssids") for b in bssids]
    plan = inventory.plan_bulk_authorisation(ssids, bssids)
    return {"authorised": inventory.authorise_planned(plan["chosen"]), "skipped": len(plan["skipped"])}


@bp.delete("/access-points/authorised/<bssid>")
def remove_authorised_ap(bssid):
    inventory.remove_authorised_access_point(_bssid(bssid))
    return {"ok": True}


@bp.get("/access-points/<bssid>")
def get_access_point(bssid):
    ap = inventory.find_access_point(_bssid(bssid))
    devices = [d for d in inventory.all_devices() if d["associatedBssid"] == ap["bssid"]]
    related = db.rows("SELECT * FROM security_events WHERE bssid = ? ORDER BY event_time DESC LIMIT 20", (ap["bssid"],))
    ap["devices"] = sorted(devices, key=lambda d: d["lastSeen"] or "", reverse=True)
    ap["events"] = [events.serialise(r) for r in related]
    return ap


@bp.patch("/access-points/<bssid>")
def update_access_point(bssid):
    bssid = _bssid(bssid)
    ap = inventory.find_access_point(bssid)
    status = one_of(json_body().get("status"), "status", ("authorised", "neighbouring"))
    conn = db.get_db()
    if status == "authorised":
        if not ap["authorised"]:
            conn.execute(
                "INSERT INTO authorised_access_points (ssid, bssid, channel, security_mode, created_at) VALUES (?, ?, ?, ?, ?)",
                (ap["ssid"] or "", bssid, ap["channel"], ap["securityMode"], timeutil.iso()))
        conn.execute("UPDATE observed_access_points SET status_override = NULL WHERE bssid = ?", (bssid,))
    else:
        if ap["authorised"]:
            raise ApiError(409, "ap_is_authorised",
                           "Remove the access point from the authorised list first.")
        conn.execute("UPDATE observed_access_points SET status_override = 'neighbouring' WHERE bssid = ?", (bssid,))
    conn.commit()
    return inventory.find_access_point(bssid)


@bp.get("/topology")
def topology():
    aps = inventory.all_access_points()
    devices = [d for d in inventory.all_devices() if d["associatedBssid"]]
    return {
        "network": st.get("institutional_ssid"),
        "accessPoints": [{k: a[k] for k in ("ssid", "bssid", "status", "location", "channel")} for a in aps],
        "devices": [{k: d[k] for k in ("macAddress", "ownerLabel", "status", "associatedBssid", "offline")} for d in devices],
    }
