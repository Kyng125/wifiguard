from flask import g, request

from .. import db, timeutil
from ..errors import ApiError
from ..services import events, inventory
from ..validators import json_body, normalise_mac, one_of, page_params, text
from . import bp

DEVICE_TYPES = ("laptop", "phone", "tablet", "desktop", "printer", "iot", "other")


def _mac(value) -> str:
    return normalise_mac(value, "mac")


@bp.get("/devices")
def list_devices():
    page, size = page_params()
    items = inventory.all_devices()
    summary = inventory.devices_summary(items)
    filtered = inventory.filter_devices(items, request.args.get("status"), request.args.get("q"))
    start = (page - 1) * size
    return {"items": filtered[start:start + size], "total": len(filtered), "page": page, "pageSize": size,
            "summary": summary}


@bp.post("/devices/authorised")
def add_authorised_device():
    data = json_body()
    mac = normalise_mac(data.get("macAddress"))
    owner = text(data, "ownerLabel", 80, required=False)
    device_type = data.get("deviceType")
    if device_type is not None:
        one_of(device_type, "deviceType", DEVICE_TYPES)
    if db.row("SELECT 1 FROM authorised_devices WHERE mac_address = ?", (mac,)):
        raise ApiError(409, "already_authorised", "This device is already authorised.", {"field": "macAddress"})
    db.get_db().execute(
        "INSERT INTO authorised_devices (mac_address, owner_label, device_type, created_at) VALUES (?, ?, ?, ?)",
        (mac, owner, device_type, timeutil.iso()))
    db.get_db().execute("UPDATE observed_devices SET review_state = 'none' WHERE mac_address = ?", (mac,))
    db.get_db().commit()
    return inventory.find_device(mac), 201


@bp.post("/devices/authorise-all")
def authorise_all_devices():
    stamp = timeutil.iso()
    cur = db.get_db().execute(
        "INSERT INTO authorised_devices (mac_address, owner_label, created_at) "
        "SELECT mac_address, NULL, ? FROM observed_devices "
        "WHERE mac_address NOT IN (SELECT mac_address FROM authorised_devices)", (stamp,))
    db.get_db().execute("UPDATE observed_devices SET review_state = 'none'")
    db.get_db().commit()
    return {"authorised": cur.rowcount}


@bp.delete("/devices/authorised/<mac>")
def remove_authorised_device(mac):
    mac = _mac(mac)
    cur = db.get_db().execute("DELETE FROM authorised_devices WHERE mac_address = ?", (mac,))
    db.get_db().commit()
    if not cur.rowcount:
        raise ApiError(404, "not_found", "That device is not on the authorised list.")
    return {"ok": True}


@bp.get("/devices/<mac>")
def get_device(mac):
    device = inventory.find_device(_mac(mac))
    notes = db.rows("SELECT text, author, created_at FROM device_notes WHERE mac_address = ? ORDER BY id DESC",
                    (device["macAddress"],))
    related = db.rows(
        "SELECT * FROM security_events WHERE source = ? OR target = ? ORDER BY event_time DESC LIMIT 20",
        (device["macAddress"], device["macAddress"]))
    device["notes"] = [{"text": n["text"], "author": n["author"], "at": n["created_at"]} for n in notes]
    device["events"] = [events.serialise(r) for r in related]
    return device


@bp.patch("/devices/<mac>")
def update_device(mac):
    mac = _mac(mac)
    device = inventory.find_device(mac)
    status = one_of(json_body().get("status"), "status", ("authorised", "under_review", "unrecognised"))
    conn = db.get_db()
    if status == "authorised":
        if device["status"] != "authorised":
            conn.execute("INSERT INTO authorised_devices (mac_address, created_at) VALUES (?, ?)", (mac, timeutil.iso()))
        conn.execute("UPDATE observed_devices SET review_state = 'none' WHERE mac_address = ?", (mac,))
    else:
        if device["status"] == "authorised":
            raise ApiError(409, "device_is_authorised",
                           "Remove the device from the authorised list first (DELETE /api/devices/authorised/<mac>).")
        conn.execute("UPDATE observed_devices SET review_state = ? WHERE mac_address = ?",
                     ("under_review" if status == "under_review" else "none", mac))
    conn.commit()
    return inventory.find_device(mac)


@bp.post("/devices/<mac>/notes")
def add_device_note(mac):
    mac = _mac(mac)
    inventory.find_device(mac)
    db.get_db().execute(
        "INSERT INTO device_notes (mac_address, text, author, created_at) VALUES (?, ?, ?, ?)",
        (mac, text(json_body(), "text", 1000), g.user["username"], timeutil.iso()))
    db.get_db().commit()
    return get_device(mac), 201
