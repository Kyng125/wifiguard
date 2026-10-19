"""Devices and access points: merge observed and authorised data and derive status.

Derived at read time (never stored): device status, Offline, vendor, IP (from ARP), AP status and the
reason an AP is a suspected rogue. Lists are built in Python, which is fine for a small institution.
"""
from datetime import timedelta

from .. import db, timeutil
from ..errors import ApiError
from ..validators import invalid
from . import oui
from . import settings as st


def _recent(ts: str | None, minutes: int) -> bool:
    return ts is not None and timeutil.parse(ts) >= timeutil.now() - timedelta(minutes=minutes)


def ap_labels() -> dict:
    labels = {}
    for r in db.rows("SELECT bssid, ssid FROM observed_access_points"):
        labels[r["bssid"]] = r["ssid"] or r["bssid"]
    for r in db.rows("SELECT bssid, ssid, description FROM authorised_access_points"):
        labels[r["bssid"]] = r["description"] or r["ssid"]
    return labels


# ------------------------------------------------------------------ devices

def _device(mac: str, obs: dict | None, auth: dict | None, ip: str | None, labels: dict) -> dict:
    if auth:
        status = "authorised"
    elif obs and obs["review_state"] == "under_review":
        status = "under_review"
    else:
        status = "unrecognised"
    last_seen = obs["last_seen"] if obs else None
    bssid = obs["associated_bssid"] if obs else None
    return {
        "macAddress": mac,
        "ownerLabel": auth["owner_label"] if auth else None,
        "deviceType": auth["device_type"] if auth else None,
        "ip": ip,
        "vendor": oui.vendor(mac),
        "firstSeen": obs["first_seen"] if obs else None,
        "lastSeen": last_seen,
        "associatedBssid": bssid,
        "accessPoint": labels.get(bssid) if bssid else None,
        "status": status,
        "active": _recent(last_seen, st.get_int("active_window_minutes")),
        "offline": not _recent(last_seen, st.get_int("offline_after_minutes")),
    }


def all_devices() -> list[dict]:
    observed = {r["mac_address"]: r for r in db.rows("SELECT * FROM observed_devices")}
    authorised = {r["mac_address"]: r for r in db.rows("SELECT * FROM authorised_devices")}
    ips = {}
    for r in db.rows("SELECT mac_address, ip_address FROM arp_bindings ORDER BY last_seen ASC, id ASC"):
        ips[r["mac_address"]] = r["ip_address"]  # later (more recent) rows win
    labels = ap_labels()
    return [_device(mac, observed.get(mac), authorised.get(mac), ips.get(mac), labels) for mac in {*observed, *authorised}]


def find_device(mac: str) -> dict:
    for d in all_devices():
        if d["macAddress"] == mac:
            return d
    raise ApiError(404, "not_found", "Device not found.")


def filter_devices(items: list[dict], status: str | None, q: str | None) -> list[dict]:
    if status == "offline":
        items = [d for d in items if d["offline"]]
    elif status:
        items = [d for d in items if d["status"] == status]
    if q:
        needle = q.lower()
        items = [
            d for d in items
            if any(needle in str(d[k] or "").lower() for k in ("macAddress", "ownerLabel", "ip", "vendor", "accessPoint"))
        ]
    return sorted(items, key=lambda d: d["lastSeen"] or "", reverse=True)


def devices_summary(items: list[dict]) -> dict:
    return {
        "total": len(items),
        "active": sum(1 for d in items if d["active"]),
        "observed24h": sum(1 for d in items if _recent(d["lastSeen"], 24 * 60)),
        "authorised": sum(1 for d in items if d["status"] == "authorised"),
        "unrecognised": sum(1 for d in items if d["status"] == "unrecognised"),
        "underReview": sum(1 for d in items if d["status"] == "under_review"),
        "discoveredLast24h": sum(1 for d in items if _recent(d["firstSeen"], 24 * 60)),
    }


# ------------------------------------------------------------ access points

def all_access_points() -> list[dict]:
    observed = {r["bssid"]: r for r in db.rows("SELECT * FROM observed_access_points")}
    authorised = {r["bssid"]: r for r in db.rows("SELECT * FROM authorised_access_points")}
    known_ssids: dict[str, dict] = {}
    institutional = st.get("institutional_ssid")
    if institutional:
        known_ssids[institutional] = {"modes": set(), "channels": set()}
    for a in authorised.values():
        entry = known_ssids.setdefault(a["ssid"], {"modes": set(), "channels": set()})
        if a["security_mode"]:
            entry["modes"].add(a["security_mode"])
        if a["channel"]:
            entry["channels"].add(a["channel"])
    out = []
    for bssid in {*observed, *authorised}:
        obs, auth = observed.get(bssid), authorised.get(bssid)
        ssid = (obs or auth)["ssid"]
        channel = obs["channel"] if obs and obs["channel"] else (auth["channel"] if auth else None)
        mode = obs["security_mode"] if obs and obs["security_mode"] else (auth["security_mode"] if auth else None)
        last_seen = obs["last_seen"] if obs else None
        reason = None
        if auth:
            status = "authorised" if _recent(last_seen, st.get_int("ap_offline_after_minutes")) else "offline"
        elif obs and obs["status_override"] == "neighbouring":
            status = "neighbouring"
        elif ssid in known_ssids:
            status = "suspected_rogue"
            reason = "Known SSID from an unknown BSSID"
            known = known_ssids[ssid]
            if mode and known["modes"] and mode not in known["modes"]:
                reason += f"; security differs from the authorised {'/'.join(sorted(known['modes']))}"
            if channel and known["channels"] and channel not in known["channels"]:
                reason += f"; channel {channel} is not used by authorised access points"
        else:
            status = "neighbouring"
        out.append({
            "ssid": ssid,
            "bssid": bssid,
            "channel": channel,
            "securityMode": mode,
            "signal": obs["signal_strength"] if obs else None,
            "firstSeen": obs["first_seen"] if obs else None,
            "lastSeen": last_seen,
            "status": status,
            "authorised": auth is not None,
            "location": auth["description"] if auth else None,
            "reason": reason,
        })
    return out


def find_access_point(bssid: str) -> dict:
    for ap in all_access_points():
        if ap["bssid"] == bssid:
            return ap
    raise ApiError(404, "not_found", "Access point not found.")


def filter_access_points(items: list[dict], status: str | None, q: str | None) -> list[dict]:
    if status:
        items = [a for a in items if a["status"] == status]
    if q:
        needle = q.lower()
        items = [a for a in items if any(needle in str(a[k] or "").lower() for k in ("ssid", "bssid", "location"))]
    order = {"suspected_rogue": 0, "authorised": 1, "offline": 2, "neighbouring": 3}
    return sorted(items, key=lambda a: (order[a["status"]], a["ssid"] or "", a["bssid"]))


def access_points_summary(items: list[dict]) -> dict:
    return {
        "total": len(items),
        "authorised": sum(1 for a in items if a["authorised"]),
        "suspectedRogue": sum(1 for a in items if a["status"] == "suspected_rogue"),
        "neighbouring": sum(1 for a in items if a["status"] == "neighbouring"),
        "offline": sum(1 for a in items if a["status"] == "offline"),
    }


# ----------------------------------------------------- authorising access points
# Shared by the API and the command line so both behave identically.

def authorise_access_point(ssid: str, bssid: str, channel: int | None = None,
                           security_mode: str | None = None, location: str | None = None) -> dict:
    """Add one access point to the authorised list. 409 if it is already there."""
    if db.row("SELECT 1 FROM authorised_access_points WHERE bssid = ?", (bssid,)):
        raise ApiError(409, "already_authorised", "This access point is already authorised.", {"field": "bssid"})
    db.get_db().execute(
        "INSERT INTO authorised_access_points (ssid, bssid, channel, security_mode, description, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?)", (ssid, bssid, channel, security_mode, location, timeutil.iso()))
    db.get_db().commit()
    return find_access_point(bssid)


def plan_bulk_authorisation(ssids: list[str] | None = None, bssids: list[str] | None = None) -> dict:
    """Decide which observed access points a bulk "authorise" would adopt. Changes nothing.

    Scope: the BSSIDs given, plus every observed access point advertising one of the SSIDs given. With neither,
    the scope is the institutional SSID, so neighbouring networks are never swept in by accident.

    Safety rule: while no access point is authorised yet (first-time setup) every in-scope access point is adopted,
    which trusts whatever is on air at that moment. Once at least one is authorised, an in-scope access point that
    is a suspected rogue (a known SSID from an unrecognised BSSID) is skipped, and so is one marked neighbouring.
    Naming a BSSID explicitly is a deliberate choice and is always adopted.
    """
    explicit = {b for b in (bssids or [])}
    scope = {s for s in (ssids or []) if s}
    if not explicit and not scope:
        institutional = st.get("institutional_ssid")
        if institutional:
            scope = {institutional}
    if not explicit and not scope:
        raise invalid("ssids", "Set the institutional network name in Settings, or say which networks to authorise.")
    access_points = all_access_points()
    first_time = not any(a["authorised"] for a in access_points)
    neighbouring = {r["bssid"] for r in db.rows(
        "SELECT bssid FROM observed_access_points WHERE status_override = 'neighbouring'")}
    chosen, skipped = [], []
    for ap in access_points:
        if ap["authorised"]:
            continue
        if ap["bssid"] in explicit:
            chosen.append(ap)
        elif ap["ssid"] and ap["ssid"] in scope:
            if ap["bssid"] in neighbouring:
                skipped.append({**ap, "skipReason": "marked as a neighbouring network"})
            elif not first_time and ap["status"] == "suspected_rogue":
                skipped.append({**ap, "skipReason": "suspected rogue: known network name from an unrecognised BSSID"})
            else:
                chosen.append(ap)
    unknown = sorted(explicit - {a["bssid"] for a in access_points})
    return {"chosen": chosen, "skipped": skipped, "firstTime": first_time, "scope": sorted(scope), "unknownBssids": unknown}


def authorise_planned(chosen: list[dict]) -> int:
    stamp = timeutil.iso()
    conn = db.get_db()
    for ap in chosen:
        conn.execute(
            "INSERT INTO authorised_access_points (ssid, bssid, channel, security_mode, created_at) VALUES (?, ?, ?, ?, ?)",
            (ap["ssid"] or "", ap["bssid"], ap["channel"], ap["securityMode"], stamp))
        conn.execute("UPDATE observed_access_points SET status_override = NULL WHERE bssid = ?", (ap["bssid"],))
    conn.commit()
    return len(chosen)


def remove_authorised_access_point(bssid: str) -> None:
    cur = db.get_db().execute("DELETE FROM authorised_access_points WHERE bssid = ?", (bssid,))
    db.get_db().commit()
    if not cur.rowcount:
        raise ApiError(404, "not_found", "That access point is not on the authorised list.")
