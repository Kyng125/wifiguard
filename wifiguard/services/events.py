"""Alert/event manager: severity, cool-down merging, timeline, querying and serialisation.

Detection (Phase 2) never writes to the database directly; it hands a match to create_event().
"""
import json
import re
from datetime import datetime, timedelta, timezone
from zoneinfo import ZoneInfo

from .. import db, timeutil
from ..defaults import CATEGORY_TO_RULE
from ..errors import ApiError
from ..validators import ALERT_STATUSES, CATEGORIES, SEVERITIES, invalid, normalise_mac
from . import settings as st

OPEN_STATUSES = ("new", "investigating")

# The evidence object is part of the API contract: these keys must be present for each category.
# (Extra keys are allowed.) Detection rules in Phase 2 must produce exactly these.
REQUIRED_EVIDENCE = {
    "deauth_flood": ("frameCount", "windowSeconds", "threshold"),
    "arp_conflict": ("ip", "previousMac", "newMac"),
    "rogue_ap": ("ssid", "channel", "securityMode"),
    "unauthorised_device": ("associatedBssid",),
}


def display_id(event_id: int) -> str:
    return f"EV-{event_id:04d}"


def parse_event_id(value) -> int:
    match = re.fullmatch(r"(?:EV-)?(\d{1,9})", str(value).strip(), re.IGNORECASE)
    if not match:
        raise ApiError(404, "not_found", "Alert not found.")
    return int(match.group(1))


def add_log(event_id: int, kind: str, text: str, actor: str | None = None, at: str | None = None) -> None:
    db.get_db().execute(
        "INSERT INTO event_log (event_id, at, kind, text, actor) VALUES (?, ?, ?, ?, ?)",
        (event_id, at or timeutil.iso(), kind, text, actor),
    )


def create_event(
    *,
    category: str,
    description: str,
    source: str | None = None,
    target: str | None = None,
    evidence: dict | None = None,
    ssid: str | None = None,
    bssid: str | None = None,
    channel: int | None = None,
    dedupe_key: str | None = None,
    cooldown_seconds: int | None = None,
    event_time: str | None = None,
    severity: str | None = None,
    status: str = "new",
    event_id: int | None = None,
    occurrences: int = 1,
    last_seen: str | None = None,
    timeline: list | None = None,
    commit: bool = True,
) -> tuple[int, bool]:
    """Create an alert, or merge into an equivalent open one inside the cool-down.

    Returns (event_id, created). `timeline` is a list of (kind, text, at) tuples.
    """
    if category not in CATEGORIES:
        raise ValueError(f"unknown category {category}")
    missing = [k for k in REQUIRED_EVIDENCE[category] if k not in (evidence or {})]
    if missing:
        raise ValueError(f"{category} evidence is missing required keys: {', '.join(missing)}")
    conn = db.get_db()
    rule_id = CATEGORY_TO_RULE[category]
    if cooldown_seconds is None:
        cooldown_seconds = st.get_int(f"rule.{rule_id}.cooldown_seconds")
    key = dedupe_key or f"{category}:{source or ''}"
    stamp = event_time or timeutil.iso()

    if cooldown_seconds > 0 and event_id is None:
        cutoff = timeutil.iso(timeutil.now() - timedelta(seconds=cooldown_seconds))
        existing = db.row(
            "SELECT id, evidence, occurrences FROM security_events WHERE dedupe_key = ? AND last_seen >= ? "
            "AND status IN ('new','investigating') ORDER BY last_seen DESC LIMIT 1",
            (key, cutoff),
        )
        if existing:
            merged = json.loads(existing["evidence"] or "{}")
            merged.update(evidence or {})
            now_stamp = timeutil.iso()
            conn.execute(
                "UPDATE security_events SET occurrences = occurrences + 1, last_seen = ?, evidence = ? WHERE id = ?",
                (now_stamp, json.dumps(merged), existing["id"]),
            )
            add_log(existing["id"], "merged", f"Repeated within the {cooldown_seconds}-second cool-down; merged into this alert.", at=now_stamp)
            if commit:
                conn.commit()
            return existing["id"], False

    severity = severity or st.get(f"severity.{category}")
    if severity not in SEVERITIES:
        raise ValueError(f"unknown severity {severity}")
    columns = (
        "event_time, category, severity, source, target, description, evidence, status, ssid, bssid, channel, "
        "rule, occurrences, first_seen, last_seen, dedupe_key"
    )
    values = [
        stamp, category, severity, source, target, description, json.dumps(evidence or {}), status, ssid, bssid,
        channel, rule_id, occurrences, stamp, last_seen or stamp, key,
    ]
    if event_id is not None:
        columns = "id, " + columns
        values = [event_id] + values
    cur = conn.execute(f"INSERT INTO security_events ({columns}) VALUES ({','.join('?' * len(values))})", values)
    new_id = event_id if event_id is not None else cur.lastrowid
    for kind, text, at in timeline or [
        ("detected", "Event started", stamp),
        ("generated", "Alert generated", stamp),
    ]:
        add_log(new_id, kind, text, at=at)
    if commit:
        conn.commit()
    return new_id, True


# ---------------------------------------------------------------- querying

def _local_bound(value: str, end: bool) -> str:
    """Date-only bounds are interpreted in the configured time zone; others as given (UTC if naive)."""
    tz = ZoneInfo(st.get("timezone"))
    try:
        if len(value) == 10:
            local = datetime.fromisoformat(value).replace(tzinfo=tz)
            if end:
                local = local + timedelta(days=1) - timedelta(milliseconds=1)
            return timeutil.iso(local)
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise invalid("from/to", "Dates must be YYYY-MM-DD or ISO date-times.", 400)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return timeutil.iso(parsed)


def _csv_list(value: str | None, allowed: tuple, field: str) -> list[str]:
    if not value:
        return []
    items = [v.strip() for v in value.split(",") if v.strip()]
    for item in items:
        if item not in allowed:
            raise invalid(field, f"Must be one of: {', '.join(allowed)}.", 400)
    return items


def build_filters(args) -> tuple[str, list]:
    clauses, params = [], []
    status = args.get("status")
    if status == "open":
        statuses = list(OPEN_STATUSES)
    else:
        statuses = _csv_list(status, ALERT_STATUSES, "status")
    if statuses:
        clauses.append(f"status IN ({','.join('?' * len(statuses))})")
        params += statuses
    severities = _csv_list(args.get("severity"), SEVERITIES, "severity")
    if severities:
        clauses.append(f"severity IN ({','.join('?' * len(severities))})")
        params += severities
    categories = _csv_list(args.get("category"), CATEGORIES, "category")
    if categories:
        clauses.append(f"category IN ({','.join('?' * len(categories))})")
        params += categories
    q = (args.get("q") or "").strip()
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        cols = ["source", "target", "ssid", "bssid", "description", "category", "'EV-' || printf('%04d', id)"]
        clauses.append("(" + " OR ".join(f"{c} LIKE ? ESCAPE '\\'" for c in cols) + ")")
        params += [like] * len(cols)
    if args.get("from"):
        clauses.append("event_time >= ?")
        params.append(_local_bound(args["from"], end=False))
    if args.get("to"):
        clauses.append("event_time <= ?")
        params.append(_local_bound(args["to"], end=True))
    if args.get("bssid"):
        clauses.append("bssid = ?")
        params.append(normalise_mac(args["bssid"], "bssid", allow_multicast=True))
    if args.get("source"):
        clauses.append("(source = ? OR target = ?)")
        params += [args["source"], args["source"]]
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


def query_events(args, page: int | None = None, size: int | None = None) -> tuple[list[dict], int]:
    where, params = build_filters(args)
    total = db.scalar(f"SELECT COUNT(*) FROM security_events{where}", params)
    sql = f"SELECT * FROM security_events{where} ORDER BY event_time DESC, id DESC"
    if page and size:
        sql += " LIMIT ? OFFSET ?"
        params = params + [size, (page - 1) * size]
    return db.rows(sql, params), total


def serialise(row: dict) -> dict:
    return {
        "id": display_id(row["id"]),
        "time": row["event_time"],
        "category": row["category"],
        "severity": row["severity"],
        "status": row["status"],
        "source": row["source"],
        "target": row["target"],
        "ssid": row["ssid"],
        "bssid": row["bssid"],
        "channel": row["channel"],
        "description": row["description"],
        "evidence": json.loads(row["evidence"] or "{}"),
        "rule": row["rule"],
        "occurrences": row["occurrences"],
        "firstSeen": row["first_seen"],
        "lastSeen": row["last_seen"],
        "resolvedAt": row["resolved_at"],
    }


def get_event(event_id: int) -> dict:
    row = db.row("SELECT * FROM security_events WHERE id = ?", (event_id,))
    if not row:
        raise ApiError(404, "not_found", "Alert not found.")
    return row


def detail(event_id: int) -> dict:
    out = serialise(get_event(event_id))
    log = db.rows("SELECT at, kind, text, actor FROM event_log WHERE event_id = ? ORDER BY at, id", (event_id,))
    out["timeline"] = [e for e in log if e["kind"] != "note"]
    out["notes"] = [{"at": e["at"], "text": e["text"], "actor": e["actor"]} for e in log if e["kind"] == "note"]
    where, params = "WHERE id != ? AND (", [event_id]
    keys = []
    if out["bssid"]:
        keys.append("bssid = ?")
        params.append(out["bssid"])
    if out["source"]:
        keys.append("source = ?")
        params.append(out["source"])
    related = []
    if keys:
        related = db.rows(
            f"SELECT id FROM security_events {where}{' OR '.join(keys)}) ORDER BY event_time DESC LIMIT 20", params
        )
    out["relatedIds"] = [display_id(r["id"]) for r in related]
    return out


def set_status(event_id: int, status: str, actor: str, note: str | None = None) -> None:
    event = get_event(event_id)
    if status not in ALERT_STATUSES:
        raise invalid("status", f"Must be one of: {', '.join(ALERT_STATUSES)}.")
    conn = db.get_db()
    if event["status"] != status:
        resolved_at = timeutil.iso() if status in ("resolved", "false_positive") else None
        conn.execute("UPDATE security_events SET status = ?, resolved_at = ? WHERE id = ?", (status, resolved_at, event_id))
        add_log(event_id, "status", f"Status changed from {event['status']} to {status}", actor)
    if note:
        add_log(event_id, "note", note, actor)
    conn.commit()


def add_note(event_id: int, text: str, actor: str) -> None:
    get_event(event_id)
    add_log(event_id, "note", text, actor)
    db.get_db().commit()


# ---------------------------------------------------------------- statistics

RANGES = {
    "1h": (timedelta(hours=1), timedelta(minutes=5)),
    "6h": (timedelta(hours=6), timedelta(minutes=30)),
    "24h": (timedelta(hours=24), timedelta(hours=1)),
    "7d": (timedelta(days=7), timedelta(hours=6)),
}


def alert_stats(range_name: str) -> dict:
    if range_name not in RANGES:
        raise invalid("range", f"Must be one of: {', '.join(RANGES)}.", 400)
    span, step = RANGES[range_name]
    end = timeutil.now()
    start = end - span
    count = int(span / step)
    buckets = [{"start": timeutil.iso(start + step * i), "count": 0} for i in range(count)]
    by_category = {c: 0 for c in CATEGORIES}
    open_by_category = {c: 0 for c in CATEGORIES}
    for r in db.rows("SELECT category, COUNT(*) AS n FROM security_events WHERE status IN ('new','investigating') GROUP BY category"):
        open_by_category[r["category"]] = r["n"]
    for r in db.rows("SELECT event_time, category FROM security_events WHERE event_time >= ?", (timeutil.iso(start),)):
        offset = timeutil.parse(r["event_time"]) - start
        index = min(int(offset / step), count - 1)
        if index >= 0:
            buckets[index]["count"] += 1
        by_category[r["category"]] += 1
    return {
        "range": range_name,
        "bucketSeconds": int(step.total_seconds()),
        "buckets": buckets,
        "byCategory": by_category,
        "total": sum(by_category.values()),
        # Current open alerts regardless of the chart range (the dashboard's donut chart).
        "open": {"total": sum(open_by_category.values()), "byCategory": open_by_category},
    }


def purge(retention_days: int) -> dict:
    """Delete closed alerts older than the retention period, plus old runtime samples."""
    cutoff = timeutil.iso(timeutil.now() - timedelta(days=retention_days))
    conn = db.get_db()
    a = conn.execute(
        "DELETE FROM security_events WHERE status IN ('resolved','false_positive') AND last_seen < ?", (cutoff,)
    ).rowcount
    f = conn.execute("DELETE FROM frame_samples WHERE at < ?", (cutoff,)).rowcount
    m = conn.execute("DELETE FROM monitor_snapshots WHERE at < ?", (cutoff,)).rowcount
    conn.commit()
    return {"alerts": a, "frameSamples": f, "snapshots": m}
