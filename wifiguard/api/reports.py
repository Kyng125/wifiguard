from .. import db, timeutil
from ..services import events, reports
from ..validators import SCENARIOS, invalid, json_body, one_of, text
from . import bp


def _number(value, name):
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 100:
        raise invalid(name, "Must be a number from 0 to 100.")
    return float(value)


def _timestamp(value, name):
    try:
        return timeutil.iso(timeutil.parse(value))
    except (ValueError, TypeError, AttributeError):
        raise invalid(name, "Must be an ISO date-time, e.g. 2026-10-12T09:30:00Z.")


def _serialise(r: dict) -> dict:
    seconds = None
    if r["alert_time"] and r["detected"] and r["scenario"] != "normal_baseline":
        seconds = round(timeutil.seconds_between(r["event_start"], r["alert_time"]), 2)
    return {
        "id": r["id"], "scenario": r["scenario"], "scenarioName": reports.SCENARIO_NAMES[r["scenario"]],
        "trial": r["trial"], "eventStart": r["event_start"],
        "alertEventId": events.display_id(r["alert_event_id"]) if r["alert_event_id"] else None,
        "alertTime": r["alert_time"], "detected": bool(r["detected"]), "secondsToDetect": seconds,
        "cpuPercent": r["cpu_percent"], "memoryPercent": r["memory_percent"], "notes": r["notes"],
        "isSample": bool(r["is_sample"]),
    }


@bp.get("/test-runs")
def list_test_runs():
    rows = db.rows("SELECT * FROM test_runs ORDER BY scenario, trial")
    return {"items": [_serialise(r) for r in rows]}


@bp.get("/test-runs/summary")
def test_run_summary():
    return reports.summary()


@bp.post("/test-runs")
def add_test_run():
    data = json_body()
    scenario = one_of(data.get("scenario"), "scenario", SCENARIOS)
    event_start = _timestamp(data.get("eventStart"), "eventStart")
    alert_event_id = None
    alert_time = _timestamp(data["alertTime"], "alertTime") if data.get("alertTime") else None
    detected = data.get("detected")
    if data.get("alertEventId"):
        alert_event_id = events.parse_event_id(data["alertEventId"])
        event = events.get_event(alert_event_id)
        alert_time = alert_time or event["first_seen"]   # take the real alert timestamp when linked
        detected = True
    if not isinstance(detected, bool):
        raise invalid("detected", "Must be true or false.")
    if alert_time and timeutil.parse(alert_time) < timeutil.parse(event_start):
        raise invalid("alertTime", "The alert cannot be earlier than the event start. Check that the clocks are synchronised.")
    trial = data.get("trial")
    if trial is None:
        trial = (db.scalar("SELECT MAX(trial) FROM test_runs WHERE scenario = ?", (scenario,)) or 0) + 1
    elif isinstance(trial, bool) or not isinstance(trial, int) or trial < 1:
        raise invalid("trial", "Must be a whole number from 1.")
    cur = db.get_db().execute(
        "INSERT INTO test_runs (scenario, trial, event_start, alert_event_id, alert_time, detected, cpu_percent, "
        "memory_percent, notes, is_sample, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?)",
        (scenario, trial, event_start, alert_event_id, alert_time, int(detected), _number(data.get("cpuPercent"), "cpuPercent"),
         _number(data.get("memoryPercent"), "memoryPercent"), text(data, "notes", 500, required=False), timeutil.iso()))
    db.get_db().commit()
    return _serialise(db.row("SELECT * FROM test_runs WHERE id = ?", (cur.lastrowid,))), 201
