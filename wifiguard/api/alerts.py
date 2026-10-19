import csv
import io

from flask import Response, g, request

from ..services import events
from ..validators import ALERT_STATUSES, json_body, one_of, page_params, text
from . import bp


@bp.get("/alerts")
def list_alerts():
    page, size = page_params()
    rows, total = events.query_events(request.args, page, size)
    return {"items": [events.serialise(r) for r in rows], "total": total, "page": page, "pageSize": size}


# Registered before /alerts/<id> so "export.csv" is never read as an id.
@bp.get("/alerts/export.csv")
def export_alerts():
    rows, _ = events.query_events(request.args)
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["id", "time", "severity", "category", "status", "source", "target", "ssid", "bssid",
                     "channel", "occurrences", "description"])
    for r in rows:
        writer.writerow([_cell(v) for v in (
            events.display_id(r["id"]), r["event_time"], r["severity"], r["category"], r["status"], r["source"],
            r["target"], r["ssid"], r["bssid"], r["channel"], r["occurrences"], r["description"])])
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": 'attachment; filename="wifiguard-alerts.csv"'})


def _cell(value):
    """Neutralise spreadsheet formula injection (values starting with = + - @)."""
    text_value = "" if value is None else str(value)
    return "'" + text_value if text_value[:1] in ("=", "+", "-", "@") else text_value


@bp.get("/alerts/<alert_id>")
def get_alert(alert_id):
    return events.detail(events.parse_event_id(alert_id))


@bp.patch("/alerts/<alert_id>")
def update_alert(alert_id):
    event_id = events.parse_event_id(alert_id)
    data = json_body()
    status = one_of(data.get("status"), "status", ALERT_STATUSES)
    note = text(data, "note", 1000, required=False)
    events.set_status(event_id, status, g.user["username"], note)
    return events.detail(event_id)


@bp.post("/alerts/<alert_id>/notes")
def add_alert_note(alert_id):
    event_id = events.parse_event_id(alert_id)
    events.add_note(event_id, text(json_body(), "text", 1000), g.user["username"])
    return events.detail(event_id), 201
