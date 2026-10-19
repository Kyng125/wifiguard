from flask import request

from ..services import monitor
from ..validators import invalid
from . import bp


@bp.get("/monitor/status")
def monitor_status():
    return monitor.status()


@bp.get("/monitor/feed")
def monitor_feed():
    try:
        since = int(request.args.get("since", 0))
        limit = int(request.args.get("limit", 50))
    except ValueError:
        raise invalid("since", "since and limit must be whole numbers.", 400)
    if since < 0 or not 1 <= limit <= 200:
        raise invalid("limit", "limit must be 1-200 and since >= 0.", 400)
    return monitor.feed(since, limit)
