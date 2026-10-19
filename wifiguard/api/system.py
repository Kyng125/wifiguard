from flask import request

from .. import db
from ..defaults import RULES
from ..services import events, inventory, monitor
from ..services import settings as st
from . import bp


def _cpu_mem() -> tuple[float | None, float | None]:
    try:
        import psutil
        return psutil.cpu_percent(interval=0.1), psutil.virtual_memory().percent
    except Exception:
        return None, None


@bp.get("/overview")
def overview():
    counts = {r["severity"]: r["n"] for r in db.rows(
        "SELECT severity, COUNT(*) AS n FROM security_events WHERE status IN ('new','investigating') GROUP BY severity")}
    total = sum(counts.values())
    devices = inventory.devices_summary(inventory.all_devices())
    aps = inventory.access_points_summary(inventory.all_access_points())
    enabled = sum(1 for r in RULES if st.get_bool(f"rule.{r}.enabled"))
    return {
        "network": st.get("institutional_ssid"),
        "openAlerts": {"total": total, "critical": counts.get("critical", 0), "high": counts.get("high", 0),
                       "medium": counts.get("medium", 0), "info": counts.get("info", 0),
                       "warnings": total - counts.get("critical", 0)},
        "devices": devices,
        "accessPoints": aps,
        "rules": {"enabled": enabled, "total": len(RULES)},
        "detectionEngine": monitor.state()["engine"],
        "warnings": monitor.warnings(),       # setup problems, e.g. no authorised access points (additive field)
    }


@bp.get("/health")
def health():
    s = monitor.state()
    snap = s["snapshot"] or {}
    cpu, mem = (snap.get("cpu_percent"), snap.get("memory_percent")) if s["fresh"] else (None, None)
    if cpu is None or mem is None:
        live_cpu, live_mem = _cpu_mem()
        cpu = live_cpu if cpu is None else cpu
        mem = live_mem if mem is None else mem
    status = monitor.status()
    return {
        "cpuPercent": cpu,
        "memoryPercent": mem,
        "packetsPerSecond": status["packetsPerSecond"],
        "packetsPerSecondSeries": monitor.packet_series() if s["fresh"] else [],
        "detectionEngine": s["engine"],
        "database": "connected",
        "captureSources": status["sources"],
        "updatedAt": status["updatedAt"],
    }


@bp.get("/stats/alerts")
def alert_stats():
    return events.alert_stats(request.args.get("range", "24h"))
