"""Pins the exact response shapes the frontend's src/api/types.ts relies on.

If one of these fails, the frontend contract changed: update types.ts and the mock fixtures too.
"""
import pytest

ALERT = {"id", "time", "category", "severity", "status", "source", "target", "ssid", "bssid", "channel",
         "description", "evidence", "rule", "occurrences", "firstSeen", "lastSeen", "resolvedAt"}
DEVICE = {"macAddress", "ownerLabel", "deviceType", "ip", "vendor", "firstSeen", "lastSeen", "associatedBssid",
          "accessPoint", "status", "active", "offline"}
AP = {"ssid", "bssid", "channel", "securityMode", "signal", "firstSeen", "lastSeen", "status", "authorised",
      "location", "reason"}


@pytest.fixture
def s(seeded):
    return seeded


def keys(resp):
    assert resp.status_code == 200, resp.get_json()
    return set(resp.get_json())


def test_alert_shapes(s):
    page = s.get("/api/alerts").get_json()
    assert set(page) == {"items", "total", "page", "pageSize"}
    assert set(page["items"][0]) == ALERT
    assert keys(s.get("/api/alerts/EV-1054")) == ALERT | {"timeline", "notes", "relatedIds"}
    detail = s.get("/api/alerts/EV-1054").get_json()
    assert set(detail["timeline"][0]) == {"at", "kind", "text", "actor"}


def test_alert_filters_accept_lists_and_open(s):
    assert s.get("/api/alerts?status=new,investigating").get_json()["total"] == \
        s.get("/api/alerts?status=open").get_json()["total"]


def test_device_shapes(s):
    page = s.get("/api/devices").get_json()
    assert set(page) == {"items", "total", "page", "pageSize", "summary"}
    assert set(page["items"][0]) == DEVICE
    assert set(page["summary"]) == {"total", "active", "observed24h", "authorised", "unrecognised",
                                    "underReview", "discoveredLast24h"}
    mac = page["items"][0]["macAddress"]
    assert keys(s.get(f"/api/devices/{mac}")) == DEVICE | {"notes", "events"}


def test_access_point_shapes(s):
    body = s.get("/api/access-points").get_json()
    assert set(body) == {"items", "summary"}
    assert set(body["items"][0]) == AP
    assert set(body["summary"]) == {"total", "authorised", "suspectedRogue", "neighbouring", "offline"}
    assert keys(s.get(f"/api/access-points/{body['items'][0]['bssid']}")) == AP | {"devices", "events"}


def test_dashboard_shapes(s):
    assert keys(s.get("/api/overview")) == {"network", "detectionEngine", "openAlerts", "devices",
                                            "accessPoints", "rules", "warnings"}   # warnings: added in v1.3
    assert set(s.get("/api/overview").get_json()["openAlerts"]) == {"total", "critical", "high", "medium",
                                                                    "info", "warnings"}
    assert keys(s.get("/api/health")) == {"cpuPercent", "memoryPercent", "packetsPerSecond",
                                          "packetsPerSecondSeries", "detectionEngine", "database",
                                          "captureSources", "updatedAt"}
    stats = s.get("/api/stats/alerts?range=24h").get_json()
    assert set(stats) == {"range", "bucketSeconds", "buckets", "byCategory", "total", "open"}
    assert set(stats["open"]) == {"total", "byCategory"}
    assert keys(s.get("/api/topology")) == {"network", "accessPoints", "devices"}


def test_rules_monitor_reports_settings_session(s):
    rule = s.get("/api/rules").get_json()["items"][0]
    assert {"id", "name", "category", "description", "severity", "enabled", "cooldownSeconds", "editable"} <= set(rule)
    assert keys(s.get("/api/monitor/status")) == {"sources", "detectionEngine", "packetsCaptured",
                                                  "packetsPerSecond", "frameMix", "channels", "channelMode",
                                                  "updatedAt", "source", "warnings"}   # source, warnings: added in v1.3
    assert keys(s.get("/api/monitor/feed")) == {"items", "lastId"}
    run = s.get("/api/test-runs").get_json()["items"][0]
    assert set(run) == {"id", "scenario", "scenarioName", "trial", "eventStart", "alertEventId", "alertTime",
                        "detected", "secondsToDetect", "cpuPercent", "memoryPercent", "notes", "isSample"}
    assert keys(s.get("/api/test-runs/summary")) == {"isSample", "scenarios", "overall"}
    assert keys(s.get("/api/settings")) == {"general", "monitoring", "security", "data", "alerts"}
    assert keys(s.get("/api/auth/session")) == {"user"}


def test_error_shape_and_csrf(s, anon):
    err = s.get("/api/alerts/EV-9999")
    assert err.status_code == 404 and set(err.get_json()["error"]) >= {"code", "message"}
    no_header = anon.client.post("/api/auth/login", json={"username": "a", "password": "b"})
    assert no_header.status_code in (400, 403)
    assert anon.get("/api/overview").status_code == 401
