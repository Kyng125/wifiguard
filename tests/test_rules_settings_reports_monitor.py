from wifiguard import timeutil


def test_rules_list_and_save(api):
    items = {r["id"]: r for r in api.get("/api/rules").get_json()["items"]}
    assert items["deauth"]["threshold"] == 100 and items["deauth"]["windowSeconds"] == 10
    assert items["deauth"]["cooldownSeconds"] == 60 and items["deauth"]["enabled"] is True
    assert "threshold" not in items["arp"]
    r = api.put("/api/rules/deauth", {"enabled": False, "threshold": 150, "windowSeconds": 20, "cooldownSeconds": 90})
    assert r.status_code == 200 and r.get_json()["threshold"] == 150 and r.get_json()["enabled"] is False


def test_rule_validation(api):
    assert api.put("/api/rules/deauth", {"threshold": 0}).status_code == 422
    assert api.put("/api/rules/deauth", {"threshold": "100"}).status_code == 422
    assert api.put("/api/rules/arp", {"threshold": 5}).status_code == 422     # not editable for ARP
    assert api.put("/api/rules/arp", {"enabled": "yes"}).status_code == 422
    assert api.put("/api/rules/arp", {}).status_code == 422
    assert api.put("/api/rules/nope", {"enabled": True}).status_code == 404
    assert api.put("/api/rules/arp", {"cooldownSeconds": 30, "bogus": 1}).status_code == 422


def test_settings_roundtrip_is_symmetric(api):
    s = api.get("/api/settings").get_json()
    assert s["monitoring"]["channels"] == [6] and s["monitoring"]["channelMode"] == "locked"
    assert s["general"]["institutionalSsid"] == "Campus-WiFi"
    assert s["alerts"]["severityByCategory"]["rogue_ap"] == "critical"
    # what GET returns can be sent back to PUT (minus the read-only alerts group)
    echo = {k: v for k, v in s.items() if k != "alerts"}
    assert api.put("/api/settings", echo).status_code == 200
    r = api.put("/api/settings", {"monitoring": {"channels": [1, 6, 11], "channelMode": "hopping"},
                                   "general": {"refreshIntervalSeconds": 10}})
    body = r.get_json()
    assert r.status_code == 200 and body["monitoring"]["channels"] == [1, 6, 11]
    assert body["general"]["refreshIntervalSeconds"] == 10 and body["general"]["timezone"] == "Africa/Lagos"


def test_settings_validation(api):
    assert api.put("/api/settings", {"monitoring": {"channels": "6", "channelMode": "hopping"}}).status_code == 422
    bad = ({"general": {"timezone": "Mars/Base"}}, {"monitoring": {"monitorInterface": "wlan0; rm -rf /"}},
           {"data": {"retentionDays": 0}}, {"general": {"refreshIntervalSeconds": 1}}, {"monitoring": {"channels": "0"}},
           {"general": {"unknownKey": 1}}, {"nonsense": {"a": 1}}, {"alerts": {"severityByCategory": {}}},
           {"general": {}}, {"general": "x"}, {"refreshInterval": 5}, {"demoState": None}, {})
    for payload in bad:
        r = api.put("/api/settings", payload)
        assert r.status_code == 422, payload
        assert r.get_json()["error"]["code"] == "validation_error"
    assert api.put("/api/settings", {"general": {"unknownKey": 1}}).get_json()["error"]["details"]["field"] == "general.unknownKey"


def test_session_timeout_setting_applies(app, api):
    api.put("/api/settings", {"security": {"sessionTimeoutMinutes": 10}})
    assert app.permanent_session_lifetime.total_seconds() == 600


def test_institutional_ssid_makes_an_unlisted_ap_suspicious(seeded):
    """A new BSSID using the institution's SSID is flagged even if no authorised AP uses that SSID."""
    seeded.put("/api/settings", {"general": {"institutionalSsid": "TECNO-MiFi-2F81"}})
    ap = seeded.get("/api/access-points/9A:4B:21:C7:0D:36").get_json()
    assert ap["status"] == "suspected_rogue" and ap["reason"].startswith("Known SSID from an unknown BSSID")


def test_monitor_status_and_feed(seeded):
    s = seeded.get("/api/monitor/status").get_json()
    assert (s["packetsCaptured"], s["packetsPerSecond"], s["detectionEngine"]) == (128492, 1284, "running")
    assert s["frameMix"] == {"management": 61240, "data": 58310, "arp": 8942}
    assert s["sources"][0]["channel"] == 6
    feed = seeded.get("/api/monitor/feed?limit=5").get_json()
    assert len(feed["items"]) == 5 and feed["lastId"] >= 5
    again = seeded.get(f"/api/monitor/feed?since={feed['lastId']}").get_json()
    assert again["items"] == [] and again["lastId"] == feed["lastId"]
    assert seeded.get("/api/monitor/feed?limit=0").status_code == 400
    flagged = [i for i in seeded.get("/api/monitor/feed?limit=50").get_json()["items"] if i["flag"]]
    assert flagged and all(i["flag"].startswith("EV-") for i in flagged)


def test_engine_reported_stopped_when_snapshot_is_stale(app, seeded):
    from wifiguard import db
    with app.app_context():
        db.get_db().execute("UPDATE monitor_snapshots SET at = ?", (timeutil.ago(minutes=5),))
        db.get_db().commit()
    h = seeded.get("/api/health").get_json()
    assert h["detectionEngine"] == "stopped" and h["packetsPerSecond"] == 0


def test_health_without_any_snapshot(api):
    h = api.get("/api/health").get_json()
    assert h["detectionEngine"] == "unknown" and h["database"] == "connected"


def test_add_test_run_and_metrics(api):
    start = "2026-10-12T09:00:00Z"
    r = api.post("/api/test-runs", {"scenario": "deauth", "eventStart": start, "alertTime": "2026-10-12T09:00:03Z", "detected": True})
    assert r.status_code == 201 and r.get_json()["secondsToDetect"] == 3.0 and r.get_json()["trial"] == 1
    api.post("/api/test-runs", {"scenario": "deauth", "eventStart": start, "detected": False})
    api.post("/api/test-runs", {"scenario": "normal_baseline", "eventStart": start, "detected": False})
    s = api.get("/api/test-runs/summary").get_json()
    deauth = next(x for x in s["scenarios"] if x["scenario"] == "deauth")
    assert (deauth["trials"], deauth["detected"], deauth["rate"], deauth["meanTimeToDetectSeconds"]) == (2, 1, 50.0, 3.0)
    assert s["overall"]["detectionRate"] == 50.0 and s["overall"]["falsePositiveRate"] == 0.0 and s["isSample"] is False


def test_test_run_linked_to_a_real_alert_uses_its_timestamp(app, api):
    from wifiguard.services import events
    with app.app_context():
        event_id, _ = events.create_event(category="deauth_flood", source="AA:BB:CC:00:00:01", description="x",
                                          evidence={"frameCount": 120, "windowSeconds": 10, "threshold": 100},
                                          event_time="2026-10-12T09:00:05.000Z")
    r = api.post("/api/test-runs", {"scenario": "deauth", "eventStart": "2026-10-12T09:00:00Z", "alertEventId": f"EV-{event_id:04d}"})
    body = r.get_json()
    assert r.status_code == 201 and body["detected"] is True and body["secondsToDetect"] == 5.0


def test_test_run_validation(api):
    good = {"scenario": "deauth", "eventStart": "2026-10-12T09:00:00Z", "detected": True}
    assert api.post("/api/test-runs", {**good, "scenario": "x"}).status_code == 422
    assert api.post("/api/test-runs", {**good, "eventStart": "yesterday"}).status_code == 422
    assert api.post("/api/test-runs", {**good, "detected": "yes"}).status_code == 422
    assert api.post("/api/test-runs", {**good, "alertTime": "2026-10-12T08:59:00Z"}).status_code == 422   # alert before event
    assert api.post("/api/test-runs", {**good, "cpuPercent": 120}).status_code == 422
    assert api.post("/api/test-runs", {**good, "alertEventId": "EV-9999"}).status_code == 404


def test_security_headers_and_spa_fallback(anon):
    r = anon.get("/")
    assert r.status_code == 200 and "frontend" in r.get_json()["message"].lower()
    assert r.headers["X-Frame-Options"] == "DENY" and r.headers["X-Content-Type-Options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert anon.get("/api/ping").headers["Cache-Control"] == "no-store"


def test_spa_fallback_serves_built_files(app, tmp_path):
    dist = tmp_path / "dist"
    (dist / "assets").mkdir(parents=True)
    (dist / "index.html").write_text("<html>app</html>")
    (dist / "assets" / "a.js").write_text("console.log(1)")
    app.config["FRONTEND_DIST"] = str(dist)
    c = app.test_client()
    assert c.get("/alerts/EV-1054").get_data(as_text=True) == "<html>app</html>"      # client-side route
    assert c.get("/assets/a.js").get_data(as_text=True) == "console.log(1)"
    assert "app" in c.get("/../../etc/passwd").get_data(as_text=True)                  # never escapes the dist folder


def test_health_includes_packet_series(seeded):
    h = seeded.get("/api/health").get_json()
    series = h["packetsPerSecondSeries"]
    assert len(series) == 13 and series[-1] == 1284 and all(isinstance(n, int) for n in series)


def test_health_series_empty_without_fresh_snapshot(api):
    assert api.get("/api/health").get_json()["packetsPerSecondSeries"] == []


def test_overview_and_topology_report_the_network_name(seeded):
    assert seeded.get("/api/overview").get_json()["network"] == "Campus-WiFi"
    assert seeded.get("/api/topology").get_json()["network"] == "Campus-WiFi"
