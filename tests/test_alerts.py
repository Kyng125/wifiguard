from wifiguard import db, timeutil
from wifiguard.services import events


EVIDENCE = {
    "deauth_flood": {"frameCount": 120, "windowSeconds": 10, "threshold": 100},
    "arp_conflict": {"ip": "192.168.1.5", "previousMac": "AA:BB:CC:00:00:01", "newMac": "AA:BB:CC:00:00:02"},
    "rogue_ap": {"ssid": "Campus-WiFi", "channel": 6, "securityMode": "WPA2"},
    "unauthorised_device": {"associatedBssid": "28:6C:07:4A:11:E0"},
}


def make(app, **kw):
    with app.app_context():
        args = dict(category="deauth_flood", source="AA:BB:CC:00:00:01", description="x", bssid="28:6C:07:4A:11:E0")
        args.update(kw)
        args.setdefault("evidence", EVIDENCE[args["category"]])
        return events.create_event(**args)


def test_cooldown_merges_repeats_and_counts_occurrences(app, api):
    first_id, created = make(app)
    second_id, created2 = make(app)
    assert created and not created2 and first_id == second_id
    alert = api.get(f"/api/alerts/{first_id}").get_json()
    assert alert["occurrences"] == 2
    assert [e["kind"] for e in alert["timeline"]] == ["detected", "generated", "merged"]


def test_closed_alert_does_not_swallow_a_new_event(app, api):
    first_id, _ = make(app)
    api.patch(f"/api/alerts/{first_id}", {"status": "resolved"})
    second_id, created = make(app)
    assert created and second_id != first_id


def test_severity_comes_from_settings_per_category(app, api):
    event_id, _ = make(app, category="rogue_ap", source="7C:10:C9:5E:3A:92")
    assert api.get(f"/api/alerts/{event_id}").get_json()["severity"] == "critical"


def test_status_change_logs_timeline_and_sets_resolved_at(api, app):
    event_id, _ = make(app)
    r = api.patch(f"/api/alerts/EV-{event_id:04d}", {"status": "false_positive", "note": "Scheduled AP reboot"})
    body = r.get_json()
    assert r.status_code == 200 and body["status"] == "false_positive" and body["resolvedAt"]
    assert any(e["kind"] == "status" and e["actor"] == "admin" for e in body["timeline"])
    assert body["notes"][0]["text"] == "Scheduled AP reboot"
    reopened = api.patch(f"/api/alerts/{event_id}", {"status": "investigating"}).get_json()
    assert reopened["resolvedAt"] is None


def test_invalid_status_and_missing_alert(api, app):
    event_id, _ = make(app)
    assert api.patch(f"/api/alerts/{event_id}", {"status": "banana"}).status_code == 422
    assert api.get("/api/alerts/EV-9999").status_code == 404
    assert api.get("/api/alerts/not-an-id").status_code == 404


def test_notes_are_stored_and_limited(api, app):
    event_id, _ = make(app)
    r = api.post(f"/api/alerts/{event_id}/notes", {"text": "Checked with the lab"})
    assert r.status_code == 201 and r.get_json()["notes"][0]["text"] == "Checked with the lab"
    assert api.post(f"/api/alerts/{event_id}/notes", {"text": "x" * 1001}).status_code == 422


def test_filters_pagination_and_search(seeded):
    assert seeded.get("/api/alerts").get_json()["total"] == 8
    assert seeded.get("/api/alerts?status=resolved,false_positive").get_json()["total"] == 2 + 1
    assert seeded.get("/api/alerts?severity=critical").get_json()["items"][0]["id"] == "EV-1053"
    assert seeded.get("/api/alerts?category=arp_conflict&status=open").get_json()["total"] == 1
    assert seeded.get("/api/alerts?q=7C:10:C9").get_json()["total"] == 1
    assert seeded.get("/api/alerts?q=EV-1052").get_json()["total"] == 1
    page = seeded.get("/api/alerts?pageSize=3&page=2").get_json()
    assert len(page["items"]) == 3 and page["total"] == 8
    assert seeded.get("/api/alerts?bssid=28:6C:07:4A:11:F4").get_json()["total"] == 1
    assert seeded.get("/api/alerts?status=nonsense").status_code == 400
    assert seeded.get("/api/alerts?pageSize=1000").status_code == 400


def test_search_treats_wildcards_literally(seeded):
    assert seeded.get("/api/alerts?q=%25").get_json()["total"] == 0


def test_date_range_uses_configured_timezone(app, api):
    # 23:30 UTC on 11 Oct is 00:30 on 12 Oct in Africa/Lagos (UTC+1), so it belongs to 12 Oct.
    make(app, event_time="2026-10-11T23:30:00.000Z", source="AA:BB:CC:00:00:77")
    assert api.get("/api/alerts?from=2026-10-12&to=2026-10-12").get_json()["total"] == 1
    assert api.get("/api/alerts?from=2026-10-11&to=2026-10-11").get_json()["total"] == 0
    assert api.get("/api/alerts?from=2026-10-11T23:00:00Z&to=2026-10-12T00:00:00Z").get_json()["total"] == 1
    assert api.get("/api/alerts?from=2100-01-01").get_json()["total"] == 0
    assert api.get("/api/alerts?from=garbage").status_code == 400


def test_detail_has_related_events(seeded):
    d = seeded.get("/api/alerts/EV-1054").get_json()
    assert [e["kind"] for e in d["timeline"]][:3] == ["detected", "threshold", "generated"]
    assert d["notes"] == [] and d["rule"] == "deauth"


def test_csv_export_neutralises_formulas(app, api):
    make(app, description="=HYPERLINK(\"http://evil\")")
    r = api.get("/api/alerts/export.csv")
    assert r.mimetype == "text/csv" and "attachment" in r.headers["Content-Disposition"]
    body = r.get_data(as_text=True)
    assert "'=HYPERLINK" in body and ",=HYPERLINK" not in body


def test_stats_buckets(seeded):
    s = seeded.get("/api/stats/alerts?range=24h").get_json()
    assert len(s["buckets"]) == 24 and s["bucketSeconds"] == 3600
    assert s["total"] == sum(b["count"] for b in s["buckets"]) == 5   # five alerts happened in the last 24 hours
    assert s["byCategory"]["unauthorised_device"] == 2
    assert len(seeded.get("/api/stats/alerts?range=1h").get_json()["buckets"]) == 12
    assert len(seeded.get("/api/stats/alerts?range=7d").get_json()["buckets"]) == 28
    assert seeded.get("/api/stats/alerts?range=2d").status_code == 400


def test_purge_removes_only_old_closed_alerts(app, seeded):
    with app.app_context():
        db.get_db().execute("UPDATE security_events SET last_seen = ? WHERE id = 1047", (timeutil.ago(days=90),))
        db.get_db().commit()
        result = events.purge(30)
    assert result["alerts"] == 1
    assert seeded.get("/api/alerts").get_json()["total"] == 7


def test_evidence_contract_is_enforced(app):
    import pytest
    with app.app_context():
        with pytest.raises(ValueError, match="frameCount"):
            events.create_event(category="deauth_flood", description="x", evidence={"windowSeconds": 10, "threshold": 100})
        with pytest.raises(ValueError, match="ip"):
            events.create_event(category="arp_conflict", description="x", evidence={})


def test_stats_include_open_totals_independent_of_range(seeded):
    for rng in ("1h", "7d"):
        s = seeded.get(f"/api/stats/alerts?range={rng}").get_json()
        assert s["open"]["total"] == 5
        assert s["open"]["byCategory"] == {"deauth_flood": 1, "arp_conflict": 1, "rogue_ap": 1, "unauthorised_device": 2}
