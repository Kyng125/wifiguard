"""The demo seed must reproduce the numbers in the shared sample dataset used by the frontend prototype."""


def test_overview_matches_guidelines(seeded):
    o = seeded.get("/api/overview").get_json()
    assert o["openAlerts"] == {"total": 5, "critical": 1, "high": 2, "medium": 2, "info": 0, "warnings": 4}
    d = o["devices"]
    assert (d["active"], d["observed24h"], d["total"]) == (38, 42, 42)
    assert (d["authorised"], d["unrecognised"], d["underReview"], d["discoveredLast24h"]) == (36, 4, 2, 3)
    assert o["accessPoints"] == {"total": 8, "authorised": 6, "suspectedRogue": 1, "neighbouring": 1, "offline": 1}
    assert o["rules"] == {"enabled": 4, "total": 4}
    assert o["detectionEngine"] == "running"


def test_health_matches_guidelines(seeded):
    h = seeded.get("/api/health").get_json()
    assert (h["cpuPercent"], h["memoryPercent"], h["packetsPerSecond"]) == (34, 48, 1284)
    assert h["detectionEngine"] == "running" and h["database"] == "connected"
    assert [(s["name"], s["role"], s["state"]) for s in h["captureSources"]] == [("wlan0mon", "monitor", "up"), ("eth0", "arp", "up")]


def test_open_alerts_listing(seeded):
    items = seeded.get("/api/alerts?status=open").get_json()["items"]
    assert [i["id"] for i in items] == ["EV-1054", "EV-1053", "EV-1052", "EV-1051", "EV-1050"]
    assert items[0]["evidence"]["frameCount"] == 184 and items[0]["occurrences"] == 3


def test_test_run_summary_matches_guidelines(seeded):
    s = seeded.get("/api/test-runs/summary").get_json()
    assert s["isSample"] is True
    by = {x["scenario"]: x for x in s["scenarios"]}
    assert (by["normal_baseline"]["trials"], by["normal_baseline"]["detected"]) == (10, 1)
    assert (by["deauth"]["detected"], by["deauth"]["meanTimeToDetectSeconds"]) == (10, 2.4)
    assert (by["arp_conflict"]["detected"], by["arp_conflict"]["meanTimeToDetectSeconds"]) == (9, 3.1)
    assert (by["rogue_ap"]["detected"], by["rogue_ap"]["meanTimeToDetectSeconds"]) == (10, 4.8)
    assert (by["unknown_device"]["detected"], by["unknown_device"]["meanTimeToDetectSeconds"]) == (10, 1.9)
    assert s["overall"]["falsePositiveRate"] == 10.0
    assert s["overall"]["detectionRate"] == 97.5  # 39 of 40 attacks


def test_seed_refuses_to_overwrite_without_reset(app, seeded):
    import pytest
    from wifiguard.seed_demo import seed
    with app.app_context():
        with pytest.raises(RuntimeError):
            seed()
