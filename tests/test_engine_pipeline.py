"""Pipeline and pcap replay: frames -> engine -> alert manager and observed_* tables, checked through the API."""
import time

import pytest

from wifiguard.engine import synthetic as syn
from wifiguard.engine.pipeline import Pipeline, replay
from wifiguard.engine.processor import Processor

ADMIN = "28:6C:07:4A:11:F4"
LAB1 = "28:6C:07:4A:12:08"


def total(api, category):
    return api.get(f"/api/alerts?category={category}&pageSize=100").get_json()["total"]


def scenario_file(tmp_path, name, **kw):
    path = str(tmp_path / f"{name}.pcap")
    return syn.write_pcap(path, syn.SCENARIOS[name](time.time(), **kw))


def run_files(app, files):
    with app.app_context():
        pipeline = Pipeline(stamp="now", refresh_seconds=None)
        processor = Processor()
        summary = None
        for path in files:
            summary = replay(path, pipeline, processor)
        return summary


@pytest.fixture
def demo(app, seeded):
    return seeded


def test_baseline_pcaps_raise_no_alerts(app, demo, tmp_path):
    before = demo.get("/api/alerts?pageSize=100").get_json()["total"]
    summary = run_files(app, scenario_file(tmp_path, "baseline"))
    assert summary["alerts"] == [] and summary["frames"] > 500
    assert demo.get("/api/alerts?pageSize=100").get_json()["total"] == before


def test_deauth_pcap_creates_one_alert_with_evidence(app, demo, tmp_path):
    before = total(demo, "deauth_flood")
    summary = run_files(app, scenario_file(tmp_path, "deauth"))
    assert len(summary["alerts"]) == 1
    event_id = summary["alerts"][0][0]
    alert = demo.get(f"/api/alerts/{event_id}").get_json()
    assert alert["category"] == "deauth_flood" and alert["severity"] == "high" and alert["status"] == "new"
    assert alert["source"] == ADMIN and alert["evidence"]["frameCount"] >= 100 and alert["rule"] == "deauth"
    assert [e["kind"] for e in alert["timeline"]] == ["detected", "generated"]
    assert total(demo, "deauth_flood") == before + 1


def test_arp_pcap_creates_a_conflict_alert(app, demo, tmp_path):
    summary = run_files(app, scenario_file(tmp_path, "arp_conflict"))
    (event_id, category, source), = summary["alerts"]
    alert = demo.get(f"/api/alerts/{event_id}").get_json()
    assert category == "arp_conflict" and alert["source"] == "192.168.1.15"
    assert alert["evidence"] == {"ip": "192.168.1.15", "previousMac": "A4:83:E7:2D:90:16", "newMac": "B2:44:0F:8E:63:D9"}
    # the new binding is remembered, so the dashboard's device list now shows the IP against the new MAC
    with app.app_context():
        from wifiguard import db
        assert db.scalar("SELECT COUNT(*) FROM arp_bindings WHERE ip_address = '192.168.1.15' AND mac_address = 'B2:44:0F:8E:63:D9'") == 1


def test_rogue_ap_pcap_flags_the_access_point(app, demo, tmp_path):
    summary = run_files(app, scenario_file(tmp_path, "rogue_ap"))
    (event_id, category, source), = summary["alerts"]
    assert (category, source) == ("rogue_ap", "7C:10:C9:5E:3A:A1")
    alert = demo.get(f"/api/alerts/{event_id}").get_json()
    assert alert["severity"] == "critical" and alert["evidence"]["securityMode"] == "WPA2"
    ap = demo.get("/api/access-points/7C:10:C9:5E:3A:A1").get_json()
    assert ap["status"] == "suspected_rogue" and ap["signal"] == -55 and ap["channel"] == 6


def test_unknown_device_pcap_flags_and_records_the_device(app, demo, tmp_path):
    summary = run_files(app, scenario_file(tmp_path, "unknown_device"))
    (event_id, category, source), = summary["alerts"]
    assert (category, source) == ("unauthorised_device", "DE:AD:BE:EF:00:21")
    assert demo.get(f"/api/alerts/{event_id}").get_json()["evidence"]["associatedBssid"] == LAB1
    device = demo.get("/api/devices/DE:AD:BE:EF:00:21").get_json()
    assert device["status"] == "unrecognised" and device["associatedBssid"] == LAB1 and device["active"] is True


def test_replaying_the_same_attack_does_not_duplicate_the_alert(app, demo, tmp_path):
    first = run_files(app, scenario_file(tmp_path, "rogue_ap"))
    again = run_files(app, scenario_file(tmp_path, "rogue_ap"))     # a new process, fresh rule state
    assert len(first["alerts"]) == 1 and again["alerts"] == [] and again["merged"] == 1
    alert = demo.get(f"/api/alerts/{first['alerts'][0][0]}").get_json()
    assert alert["occurrences"] == 2 and alert["timeline"][-1]["kind"] == "merged"


def test_capture_time_stamps_use_the_frame_clock(app, demo, tmp_path):
    path = scenario_file(tmp_path, "rogue_ap")[0]
    with app.app_context():
        summary = replay(path, Pipeline(stamp="capture", refresh_seconds=None))
    alert = demo.get(f"/api/alerts/{summary['alerts'][0][0]}").get_json()
    assert abs(__import__("datetime").datetime.fromisoformat(alert["time"].replace("Z", "+00:00")).timestamp() - time.time()) < 60


def test_threshold_changed_on_the_dashboard_is_picked_up(app, demo, tmp_path):
    packets = syn.deauth_flood(time.time(), LAB1, frames=30, seconds=3)
    path = str(tmp_path / "small.pcap")
    syn.write_pcap(path, packets)
    assert run_files(app, [path])["alerts"] == []                    # 30 frames < default threshold of 100
    assert demo.put("/api/rules/deauth", {"threshold": 20}).status_code == 200
    with app.app_context():
        pipeline = Pipeline(stamp="now", refresh_seconds=None)       # picks the setting up on start...
        assert len(replay(path, pipeline)["alerts"]) == 1
        demo.put("/api/rules/deauth", {"threshold": 50})
        pipeline.refresh()                                           # ...and on refresh while running
        assert pipeline.engine.config.deauth_threshold == 50


def test_authorised_list_changes_apply_without_restart(app, demo, tmp_path):
    mac = "DE:AD:BE:EF:00:22"
    with app.app_context():
        pipeline = Pipeline(stamp="now", refresh_seconds=None)
    assert demo.post("/api/devices/authorised", {"macAddress": mac, "ownerLabel": "Visitor-Laptop"}).status_code == 201
    with app.app_context():
        pipeline.refresh()
        for frame in map(Processor().process, syn.unknown_device(time.time(), mac)):
            assert pipeline.handle(frame) == []
        pipeline.flush()


def test_observation_writes_are_coalesced(app, demo):
    with app.app_context():
        pipeline = Pipeline(stamp="now", refresh_seconds=None, write_interval=5.0)
        base = time.time()
        writes = sum(pipeline._should_write(("ap", "X"), ("s",), base + i * 0.1) for i in range(100))     # 10 s of beacons
        assert writes == 2                                                                                   # not 100
        assert pipeline._should_write(("ap", "X"), ("other",), base + 10.5)                                  # a change is written at once


def test_replay_cli(app, demo, tmp_path):
    path = scenario_file(tmp_path, "deauth")[0]
    result = app.test_cli_runner().invoke(args=["replay-pcap", path])
    assert result.exit_code == 0, result.output
    assert "New alerts: 1" in result.output and "deauth_flood" in result.output


def test_pipeline_works_on_an_empty_database(app, tmp_path):
    with app.app_context():
        pipeline = Pipeline(stamp="now", refresh_seconds=None)
        assert pipeline.engine.reference.authorised_aps == {}
        summary = replay(scenario_file(tmp_path, "deauth")[0], pipeline)
    assert len(summary["alerts"]) == 1                               # deauth needs no inventory
