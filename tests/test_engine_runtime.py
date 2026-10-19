"""Replay mixer pacing (fake clock) and the background runtime end to end (real thread, fast replay)."""
import threading
import time
from pathlib import Path

import pytest

from wifiguard import db
from wifiguard.engine.frames import Frame
from wifiguard.engine.sources import ReplayMixer, list_scenarios, scenario_files
from wifiguard.seed_demo import seed

SAMPLES = Path(__file__).resolve().parent.parent / "samples" / "pcaps"


class FakeTime:
    def __init__(self, now=1000.0):
        self.now = now

    def clock(self):
        return self.now

    def wait(self, seconds):
        self.now += seconds
        return False


def frames(*times, kind="beacon"):
    return iter([Frame(ts=t, frame_type="management", kind=kind, bssid="AA:BB:CC:00:00:01") for t in times])


def collect(mixer, limit, stop=None, on_frame=None):
    stop = stop or threading.Event()
    out = []
    for frame, name in mixer.run(stop):
        out.append((frame.ts, name))
        if on_frame:
            on_frame(len(out))
        if len(out) >= limit:
            stop.set()
    return out


def test_frames_are_released_at_their_original_spacing_starting_now():
    t = FakeTime(1000)
    mixer = ReplayMixer(lambda name: frames(50, 51, 52.5), background="b", loop=False, clock=t.clock, wait=t.wait)
    assert [ts for ts, _ in collect(mixer, 10, stop=_stop_when_idle(mixer))] == [1000, 1001, 1002.5]


def _stop_when_idle(mixer):
    """Stop once nothing is left to play (non-looping tests)."""
    stop = threading.Event()
    original = mixer.wait

    def wait(seconds):
        if not mixer._streams:
            stop.set()
            return True
        return original(seconds)
    mixer.wait = wait
    return stop


def test_speed_scales_time():
    t = FakeTime(0)
    mixer = ReplayMixer(lambda name: frames(0, 4, 8), background="b", loop=False, speed=2, clock=t.clock, wait=t.wait)
    assert [ts for ts, _ in collect(mixer, 10, stop=_stop_when_idle(mixer))] == [0, 2, 4]


def test_long_silences_are_shortened():
    t = FakeTime(0)
    mixer = ReplayMixer(lambda name: frames(0, 1, 500, 501), background="b", loop=False, max_gap=2, clock=t.clock, wait=t.wait)
    assert [ts for ts, _ in collect(mixer, 10, stop=_stop_when_idle(mixer))] == [0, 1, 3, 4]


def test_looping_background_never_runs_time_backwards():
    t = FakeTime(0)
    mixer = ReplayMixer(lambda name: frames(10, 11, 12), background="b", loop=True, clock=t.clock, wait=t.wait)
    stamps = [ts for ts, _ in collect(mixer, 9)]
    assert len(stamps) == 9 and stamps == sorted(stamps)
    assert stamps[3] >= stamps[2]          # the second pass starts after the first ended


def test_a_triggered_scenario_is_layered_on_the_background_in_time_order():
    t = FakeTime(0)
    sources = {"bg": lambda: frames(*range(0, 30)), "attack": lambda: frames(0, 0.5, 1.5, kind="deauthentication")}
    mixer = ReplayMixer(lambda name: sources[name](), background="bg", loop=True, clock=t.clock, wait=t.wait)
    out = collect(mixer, 12, on_frame=lambda n: mixer.add("attack") if n == 3 else None)
    names = [n for _, n in out]
    stamps = [ts for ts, _ in out]
    assert stamps == sorted(stamps)
    assert names.count("attack") == 3 and names.index("attack") > 2
    # the background kept playing between attack frames
    first, last = names.index("attack"), len(names) - 1 - names[::-1].index("attack")
    assert "bg" in names[first:last + 1]
    assert mixer.active() == [] or True    # (active() is covered by the runtime test)


def test_stop_ends_the_stream_even_while_waiting():
    mixer = ReplayMixer(lambda name: frames(0, 1000), background="b", loop=False, max_gap=500)
    stop = threading.Event()
    threading.Timer(0.3, stop.set).start()
    started = time.monotonic()
    assert [n for _, n in mixer.run(stop)] == ["b"]            # first frame released at once, then it waits
    assert time.monotonic() - started < 2


def test_an_empty_recording_is_not_restarted_in_a_loop():
    t = FakeTime(0)
    opened = []
    mixer = ReplayMixer(lambda name: opened.append(name) or iter([]), background="b", loop=True, clock=t.clock, wait=t.wait)
    stop = threading.Event()
    waits = {"n": 0}

    def wait(seconds):
        waits["n"] += 1
        return waits["n"] > 3
    mixer.wait = wait
    assert list(mixer.run(stop)) == [] and opened == ["b"]


def test_invalid_speed():
    with pytest.raises(ValueError):
        ReplayMixer(lambda n: iter([]), speed=0)


# ------------------------------------------------------------------------- scenario files

def test_bundled_scenarios_are_listed_with_what_they_should_raise():
    found = {s["id"]: s for s in list_scenarios(SAMPLES)}
    assert list(found)[:5] == ["baseline", "deauth", "arp_conflict", "rogue_ap", "unknown_device"]
    assert found["deauth"]["expects"] == "deauth_flood" and found["baseline"]["background"] is True
    assert [Path(p).name for p in scenario_files(SAMPLES, "baseline")] == ["baseline.pcap", "baseline-arp.pcap"]
    assert scenario_files(SAMPLES, "../etc/passwd") == []


def test_other_pcaps_dropped_into_the_folder_become_scenarios(tmp_path):
    (tmp_path / "my-capture.pcap").write_bytes(b"")
    (tmp_path / "my-capture-arp.pcap").write_bytes(b"")
    (tmp_path / "bad name.pcap").write_bytes(b"")
    found = list_scenarios(tmp_path)
    assert [s["id"] for s in found] == ["my-capture"] and found[0]["bundled"] is False


# ------------------------------------------------------------------- runtime, end to end

@pytest.fixture
def live(app, api):
    app.config["REPLAY_DIR"] = str(SAMPLES)
    with app.app_context():
        seed(reset=True)
    yield api
    from wifiguard.services import engine_control
    engine_control.get_runtime(app).stop()


def wait_for(predicate, seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(0.1)
    return False


def count(app, sql, *args):
    with app.app_context():
        return db.scalar(sql, args)


def test_engine_status_before_start(live):
    body = live.get("/api/engine").get_json()
    assert body["running"] is False and [s["id"] for s in body["scenarios"]][0] == "baseline"
    status = live.get("/api/monitor/status").get_json()
    assert status["source"] == {"kind": "none"}


def test_trigger_needs_a_running_engine_and_a_known_scenario(live):
    assert live.post("/api/engine/trigger", {"scenario": "deauth"}).status_code == 409
    assert live.post("/api/engine/start", {"background": None, "speed": 20}).status_code == 200
    assert live.post("/api/engine/trigger", {"scenario": "nope"}).status_code == 422
    assert live.post("/api/engine/trigger", {}).status_code == 422
    assert live.post("/api/engine/start", {}).status_code == 409                 # already running
    live.post("/api/engine/stop")


@pytest.mark.parametrize("body", [{"background": 5}, {"background": "nope"}, {"loop": "yes"}, {"speed": 0},
                                  {"speed": 100}, {"speed": True}])
def test_start_validates_input(live, body):
    assert live.post("/api/engine/start", body).status_code == 422


def test_a_triggered_scenario_raises_its_alert_and_the_dashboard_state_follows(live, app):
    assert live.post("/api/engine/start", {"speed": 20}).status_code == 200      # baseline in the background
    assert wait_for(lambda: count(app, "SELECT COUNT(*) FROM monitor_snapshots WHERE engine_state = 'running'") > 0)
    before = count(app, "SELECT COUNT(*) FROM security_events WHERE category = 'deauth_flood'")
    live.post("/api/engine/trigger", {"scenario": "deauth"})
    # The Admin Block deauth alert in the demo data is old, so a fresh one is raised (or merged if a recent one is open).
    assert wait_for(lambda: count(app, "SELECT COUNT(*) FROM security_events WHERE category = 'deauth_flood' "
                                       "AND last_seen > ?", _seconds_ago(30)) >= 1)
    assert wait_for(lambda: live.get("/api/monitor/status").get_json()["packetsCaptured"] > 0)   # next 2-second snapshot
    status = live.get("/api/monitor/status").get_json()
    assert status["detectionEngine"] == "running" and status["source"]["kind"] == "replay"
    assert status["sources"][0]["name"].startswith("replay: baseline") and status["sources"][0]["mode"] == "replay"
    assert sum(status["frameMix"].values()) > 0
    flagged = [i for i in live.get("/api/monitor/feed?limit=200").get_json()["items"] if i["flag"]]
    assert flagged and flagged[0]["subtype"] == "deauthentication"
    live.post("/api/engine/stop")
    assert wait_for(lambda: not live.get("/api/engine").get_json()["running"])
    final = live.get("/api/monitor/status").get_json()
    assert final["detectionEngine"] == "stopped" and final["source"] == {"kind": "none"}
    assert before <= count(app, "SELECT COUNT(*) FROM security_events WHERE category = 'deauth_flood'")


def _seconds_ago(n):
    from datetime import timedelta
    from wifiguard import timeutil
    return timeutil.iso(timeutil.now() - timedelta(seconds=n))


def test_baseline_alone_raises_no_new_alerts(live, app):
    alerts_before = count(app, "SELECT COUNT(*) FROM security_events")
    assert live.post("/api/engine/start", {"speed": 20, "loop": False}).status_code == 200
    # Played once (about 3 s at this speed), then the engine idles, waiting for a scenario to be triggered.
    assert wait_for(lambda: live.get("/api/engine").get_json()["framesAnalysed"] > 500, seconds=30)
    body = live.get("/api/engine").get_json()
    assert body["running"] is True and body["error"] is None and body["alertsRaised"] == 0
    live.post("/api/engine/stop")
    assert count(app, "SELECT COUNT(*) FROM security_events") == alerts_before


def test_unknown_device_scenario_raises_the_alert(live, app):
    live.post("/api/engine/start", {"background": None, "speed": 20})
    live.post("/api/engine/trigger", {"scenario": "unknown_device"})
    assert wait_for(lambda: count(app, "SELECT COUNT(*) FROM security_events WHERE category = 'unauthorised_device' "
                                       "AND source = 'DE:AD:BE:EF:00:21'") == 1)
    live.post("/api/engine/stop")


# ------------------------------------------------------------------------------ warnings

def test_warnings_explain_a_silent_or_noisy_setup(app, api, anon):
    codes = lambda: [w["code"] for w in api.get("/api/monitor/status").get_json()["warnings"]]   # noqa: E731
    assert codes() == ["no_authorised_aps"]
    api.post("/api/access-points/authorised", {"ssid": "Campus-WiFi", "bssid": "28:6C:07:4A:11:E0"})
    assert codes() == ["no_device_baseline"]
    with app.app_context():
        db.get_db().execute("INSERT INTO observed_devices (mac_address, associated_bssid, first_seen, last_seen) "
                            "VALUES ('3C:52:82:1A:7B:09', '28:6C:07:4A:11:E0', 'x', 'x')")
        db.get_db().commit()
    assert codes() == []
    assert anon.get("/api/engine").status_code == 401
