"""Phase 4: the evaluation harness, its saved results, its exports and the threshold sweep.

Trials are shortened with monkeypatch so the suite stays fast; the logic under test is unchanged.
"""
import csv
import json

import pytest

from wifiguard import db
from wifiguard.defaults import DEFAULT_SETTINGS
from wifiguard.evaluation import export, harness, traffic

SETTINGS = dict(DEFAULT_SETTINGS)


@pytest.fixture(autouse=True)
def short_trials(monkeypatch):
    monkeypatch.setattr(harness, "NORMAL_SECONDS", 15.0)
    monkeypatch.setattr(harness, "OFFSET_RANGE", (2.0, 4.0))
    monkeypatch.setattr(harness, "GRACE_SECONDS", 5.0)
    monkeypatch.setattr(traffic, "BEACON_HZ", 2)           # fewer beacons to build; the rules under test do not depend on the rate


def evaluate(settings=SETTINGS, **kw):
    kw.setdefault("trials", 3)
    return harness.run_evaluation(settings, **kw)


@pytest.fixture
def template(tmp_path):
    path = str(tmp_path / "template.db")
    harness.build_template(path, SETTINGS)
    return path


# ------------------------------------------------------------------------------------ what a run measures

def test_every_scenario_is_detected_and_the_baseline_stays_quiet():
    ev = evaluate()
    summary = harness.summarise(ev.results)
    by = {s["scenario"]: s for s in summary["scenarios"]}
    assert set(by) == set(harness.SCENARIOS) and all(s["trials"] == 3 for s in summary["scenarios"])
    assert by["normal_baseline"]["detected"] == 0 and summary["overall"]["falsePositiveRate"] == 0.0
    assert all(by[s]["rate"] == 100.0 for s in harness.SCENARIOS[1:]) and summary["overall"]["detectionRate"] == 100.0
    for r in ev.results:
        assert r.other_alerts == [], f"{r.scenario} {r.trial} raised {r.other_alerts}"
        if r.scenario != "normal_baseline":
            assert r.alert_time >= r.event_start and r.seconds_to_detect is not None


def test_time_to_detect_reflects_how_each_rule_works():
    ev = evaluate()
    for r in ev.results:
        if r.scenario == "deauth":
            # the rule must accumulate 100 frames, so the delay is positive and cannot exceed the burst length
            assert 0 < r.seconds_to_detect <= r.params["seconds"]
        elif r.scenario != "normal_baseline":
            assert r.seconds_to_detect <= 0.5        # these rules fire on the first matching frame


def test_the_same_seed_repeats_exactly_and_another_seed_differs():
    def fingerprint(ev):
        return [(r.scenario, r.trial, r.detected, r.seconds_to_detect, r.params, r.frames) for r in ev.results]
    first = fingerprint(evaluate(trials=2, seed_value=7))
    assert first == fingerprint(evaluate(trials=2, seed_value=7))
    assert first != fingerprint(evaluate(trials=2, seed_value=8))


def test_trials_within_a_run_are_not_copies_of_each_other():
    ev = evaluate(trials=5, scenarios=("deauth", "rogue_ap"))
    deauth = [(r.params["frames"], r.params["seconds"]) for r in ev.results if r.scenario == "deauth"]
    rogue = [(r.params["bssid"], r.params["variant"]) for r in ev.results if r.scenario == "rogue_ap"]
    assert len(set(deauth)) == 5 and len(set(rogue)) == 5


def test_trials_are_isolated_from_each_other(template):
    # The unrecognised-device alert only fires the first time a device is seen. If one trial leaked state into the next,
    # replaying the same trial would find the device already known and miss it.
    a = harness.run_trial(template, "unknown_device", 1, 3)
    b = harness.run_trial(template, "unknown_device", 1, 3)
    assert a.detected and b.detected and a.params == b.params


def test_realtime_mode_records_cpu_and_memory(template):
    r = harness.run_trial(template, "deauth", 1, 1, mode="realtime", speed=10.0)
    assert r.detected and r.cpu_percent is not None and r.memory_percent is not None
    assert harness.run_trial(template, "deauth", 1, 1).cpu_percent is None          # fast mode: not measured


def test_input_is_validated():
    for kw in ({"trials": 0}, {"mode": "slow"}, {"speed": 2.0}, {"speed": -1, "mode": "realtime"}):
        with pytest.raises(harness.EvaluationError):
            evaluate(**kw)
    with pytest.raises(harness.EvaluationError):
        harness.run_trial("x", "nope", 1, 1)


# --------------------------------------------- the harness must be able to fail (otherwise 100% means nothing)

def test_a_threshold_set_too_high_produces_misses():
    ev = evaluate({**SETTINGS, "rule.deauth.threshold": "1000"}, scenarios=("deauth",))
    assert [r.detected for r in ev.results] == [False] * 3
    assert harness.summarise(ev.results)["overall"]["detectionRate"] == 0.0


def test_a_disabled_rule_produces_misses():
    ev = evaluate({**SETTINGS, "rule.rogue_ap.enabled": "0"}, scenarios=("rogue_ap", "arp_conflict"))
    by = {s["scenario"]: s["rate"] for s in harness.summarise(ev.results)["scenarios"]}
    assert by["rogue_ap"] == 0.0 and by["arp_conflict"] == 100.0        # only the disabled rule is affected


def test_a_threshold_set_too_low_produces_false_positives():
    ev = evaluate({**SETTINGS, "rule.deauth.threshold": "3"}, scenarios=("normal_baseline",), trials=4)
    assert harness.summarise(ev.results)["overall"]["falsePositiveRate"] > 0
    assert any("deauth_flood" in r.other_alerts for r in ev.results)


# --------------------------------------------------------------------------------------------- saving

def test_save_replaces_demo_samples_and_matches_the_reports_api(app, seeded):
    ev = evaluate()
    with app.app_context():
        assert db.scalar("SELECT COUNT(*) FROM test_runs WHERE is_sample = 1") == 50
        saved = harness.save(ev, app.config["INSTANCE_DIR"])
        assert db.scalar("SELECT COUNT(*) FROM test_runs WHERE is_sample = 1") == 0
        assert db.scalar("SELECT COUNT(*) FROM test_runs") == saved["saved"] == 15
    api = seeded.get("/api/test-runs/summary").get_json()
    assert api["isSample"] is False
    mine = {s["scenario"]: s for s in harness.summarise(ev.results)["scenarios"]}
    for row in api["scenarios"]:           # one set of formulas: the harness and the Reports API must agree
        for key in ("trials", "detected", "rate", "meanTimeToDetectSeconds"):
            assert row[key] == mine[row["scenario"]][key], (row["scenario"], key)
    assert api["overall"]["detectionRate"] == harness.summarise(ev.results)["overall"]["detectionRate"]
    runs = seeded.get("/api/test-runs").get_json()["items"]
    assert len(runs) == 15 and all(not r["isSample"] for r in runs)
    meta = json.loads(open(saved["metadata"], encoding="utf-8").read())
    assert meta["seed"] == 1 and meta["trialsPerScenario"] == 3 and len(meta["trials"]) == 15
    assert meta["settings"]["rule.deauth.threshold"] == "100" and meta["kind"] == "simulated replay"


def test_a_finished_evaluation_is_not_overwritten_by_accident(app, seeded):
    ev = evaluate(trials=1)
    with app.app_context():
        harness.save(ev, app.config["INSTANCE_DIR"])
        with pytest.raises(harness.EvaluationError, match="--replace"):
            harness.save(ev, app.config["INSTANCE_DIR"])
        harness.save(evaluate(trials=2), app.config["INSTANCE_DIR"], replace=True)
        assert db.scalar("SELECT COUNT(*) FROM test_runs") == 10


# --------------------------------------------------------------------------------------------- export

def test_export_writes_the_four_files_from_the_saved_run(app, seeded, tmp_path):
    with app.app_context():
        harness.save(evaluate(), app.config["INSTANCE_DIR"])
        result = export.write_all(str(tmp_path / "out"), app.config["INSTANCE_DIR"])
    assert result["warnings"] == []
    out = tmp_path / "out"
    assert sorted(p.name for p in out.iterdir()) == ["methodology.md", "metrics.csv", "metrics.md", "test_runs.csv"]
    rows = list(csv.reader(open(out / "test_runs.csv", encoding="utf-8-sig")))
    assert rows[0][:6] == ["Scenario", "Trial", "Event start (UTC)", "Alert time (UTC)", "Outcome", "Detected (1/0)"]
    assert len(rows) == 16
    outcomes = {(r[0], r[4]) for r in rows[1:]}
    assert ("Normal traffic baseline", "Clean") in outcomes and ("Deauthentication scenario", "Detected") in outcomes
    metrics = open(out / "metrics.md", encoding="utf-8").read()
    assert "Deauthentication scenario (detection rate) | 3 | 3 | 100.0" in metrics and "false-positive rate" in metrics
    method = open(out / "methodology.md", encoding="utf-8").read()
    for expected in ("Simulated replay", "3 trials for each of the 5 scenarios", "Random seed 1", "100 frames in 10 s",
                     "first malicious frame", "Not measured", "must not be reported as over-the-air performance"):
        assert expected in method, expected


def test_export_warns_when_the_log_is_only_demo_data_or_has_hand_entered_runs(app, seeded, tmp_path):
    with app.app_context():
        warned = export.write_all(str(tmp_path / "a"), app.config["INSTANCE_DIR"])["warnings"]
    assert any("demo sample" in w for w in warned)
    with app.app_context():
        harness.save(evaluate(trials=1), app.config["INSTANCE_DIR"])
    seeded.post("/api/test-runs", {"scenario": "deauth", "eventStart": "2026-10-14T10:00:00Z",
                                   "alertTime": "2026-10-14T10:00:03Z", "detected": True})
    with app.app_context():
        warned = export.write_all(str(tmp_path / "b"), app.config["INSTANCE_DIR"])["warnings"]
    assert any("entered by hand" in w for w in warned)


def test_export_of_an_empty_log_is_refused(app, tmp_path):
    with app.app_context():
        with pytest.raises(ValueError, match="empty"):
            export.write_all(str(tmp_path), app.config["INSTANCE_DIR"])


def test_export_without_metadata_does_not_invent_conditions(app, seeded, tmp_path):
    seeded.post("/api/test-runs", {"scenario": "deauth", "eventStart": "2026-10-14T10:00:00Z",
                                   "alertTime": "2026-10-14T10:00:03Z", "detected": True})
    with app.app_context():
        db.get_db().execute("DELETE FROM test_runs WHERE is_sample = 1")
        db.get_db().commit()
        export.write_all(str(tmp_path), app.config["INSTANCE_DIR"])
    text = open(tmp_path / "methodology.md", encoding="utf-8").read()
    assert "No run metadata was found" in text and "Simulated replay" not in text


# ----------------------------------------------------------------------------------------------- sweep

def test_sweep_shows_the_threshold_boundary_and_the_effect_of_a_slow_burst():
    result = harness.sweep_deauth(SETTINGS, counts=(50, 99, 100, 150), durations=(5, 30))
    detected = {r["frames"]: r["detected"] for r in result["counts"]}
    assert detected == {50: False, 99: False, 100: True, 150: True}
    assert result["threshold"] == 100 and result["windowSeconds"] == 10
    slow = {r["seconds"]: r["detected"] for r in result["durations"]}
    assert slow == {5.0: True, 30.0: False}               # 150 frames over 30 s never put 100 inside one 10 s window


# ------------------------------------------------------------------------------------------------ CLI

def test_cli_run_stores_nothing_without_save_and_saves_with_it(app, seeded):
    runner = app.test_cli_runner()
    out = runner.invoke(args=["evaluate", "run", "--trials", "1", "--scenario", "deauth"])
    assert out.exit_code == 0 and "Nothing was stored" in out.output and "Deauthentication scenario" in out.output
    with app.app_context():
        assert db.scalar("SELECT COUNT(*) FROM test_runs WHERE is_sample = 1") == 50
    out = runner.invoke(args=["evaluate", "run", "--trials", "1", "--scenario", "deauth", "--save"])
    assert out.exit_code == 0 and "Saved 1 runs" in out.output
    again = runner.invoke(args=["evaluate", "run", "--trials", "1", "--scenario", "deauth", "--save"])
    assert again.exit_code != 0 and "--replace" in again.output


def test_cli_export_and_sweep(app, seeded, tmp_path):
    runner = app.test_cli_runner()
    runner.invoke(args=["evaluate", "run", "--trials", "1", "--save"])
    out = runner.invoke(args=["evaluate", "export", "--out", str(tmp_path / "x")])
    assert out.exit_code == 0 and "methodology.md" in out.output and (tmp_path / "x" / "metrics.csv").exists()
    sweep = runner.invoke(args=["evaluate", "sweep", "--csv", str(tmp_path / "sweep.csv")])
    assert sweep.exit_code == 0 and "Threshold 100 frames in 10 s" in sweep.output
    table = list(csv.reader(open(tmp_path / "sweep.csv", encoding="utf-8-sig")))
    assert table[0][0] == "Table" and len(table) == 1 + 10 + 7
