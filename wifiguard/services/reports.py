"""Evaluation metrics from the test-run log, using the formulas in Section 3.13 of the report.

Detection Rate = correctly detected attacks / total test attacks x 100
False-Positive Rate = false alerts / total legitimate test events x 100   (baseline scenario)
Mean Time to Detect = sum(alert time - event start) / number of detected events (seconds)
"""
from .. import db, timeutil
from ..validators import SCENARIOS

SCENARIO_NAMES = {
    "normal_baseline": "Normal traffic baseline",
    "deauth": "Deauthentication scenario",
    "arp_conflict": "ARP conflict scenario",
    "rogue_ap": "Rogue access point scenario",
    "unknown_device": "Unknown device scenario",
}


def _pct(part: int, whole: int) -> float | None:
    return round(part / whole * 100, 1) if whole else None


def _mean(values: list[float]) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def summary() -> dict:
    runs = db.rows("SELECT * FROM test_runs ORDER BY scenario, trial")
    scenarios = []
    all_attack_trials = all_attack_detected = 0
    all_times: list[float] = []
    baseline_trials = baseline_false = 0
    for scenario in SCENARIOS:
        rs = [r for r in runs if r["scenario"] == scenario]
        is_baseline = scenario == "normal_baseline"
        detected = [r for r in rs if r["detected"]]
        times = [
            timeutil.seconds_between(r["event_start"], r["alert_time"])
            for r in detected if r["alert_time"] and not is_baseline
        ]
        cpu = [r["cpu_percent"] for r in rs if r["cpu_percent"] is not None]
        mem = [r["memory_percent"] for r in rs if r["memory_percent"] is not None]
        scenarios.append({
            "scenario": scenario,
            "name": SCENARIO_NAMES[scenario],
            "kind": "baseline" if is_baseline else "attack",
            "trials": len(rs),
            "detected": len(detected),
            "rate": _pct(len(detected), len(rs)),   # baseline: false-positive rate; others: detection rate
            "meanTimeToDetectSeconds": _mean(times),
            "avgCpuPercent": _mean(cpu),
            "avgMemoryPercent": _mean(mem),
        })
        if is_baseline:
            baseline_trials, baseline_false = len(rs), len(detected)
        else:
            all_attack_trials += len(rs)
            all_attack_detected += len(detected)
            all_times += times
    return {
        "isSample": bool(runs) and all(r["is_sample"] for r in runs),
        "scenarios": scenarios,
        "overall": {
            "detectionRate": _pct(all_attack_detected, all_attack_trials),
            "falsePositiveRate": _pct(baseline_false, baseline_trials),
            "meanTimeToDetectSeconds": _mean(all_times),
            "totalRuns": len(runs),
        },
    }
