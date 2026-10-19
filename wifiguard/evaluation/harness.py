"""Runs the Table 3.5 scenarios as repeated trials and computes the Section 3.13 measures.

How a trial works
-----------------
* Each trial gets its own copy of a freshly seeded database with no alerts, so trials cannot affect each other
  (a rule cool-down or an "already observed" device from one trial never leaks into the next).
* Varied normal traffic plays throughout. For an attack scenario the attack is layered on top of it at a random moment.
* The true start of an attack is the release time of its first malicious frame. The alert time is the time the event
  manager stamped on the alert it created, read back from the database. Detected means an alert of the expected
  category was created at or after the start. For the baseline, any alert at all is a false positive.
* `fast` mode runs on a virtual clock (frame times are exact, nothing sleeps); `realtime` runs on the wall clock and
  also records the CPU and memory of this process while it analyses the traffic.

What it does not measure: capture, the radio, the dashboard's refresh delay. See docs/evaluation.md.
"""
import dataclasses
import json
import platform
import random
import shutil
import sqlite3
import sys
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Callable

from .. import create_app, db, timeutil
from ..engine.pipeline import Pipeline
from ..engine.processor import Processor
from ..engine.sources import ReplayMixer
from ..seed_demo import seed
from ..services import settings as st
from ..validators import SCENARIOS
from . import traffic

VERSION = "1.4"
NORMAL_SECONDS = 60.0            # length of one baseline trial
OFFSET_RANGE = (5.0, 15.0)       # when, within the normal traffic, the attack begins
GRACE_SECONDS = 10.0             # how long after the attack ends the trial keeps listening
NOTES_LIMIT = 480


class EvaluationError(Exception):
    pass


class VirtualClock:
    """A clock that only moves when the mixer waits, so a trial runs instantly and its frame times are exact."""

    def __init__(self, start: float):
        self.now = start

    def clock(self) -> float:
        return self.now

    def wait(self, seconds: float) -> bool:
        self.now += seconds
        return False


@dataclass
class TrialResult:
    scenario: str
    trial: int
    event_start: str
    alert_time: str | None
    detected: bool
    seconds_to_detect: float | None
    cpu_percent: float | None
    memory_percent: float | None
    notes: str
    params: dict = field(default_factory=dict)
    frames: int = 0
    other_alerts: list = field(default_factory=list)


@dataclass
class Execution:
    events: list
    event_start: float | None
    first_frame: float | None
    frames: int
    cpu: float | None
    memory: float | None
    benign_deauth_max: int


def _iso(ts: float) -> str:
    return timeutil.iso(datetime.fromtimestamp(ts, tz=timezone.utc))


# ------------------------------------------------------------------------------------------ database

def build_template(path: str, settings: dict | None = None) -> None:
    """A seeded database with no alerts and no test runs, carrying the given settings (thresholds, SSID...)."""
    app = create_app({"DATABASE": path, "INSTANCE_DIR": str(Path(path).parent), "SECRET_KEY": "evaluation", "TESTING": True})
    with app.app_context():
        seed(reset=True)
        conn = db.get_db()
        for table in ("event_log", "security_events", "frame_samples", "monitor_snapshots", "test_runs"):
            conn.execute(f"DELETE FROM {table}")
        conn.commit()
        if settings:
            st.set_many({k: v for k, v in settings.items() if not k.startswith("monitor_") and k != "timezone"})
    conn = sqlite3.connect(path)
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    conn.execute("PRAGMA journal_mode = DELETE")
    conn.close()


def settings_snapshot(settings: dict) -> dict:
    keep = ("institutional_ssid", "channels", "channel_mode", "refresh_interval_seconds")
    return {k: v for k, v in settings.items() if k.startswith(("rule.", "severity.")) or k in keep}


# ------------------------------------------------------------------------------------------ execution

def _execute(template: str, normal_frames: list, attack_frames: list | None, offset: float, duration: float,
             mode: str, speed: float) -> Execution:
    """Play the traffic through the real engine and pipeline in an isolated copy of the template database."""
    with tempfile.TemporaryDirectory(prefix="wifiguard-trial-") as work:
        path = str(Path(work) / "trial.db")
        shutil.copyfile(template, path)
        app = create_app({"DATABASE": path, "INSTANCE_DIR": work, "SECRET_KEY": "evaluation", "TESTING": True})
        streams = {"normal": normal_frames, "attack": attack_frames or []}
        virtual = VirtualClock(time.time()) if mode == "fast" else None
        clock = virtual.clock if virtual else time.time
        stop = threading.Event()
        state = {"added": False}
        start = clock()

        def tick() -> None:
            elapsed = (clock() - start) * speed
            if attack_frames and not state["added"] and elapsed >= offset:
                state["added"] = True
                mixer.add("attack")
            if elapsed >= duration:
                stop.set()

        mixer = ReplayMixer(lambda name: (dataclasses.replace(f) for f in streams[name]), background="normal", loop=False,
                            speed=speed, max_gap=float("inf"), clock=clock, wait=virtual.wait if virtual else None, tick=tick)
        event_start = first_frame = None
        frames = 0
        deauth_times: list[float] = []
        cpu = memory = None
        with app.app_context():
            pipeline = Pipeline(stamp="capture", refresh_seconds=None)
            process = None
            if mode == "realtime":
                try:
                    import psutil
                    process = psutil.Process()
                    process.cpu_percent(None)
                except Exception:                                  # noqa: BLE001 - metrics are optional
                    process = None
            for frame, name in mixer.run(stop):
                frames += 1
                first_frame = first_frame if first_frame is not None else frame.ts
                if name == "attack" and event_start is None:
                    event_start = frame.ts
                if name == "normal" and frame.kind == "deauthentication":
                    deauth_times.append(frame.ts)
                pipeline.handle(frame)
            pipeline.flush()
            if process is not None:
                cpu, memory = round(process.cpu_percent(None), 1), round(process.memory_percent(), 1)
            events = db.rows("SELECT id, category, source, first_seen FROM security_events ORDER BY first_seen, id")
    return Execution(events, event_start, first_frame, frames, cpu, memory, _max_in_window(deauth_times, 10.0))


def _max_in_window(times: list[float], window: float) -> int:
    best = left = 0
    for right, t in enumerate(times):
        while t - times[left] > window:
            left += 1
        best = max(best, right - left + 1)
    return best


def _frames(packets: list, processor: Processor) -> list:
    return [f for f in (processor.process(p) for p in packets) if f is not None]


# --------------------------------------------------------------------------------------------- trials

def run_trial(template: str, scenario: str, trial: int, seed_value: int, mode: str = "fast", speed: float = 1.0) -> TrialResult:
    if scenario not in SCENARIOS:
        raise EvaluationError(f"unknown scenario {scenario}")
    rng = random.Random(f"{seed_value}:{scenario}:{trial}")
    inv = traffic.Inventory.demo()
    processor = Processor()
    attack = None
    offset = 0.0
    if scenario == "normal_baseline":
        duration = NORMAL_SECONDS
    else:
        attack = traffic.attack(scenario, rng, inv)
        offset = round(rng.uniform(*OFFSET_RANGE), 2)
        duration = offset + max(float(p.time) for p in attack.packets) + GRACE_SECONDS
    packets, summary = traffic.normal(rng, duration, inv)
    run = _execute(template, _frames(packets, processor), _frames(attack.packets, processor) if attack else None,
                   offset, duration, mode, speed)

    if attack is None:
        start_ts = run.first_frame if run.first_frame is not None else time.time()
        false_alerts = [e["category"] for e in run.events]
        detected = bool(false_alerts)
        alert_time = run.events[0]["first_seen"] if detected else None
        seconds = None
        params = {"frames": run.frames, **summary, "max_benign_deauth_in_10s": run.benign_deauth_max}
        other = false_alerts
        note = (f"normal traffic {NORMAL_SECONDS:.0f}s, {run.frames} frames; roaming/other deauth max {run.benign_deauth_max} "
                f"in 10s; reconnects {summary['reconnects']}; false alerts: {', '.join(false_alerts) or 'none'}")
    else:
        if run.event_start is None:
            raise EvaluationError("the attack was never released; the trial window is too short")
        start_ts = run.event_start
        matches = [e for e in run.events if e["category"] == attack.expects and e["first_seen"] >= _iso(start_ts)]
        detected = bool(matches)
        alert_time = matches[0]["first_seen"] if detected else None
        seconds = round(timeutil.seconds_between(_iso(start_ts), alert_time), 2) if detected else None
        other = [e["category"] for e in run.events if e not in matches]
        params = {**attack.params, "attack_offset_s": offset}
        note = (f"{scenario} " + ", ".join(f"{k}={v}" for k, v in attack.params.items())
                + f"; began {offset:.1f}s into normal traffic; also raised: {', '.join(other) or 'nothing else'}")
    prefix = f"simulated replay ({mode}), seed {seed_value}: "
    return TrialResult(scenario, trial, _iso(start_ts), alert_time, detected, seconds, run.cpu, run.memory,
                       (prefix + note)[:NOTES_LIMIT], params, run.frames, other)


@dataclass
class Evaluation:
    results: list
    meta: dict


def run_evaluation(settings: dict, trials: int = 10, seed_value: int = 1, scenarios: tuple = SCENARIOS,
                   mode: str = "fast", speed: float = 1.0, progress: Callable[[TrialResult], None] | None = None) -> Evaluation:
    if mode not in ("fast", "realtime"):
        raise EvaluationError("mode must be fast or realtime")
    if not 1 <= trials <= 1000:
        raise EvaluationError("trials must be between 1 and 1000")
    if speed <= 0 or (mode == "fast" and speed != 1.0):
        raise EvaluationError("speed must be positive, and is only used in realtime mode")
    results: list[TrialResult] = []
    started = timeutil.iso()
    with tempfile.TemporaryDirectory(prefix="wifiguard-eval-") as work:
        template = str(Path(work) / "template.db")
        build_template(template, settings)
        for scenario in scenarios:
            for trial in range(1, trials + 1):
                result = run_trial(template, scenario, trial, seed_value, mode, speed)
                results.append(result)
                if progress:
                    progress(result)
    return Evaluation(results, metadata(settings, trials, seed_value, scenarios, mode, speed, started))


def metadata(settings, trials, seed_value, scenarios, mode, speed, started) -> dict:
    try:
        import scapy
        scapy_version = scapy.__version__
    except Exception:                                                  # noqa: BLE001
        scapy_version = None
    import os
    return {
        "tool": "wifiguard evaluation", "version": VERSION, "startedAt": started, "finishedAt": timeutil.iso(),
        "kind": "simulated replay", "mode": mode, "speed": speed, "seed": seed_value, "trialsPerScenario": trials,
        "scenarios": list(scenarios), "normalTrafficSeconds": NORMAL_SECONDS, "attackOffsetSeconds": list(OFFSET_RANGE),
        "graceSeconds": GRACE_SECONDS, "settings": settings_snapshot(settings), "trafficRanges": traffic.RANGES,
        "environment": {"python": sys.version.split()[0], "platform": platform.platform(), "scapy": scapy_version,
                        "cpuCount": os.cpu_count()},
    }


# -------------------------------------------------------------------------------------------- metrics

def _pct(part: int, whole: int) -> float | None:
    return round(part / whole * 100, 1) if whole else None


def _mean(values: list) -> float | None:
    return round(sum(values) / len(values), 2) if values else None


def summarise(results: list) -> dict:
    """The Section 3.13 measures for a list of trial results; the same figures the Reports API computes from test_runs."""
    rows, attack_trials, attack_hits, times, base_trials, base_false = [], 0, 0, [], 0, 0
    for scenario in SCENARIOS:
        rs = [r for r in results if r.scenario == scenario]
        if not rs:
            continue
        hits = [r for r in rs if r.detected]
        ttd = [r.seconds_to_detect for r in hits if r.seconds_to_detect is not None]
        rows.append({
            "scenario": scenario, "kind": "baseline" if scenario == "normal_baseline" else "attack", "trials": len(rs),
            "detected": len(hits), "rate": _pct(len(hits), len(rs)), "meanTimeToDetectSeconds": _mean(ttd),
            "avgCpuPercent": _mean([r.cpu_percent for r in rs if r.cpu_percent is not None]),
            "avgMemoryPercent": _mean([r.memory_percent for r in rs if r.memory_percent is not None]),
        })
        if scenario == "normal_baseline":
            base_trials, base_false = len(rs), len(hits)
        else:
            attack_trials += len(rs)
            attack_hits += len(hits)
            times += ttd
    return {"scenarios": rows, "overall": {
        "detectionRate": _pct(attack_hits, attack_trials), "falsePositiveRate": _pct(base_false, base_trials),
        "meanTimeToDetectSeconds": _mean(times), "totalRuns": len(results)}}


# --------------------------------------------------------------------------------------------- saving

def save(evaluation: Evaluation, instance_dir: str, replace: bool = False) -> dict:
    """Write the results into test_runs (and the run metadata next to the database). Needs an app context.

    Demo sample rows are always replaced. Earlier real results are only replaced with replace=True, so a finished
    evaluation is never overwritten by accident.
    """
    conn = db.get_db()
    real = conn.execute("SELECT COUNT(*) FROM test_runs WHERE is_sample = 0").fetchone()[0]
    if real and not replace:
        raise EvaluationError(f"test_runs already holds {real} real result(s). Pass --replace to overwrite them.")
    conn.execute("DELETE FROM test_runs" if replace else "DELETE FROM test_runs WHERE is_sample = 1")
    stamp = timeutil.iso()
    conn.executemany(
        "INSERT INTO test_runs (scenario, trial, event_start, alert_event_id, alert_time, detected, cpu_percent, "
        "memory_percent, notes, is_sample, created_at) VALUES (?, ?, ?, NULL, ?, ?, ?, ?, ?, 0, ?)",
        [(r.scenario, r.trial, r.event_start, r.alert_time, int(r.detected), r.cpu_percent, r.memory_percent, r.notes, stamp)
         for r in evaluation.results])
    conn.commit()
    folder = Path(instance_dir) / "evaluation"
    folder.mkdir(parents=True, exist_ok=True)
    meta = {**evaluation.meta, "savedAt": stamp,
            "trials": [{"scenario": r.scenario, "trial": r.trial, "params": r.params, "framesAnalysed": r.frames,
                        "otherAlerts": r.other_alerts} for r in evaluation.results]}
    target = folder / f"run-{stamp.replace(':', '').replace('-', '')[:15]}.json"
    target.write_text(json.dumps(meta, indent=2), encoding="utf-8")
    return {"saved": len(evaluation.results), "metadata": str(target)}


# ----------------------------------------------------------------------------------- threshold sweep

def sweep_deauth(settings: dict, counts=(50, 80, 95, 99, 100, 101, 110, 150, 200, 300), seconds: float = 8.0,
                 durations=(5, 8, 10, 11, 15, 20, 30), fixed_frames: int = 150) -> dict:
    """How the deauthentication rule behaves at and around its threshold, with no other traffic.

    Table 1 varies the number of frames in a fixed burst; table 2 keeps the frame count and stretches the burst out, so
    the rate drops below what the window can accumulate.
    """
    inv = traffic.Inventory.demo()
    processor = Processor()
    out = {"counts": [], "durations": [], "threshold": int(settings.get("rule.deauth.threshold", 100)),
           "windowSeconds": int(settings.get("rule.deauth.window_seconds", 10))}
    with tempfile.TemporaryDirectory(prefix="wifiguard-sweep-") as work:
        template = str(Path(work) / "template.db")
        build_template(template, settings)

        def probe(frames: int, burst_seconds: float) -> dict:
            packets = traffic.deauth_burst(frames, burst_seconds, inv)
            run = _execute(template, [], _frames(packets, processor), 0.0, burst_seconds + 12.0, "fast", 1.0)
            hits = [e for e in run.events if e["category"] == "deauth_flood"]
            seconds_to = round(timeutil.seconds_between(_iso(run.event_start), hits[0]["first_seen"]), 2) if hits else None
            return {"frames": frames, "seconds": burst_seconds, "framesPerSecond": round(frames / burst_seconds, 1),
                    "detected": bool(hits), "secondsToDetect": seconds_to}

        for n in counts:
            out["counts"].append(probe(n, seconds))
        for d in durations:
            out["durations"].append(probe(fixed_frames, float(d)))
    return out
