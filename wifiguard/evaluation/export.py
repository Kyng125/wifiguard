"""Files for Chapter 4 and Appendix B, written from the test_runs log and the run metadata.

    test_runs.csv    one row per trial: the Appendix B template filled with the raw observations
    metrics.csv      the Section 3.13 measures per scenario and overall
    metrics.md       the same as a table to paste into the report
    methodology.md   the test conditions the report must state (Section 2.2.16), filled in from the run
"""
import csv
import json
from pathlib import Path

from .. import db, timeutil
from ..services import reports
from ..services import settings as st

OUTCOME = {"normal_baseline": ("False alert", "Clean")}


def latest_metadata(instance_dir: str) -> tuple[dict | None, str | None]:
    files = sorted((Path(instance_dir) / "evaluation").glob("run-*.json"))
    if not files:
        return None, None
    return json.loads(files[-1].read_text(encoding="utf-8")), str(files[-1])


def _fmt(value, suffix="") -> str:
    return "n/a" if value is None else f"{value}{suffix}"


def write_all(out_dir: str, instance_dir: str, meta_file: str | None = None) -> dict:
    """Write the four files. Needs an app context. Returns {path: description} and warnings."""
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    if meta_file:
        meta, meta_path = json.loads(Path(meta_file).read_text(encoding="utf-8")), meta_file
    else:
        meta, meta_path = latest_metadata(instance_dir)
    runs = db.rows("SELECT * FROM test_runs ORDER BY scenario, trial")
    summary = reports.summary()
    warnings = []
    if not runs:
        raise ValueError("test_runs is empty. Run 'flask --app wifiguard evaluate run --save' or log lab trials first.")
    if summary["isSample"]:
        warnings.append("The log contains only demo sample rows; the exports are placeholders, not results.")
    if meta and len(runs) != len(meta.get("trials", [])):
        warnings.append(f"test_runs holds {len(runs)} runs but the latest evaluation run recorded {len(meta.get('trials', []))}; "
                        "the extra runs were entered by hand, and the methodology note describes only the simulated run.")

    files = {}
    path = out / "test_runs.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:      # BOM so Excel on Windows reads UTF-8
        writer = csv.writer(handle)
        writer.writerow(["Scenario", "Trial", "Event start (UTC)", "Alert time (UTC)", "Outcome", "Detected (1/0)",
                         "Seconds to detect", "CPU %", "Memory %", "Notes"])
        for r in runs:
            attack = r["scenario"] != "normal_baseline"
            seconds = (round(timeutil.seconds_between(r["event_start"], r["alert_time"]), 2)
                       if attack and r["detected"] and r["alert_time"] else "")
            outcome = ("Detected" if r["detected"] else "Missed") if attack else OUTCOME["normal_baseline"][0 if r["detected"] else 1]
            writer.writerow([reports.SCENARIO_NAMES[r["scenario"]], r["trial"], r["event_start"], r["alert_time"] or "",
                             outcome, r["detected"], seconds, _blank(r["cpu_percent"]), _blank(r["memory_percent"]),
                             r["notes"] or ""])
    files[str(path)] = "Appendix B: one row per trial"

    path = out / "metrics.csv"
    with open(path, "w", newline="", encoding="utf-8-sig") as handle:
        writer = csv.writer(handle)
        writer.writerow(["Scenario", "Kind", "Trials", "Detected or false alerts", "Rate %", "Mean time to detect (s)",
                         "Avg CPU %", "Avg memory %"])
        for s in summary["scenarios"]:
            writer.writerow([s["name"], s["kind"], s["trials"], s["detected"], _blank(s["rate"]),
                             _blank(s["meanTimeToDetectSeconds"]), _blank(s["avgCpuPercent"]), _blank(s["avgMemoryPercent"])])
        o = summary["overall"]
        writer.writerow(["Overall", "", o["totalRuns"], "", f"detection {_fmt(o['detectionRate'])}; false-positive {_fmt(o['falsePositiveRate'])}",
                         _blank(o["meanTimeToDetectSeconds"]), "", ""])
    files[str(path)] = "Section 3.13 measures per scenario"

    path = out / "metrics.md"
    path.write_text(_metrics_markdown(summary), encoding="utf-8")
    files[str(path)] = "the same table for the report"

    path = out / "methodology.md"
    path.write_text(_methodology(meta, meta_path, summary, warnings), encoding="utf-8")
    files[str(path)] = "test conditions to state in Chapter 4"
    return {"files": files, "warnings": warnings}


def _blank(value):
    return "" if value is None else value


def _metrics_markdown(summary: dict) -> str:
    lines = ["| Scenario | Trials | Detected / false alerts | Rate (%) | Mean time to detect (s) | Avg CPU (%) | Avg memory (%) |",
             "| --- | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for s in summary["scenarios"]:
        label = s["name"] + (" (false-positive rate)" if s["kind"] == "baseline" else " (detection rate)")
        lines.append(f"| {label} | {s['trials']} | {s['detected']} | {_fmt(s['rate'])} | {_fmt(s['meanTimeToDetectSeconds'])} | "
                     f"{_fmt(s['avgCpuPercent'])} | {_fmt(s['avgMemoryPercent'])} |")
    o = summary["overall"]
    lines += ["", f"Overall detection rate {_fmt(o['detectionRate'], '%')}; false-positive rate {_fmt(o['falsePositiveRate'], '%')}; "
                  f"mean time to detect {_fmt(o['meanTimeToDetectSeconds'], ' s')}; {o['totalRuns']} runs in total.", ""]
    return "\n".join(lines)


def _methodology(meta: dict | None, meta_path: str | None, summary: dict, warnings: list) -> str:
    today = timeutil.iso()[:10]
    out = [f"# Evaluation method (generated {today})", ""]
    out += [f"> Check: {w}" for w in warnings] + ([""] if warnings else [])
    if not meta:
        out += ["No run metadata was found, so the test conditions cannot be filled in automatically. The results in "
                "`test_runs.csv` still stand; state the number of repetitions, the traffic conditions, the threshold settings "
                "and how the true start of each event was determined (Section 2.2.16) from your own lab notes.", ""]
        return "\n".join(out)
    t = meta["trialsPerScenario"]
    rules = meta["settings"]
    thresholds = [
        ("Deauthentication flood", f"{rules.get('rule.deauth.threshold')} frames in {rules.get('rule.deauth.window_seconds')} s, "
                                   f"cool-down {rules.get('rule.deauth.cooldown_seconds')} s"),
        ("ARP conflict", f"cool-down {rules.get('rule.arp.cooldown_seconds')} s"),
        ("Rogue access point", f"cool-down {rules.get('rule.rogue_ap.cooldown_seconds')} s"),
        ("Unrecognised device", f"cool-down {rules.get('rule.unauthorised_device.cooldown_seconds')} s"),
    ]
    refresh = rules.get("refresh_interval_seconds", "5")
    realtime = meta["mode"] == "realtime"
    ranges = meta["trafficRanges"]
    out += [
        "## Type of test", "",
        "Simulated replay. The frames are fabricated, header-only 802.11 and ARP frames built from the demo inventory and passed "
        "through the same packet processor, detection engine and event manager that live capture would use. No wireless adapter, "
        "radio or transmission was involved. The results therefore verify the detection logic and the delay inherent in the rules. "
        "They do not show how capture, the radio environment or a busy network affect detection, and they must not be reported "
        "as over-the-air performance.", "",
        "## Repetitions", "",
        f"{t} trials for each of the {len(meta['scenarios'])} scenarios ({summary['overall']['totalRuns']} runs in the log). "
        f"Each trial ran in its own fresh database. Random seed {meta['seed']}; the run is reproducible with "
        f"`flask --app wifiguard evaluate run --trials {t} --seed {meta['seed']} --mode {meta['mode']}`.", "",
        "## Traffic conditions", "",
        f"Normal traffic played throughout each trial ({meta['normalTrafficSeconds']:.0f} s for the baseline): "
        f"beacons at {ranges['normal']['beacons_per_second_per_access_point']} per second from each authorised access point, "
        f"client data frames ({ranges['normal']['client_data_frames_per_second']}), ARP replies "
        f"({ranges['normal']['arp_reply_every_seconds']}), client reconnects ({ranges['normal']['client_reconnects']}), "
        f"{ranges['normal']['other_benign_deauthentication_frames']} other benign deauthentication frames, and a neighbouring "
        f"network that is not ours. In the attack scenarios the attack began between {meta['attackOffsetSeconds'][0]:.0f} and "
        f"{meta['attackOffsetSeconds'][1]:.0f} s into this traffic and the trial listened for {meta['graceSeconds']:.0f} s after "
        "it ended. Attack parameters were drawn at random for each trial from these ranges:", "",
    ]
    for name in ("deauth", "arp_conflict", "rogue_ap", "unknown_device"):
        out.append(f"- **{reports.SCENARIO_NAMES[name]}**: " + "; ".join(f"{k.replace('_', ' ')}: {v}" for k, v in ranges[name].items()))
    out += ["", "## Threshold settings", ""]
    out += [f"- {name}: {value}" for name, value in thresholds]
    out += [f"- Institutional network name: {rules.get('institutional_ssid')}", "",
            "## How the true start and the alert time were determined", "",
            "The true start of an attack is the release time of its first malicious frame, known exactly because the harness "
            "released it. The alert time is the timestamp the event manager recorded on the alert it created, read back from the "
            "database. Mean time to detect is the mean of (alert time - event start) over detected trials, as in Section 3.13. "
            "A trial counts as detected when an alert of the expected category was created at or after the start; for the "
            "baseline, any alert at all counts as a false positive.", "",
            "The ARP, rogue access point and unrecognised-device rules fire on the first matching frame, so their simulated time "
            "to detect is about zero by design. The deauthentication rule needs to accumulate its threshold, so its time to detect "
            "reflects the attack's frame rate. A real deployment adds capture delay and, for the administrator, the dashboard's "
            f"refresh interval ({refresh} s); the alert time recorded here is when the alert was created, not when it was displayed.", "",
            "## Resource utilisation", "",
            ("CPU and memory are those of the WiFiGuard process (psutil) while it analysed the traffic in real time, averaged over "
             "each trial window. They include analysis and database writes but not packet capture."
             if realtime else
             "Not measured: this run used the virtual-clock fast mode, which analyses traffic as fast as possible and says nothing "
             "about load. Re-run with `--mode realtime` to record CPU and memory."), "",
            "## Environment", "",
            f"Python {meta['environment']['python']}, Scapy {meta['environment']['scapy']}, {meta['environment']['platform']}, "
            f"{meta['environment']['cpuCount']} logical CPUs. WiFiGuard evaluation tool {meta['version']}. "
            f"Run started {meta['startedAt']}. Metadata file: `{Path(meta_path).name if meta_path else 'n/a'}`.", "",
            "## Limitations to state", "",
            "- Attack intensities were chosen above the configured thresholds, so a high detection rate for them is expected; the "
            "threshold sweep (`flask --app wifiguard evaluate sweep`) shows behaviour at and below the deauthentication threshold.",
            "- One demo network, one set of client behaviours, one machine. Results do not transfer to other environments without "
            "testing there.",
            "- Fabricated frames cannot reveal capture loss, channel hopping misses, driver quirks or real client behaviour. "
            "Live lab trials (docs/evaluation.md) are needed for any claim about real networks.", ""]
    return "\n".join(out)


def settings_for_run() -> dict:
    """Current settings of the connected database, used so an evaluation measures the system as configured."""
    return st.get_all()
