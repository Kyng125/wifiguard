# Evaluation (Phase 4, Chapter 4)

Implements the five-scenario method of report Section 3.12 and the measures of Section 3.13: detection rate, false-positive
rate, mean time to detect, and resource use, from repeated trials with the raw observations recorded (Appendix B).

## What this is, and what it is not

`flask --app wifiguard evaluate ...` runs **simulated trials**. Fabricated, header-only frames go through the real packet
processor, detection engine and event manager, and the results are written to the same `test_runs` log the Reports screen
reads. That verifies the detection logic and the delay built into the rules, reproducibly, on any laptop.

It does **not** show how capture, the radio environment, channel hopping, a busy network or real client behaviour affect
detection. Do not report these figures as over-the-air performance. Live lab trials are recorded separately (last section).

## Running it

```bash
flask --app wifiguard evaluate run                        # preview: 5 scenarios x 10 trials, seconds to run, stores nothing
flask --app wifiguard evaluate run --save                 # store the results in the Reports test-run log
flask --app wifiguard evaluate run --mode realtime --save --replace     # wall-clock run, about 30 minutes, adds CPU and memory
flask --app wifiguard evaluate sweep                      # how the deauthentication rule behaves at and below its threshold
flask --app wifiguard evaluate export                     # CSV, table and methodology note for the report
```

On Windows use `python -m flask --app wifiguard ...`. Useful options for `run`: `--trials N` (default 10), `--seed N`
(default 1; the same seed repeats a run exactly), `--scenario NAME` (repeatable), `--speed X` (realtime only; compressing time
changes frame rates, so leave it at 1 for reported results).

- `--save` replaces the demo sample rows. Earlier **real** results are never overwritten unless you add `--replace`.
- The trials use the **current rule settings** from the database, so change a threshold on the Detection Rules screen or in
  Settings, run again, and compare. Each run's settings are written to its metadata file.
- The results appear on the Reports screen once that screen is built; until then use `export`.

## What one trial does

1. A fresh copy of a seeded demo database with no alerts is made, so trials cannot affect each other. (A rule cool-down, or a
   device already "observed" in one trial, never carries into the next.)
2. Varied normal traffic plays for the whole trial: beacons from every authorised access point, known clients sending data and
   ARP replies, reconnects, a few roaming deauthentication frames, and a neighbouring network that is not ours.
3. In an attack scenario the attack is layered on top at a random moment 5 to 15 seconds in, with parameters drawn at random
   for that trial. The baseline trial is 60 seconds of normal traffic only.
4. **True start** = the release time of the attack's first malicious frame (known exactly, because the harness released it).
   **Alert time** = the timestamp the event manager recorded on the alert, read back from the database.
5. **Detected** = an alert of the expected category was created at or after the start. For the baseline, **any alert is a
   false positive**.

`fast` mode uses a virtual clock (frame times are exact, nothing sleeps). `realtime` uses the wall clock and also records the
CPU and memory of the WiFiGuard process while it analyses the traffic (psutil, averaged over the trial); that excludes packet
capture, which does not exist in replay.

## Test conditions (what Chapter 4 must state)

| Scenario | What varies from trial to trial |
| --- | --- |
| Normal baseline | 60 s; beacons at 10/s per access point; 0.5 to 3 data frames/s and an ARP reply every 5 to 15 s per known client; 0 to 2 reconnects per client with 1 to 3 roaming deauthentication frames; 0 to 12 other benign deauthentication frames; neighbouring network |
| Deauthentication | 120 to 300 frames over 4 to 9 s, from a random authorised access point, broadcast (50%) or to one client |
| ARP conflict | 1 to 3 spoofed replies, 0.5 to 3 s apart, claiming a known client's IP from a random locally administered MAC |
| Rogue access point | 2 to 5 s of beacons at 10/s on channel 1, 6 or 11; 75% an unauthorised BSSID with a known network name (Open, WPA2 or WPA3), 25% an authorised BSSID cloned with weaker security |
| Unknown device | random vendor or randomised address on a random authorised access point; authentication, association and data, or data only |

`export` writes the same information, the thresholds in force, the seed, the environment and the limits into
`methodology.md`, so the report states the number of repetitions, the traffic conditions, the threshold settings and the method
for the true start, as Section 2.2.16 asks.

## Reading the results

- **A high detection rate here is expected, not an achievement.** The attack intensities are above the configured thresholds. The
  harness can fail, and the tests prove it does (a threshold raised to 1000 gives 0% detection, a disabled rule gives misses,
  a threshold lowered to 3 gives false positives), but 100% on well-formed attacks only says the rules do what they claim.
- **Mean time to detect is about 0 for three rules by design.** ARP, rogue access point and unrecognised device fire on the first
  matching frame. The deauthentication figure reflects how long the attack takes to reach the threshold: it depends on the
  attack's frame rate, not on the software being slow. Real deployments add capture delay and the dashboard refresh interval
  (the alert time here is when the alert was created, not when it was displayed).
- **The sweep is the more informative table for calibration.** It shows detection with 50, 80, 95, 99, 100, 101... frames in an
  8 s burst, and with a fixed 150 frames stretched over 5 to 30 s, so the report can show where the threshold sits relative to
  attack rates and to the benign roaming ceiling. Each baseline trial's notes record the highest benign deauthentication count
  in any 10 s window (Section 2.2.15 suggests choosing thresholds from observed normal traffic).
- **The false-positive rate is only as good as the baseline.** Here it covers ordinary activity of known clients. It says nothing
  about a crowded lecture hall or unusual devices. Section 3.13 defines it per legitimate test event; each 60 s baseline trial is
  one such event.
- Report the number of trials per scenario next to every percentage, as the literature review recommends, and keep the
  per-scenario rows (`metrics.md`) rather than only the overall figure.

## Live lab trials (recording protocol only)

This project includes **no tool that transmits attack frames**, and none will be added. To evaluate on a real network:

1. Use an **isolated, authorised** lab network you own, with a monitor-mode adapter on a Linux host. The live capture side is not
   built; see `live-capture-backup.md`.
2. Keep live results in their own database so they do not mix with simulated ones: start WiFiGuard with a different
   `WIFIGUARD_INSTANCE` folder.
3. Generate each test event with whatever approved method your supervisor and lab policy allow, on your own equipment, and note
   the **start time from the generating device's clock**. Synchronise both clocks first (NTP). The API refuses an alert time
   earlier than the event start, which usually means the clocks disagree.
4. For each trial record: scenario, event start (UTC), the alert id if one appeared, whether it was detected, CPU and memory
   from the Dashboard, and notes (traffic conditions, channel, distance). Log it with `POST /api/test-runs`
   (`{scenario, eventStart, alertEventId, detected, cpuPercent, memoryPercent, notes}`); giving `alertEventId` takes the real alert
   timestamp automatically. The Reports screen is meant to offer the same as a form once it is built.
5. Run the baseline first for a fixed observation window per trial (for example ten-minute windows of ordinary use), record any
   alert in it as a false positive (`detected: true`), and repeat the same number of trials for every scenario.
6. Mask MAC addresses in anything shared outside the project team (Section 3.14), and store no content, only what the
   rules need.

`evaluate export` works on live results too, but its methodology note is only auto-filled for simulated runs; for live trials it
says so and leaves the conditions for you to describe.

## If something looks wrong

| You see | It means |
| --- | --- |
| `test_runs already holds N real result(s)` | A finished evaluation is already stored. Add `--replace` to overwrite it. |
| `Check: ... only demo sample rows` | You exported before running `--save`; the files are placeholders. |
| `Check: ... entered by hand` | The log has runs that did not come from the harness; the methodology note describes only the simulated run. |
| `MTTD` shows `n/a` for a scenario | No trial in it was detected, or all were. For the baseline it is always `n/a`. |
| CPU and memory `n/a` | The run used `fast` mode; use `--mode realtime`. |
