"""Runs the detection engine in the background from a replay source and keeps the dashboard's runtime state fresh.

This is the part that makes WiFiGuard look and behave live without a radio: recorded scenarios are replayed at their
original pace (see sources.py), pass through the same engine and pipeline a live capture would, and the runtime writes
the monitor snapshots and the rolling frame feed that the Network Monitor and Dashboard read.

One runtime per process. Start it from the API (`/api/engine/start`) or `python run.py --demo`. It must not run in
several worker processes at once, or every frame would be analysed twice (run.py uses a single process).
"""
import importlib
import logging
import threading
import time
from datetime import datetime, timezone

from .. import db, timeutil
from .frames import Frame
from .pipeline import Pipeline
from .processor import Processor
from .sources import BASELINE, ReplayMixer, frames_from_files, list_scenarios, scenario_files

log = logging.getLogger(__name__)

SNAPSHOT_SECONDS = 2.0
FEED_PER_SECOND = 6            # frames sampled into the Network Monitor feed per second, flagged ones always
BEACON_SAMPLE_EVERY = 25       # beacons are so frequent that only one in this many is sampled
FEED_KEEP = 300
SNAPSHOT_KEEP = 1000

SUBTYPE_LABELS = {"arp_reply": "reply", "arp_request": "request"}


def _iso(ts: float) -> str:
    return timeutil.iso(datetime.fromtimestamp(ts, tz=timezone.utc))


def subtype_label(frame: Frame) -> str:
    """The feed shows subtypes the way the frontend expects: 'probe-response', 'association-request', 'reply'."""
    return SUBTYPE_LABELS.get(frame.kind, frame.kind.replace("_", "-"))


class _Meter:
    """Counts frames and turns the totals into the numbers a monitor snapshot holds."""

    def __init__(self):
        self.total = self.management = self.data = self.arp = 0
        self.channel = None
        self._mark_time = time.monotonic()
        self._mark_total = 0

    def add(self, frame: Frame) -> None:
        self.total += 1
        if frame.frame_type == "management":
            self.management += 1
        elif frame.frame_type == "data":
            self.data += 1
        else:
            self.arp += 1
        if frame.channel:
            self.channel = frame.channel

    def rate(self) -> int:
        now = time.monotonic()
        elapsed = max(now - self._mark_time, 1e-6)
        pps = round((self.total - self._mark_total) / elapsed)
        self._mark_time, self._mark_total = now, self.total
        return pps


class _Feed:
    """Samples frames into frame_samples (headers only, never payloads) at a bounded rate."""

    def __init__(self):
        self._tokens = float(FEED_PER_SECOND)
        self._at = time.monotonic()
        self._beacons = 0
        self._last_prune = time.monotonic()

    def _allow(self) -> bool:
        now = time.monotonic()
        self._tokens = min(float(FEED_PER_SECOND), self._tokens + (now - self._at) * FEED_PER_SECOND)
        self._at = now
        if self._tokens >= 1:
            self._tokens -= 1
            return True
        return False

    def record(self, frame: Frame, flag_event_id: int | None) -> None:
        if flag_event_id is None:
            if frame.kind == "beacon":
                self._beacons += 1
                if self._beacons % BEACON_SAMPLE_EVERY:
                    return
            if not self._allow():
                return
        source = frame.transmitter or frame.arp_sender_mac
        destination = frame.receiver or frame.arp_target_mac
        conn = db.get_db()
        conn.execute(
            "INSERT INTO frame_samples (at, frame_type, subtype, source, destination, bssid, channel, flag_event_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (_iso(frame.ts), frame.frame_type, subtype_label(frame), source, destination, frame.bssid,
             frame.channel, flag_event_id))
        if time.monotonic() - self._last_prune > 10:
            conn.execute("DELETE FROM frame_samples WHERE id <= (SELECT MAX(id) FROM frame_samples) - ?", (FEED_KEEP,))
            self._last_prune = time.monotonic()


def _system_load() -> tuple[float | None, float | None]:
    try:
        import psutil
        return psutil.cpu_percent(interval=None), psutil.virtual_memory().percent
    except Exception:                                    # noqa: BLE001 - metrics are optional
        return None, None


def write_snapshot(meter: _Meter, engine_state: str, monitor_state: str, arp_state: str) -> None:
    cpu, memory = _system_load()
    conn = db.get_db()
    conn.execute(
        "INSERT INTO monitor_snapshots (at, packets_total, packets_per_sec, mgmt_count, data_count, arp_count, engine_state, "
        "monitor_state, arp_state, current_channel, cpu_percent, memory_percent) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (timeutil.iso(), meter.total, meter.rate() if engine_state == "running" else 0, meter.management, meter.data,
         meter.arp, engine_state, monitor_state, arp_state, meter.channel, cpu, memory))
    conn.execute("DELETE FROM monitor_snapshots WHERE id <= (SELECT MAX(id) FROM monitor_snapshots) - ?", (SNAPSHOT_KEEP,))
    conn.commit()


class ReplayRuntime:
    """Owns the background thread. All public methods are safe to call from request threads."""

    def __init__(self, app, directory: str):
        self.app = app
        self.directory = directory
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._mixer: ReplayMixer | None = None
        self._state: dict = self._idle_state()

    @staticmethod
    def _idle_state() -> dict:
        return {"running": False, "background": None, "loop": True, "speed": 1.0, "startedAt": None,
                "framesAnalysed": 0, "alertsRaised": 0, "alertsMerged": 0, "triggered": [], "error": None}

    # ------------------------------------------------------------------ control

    def scenarios(self) -> list[dict]:
        return list_scenarios(self.directory)

    def known(self, name: str) -> bool:
        return any(s["id"] == name for s in self.scenarios())

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self, background: str | None = BASELINE, loop: bool = True, speed: float = 1.0) -> None:
        """Begin replaying. `background` plays continuously (None = silence until a scenario is triggered)."""
        with self._lock:
            if self.running:
                raise RuntimeError("already running")
            if background is not None and not self.known(background):
                raise KeyError(background)
            importlib.import_module("scapy.utils")      # fail here, not in the thread, if scapy is missing
            self._stop = threading.Event()
            processor = Processor()
            self._mixer = ReplayMixer(
                lambda name: frames_from_files(scenario_files(self.directory, name), processor),
                background=background, loop=loop, speed=speed)
            self._state = {**self._idle_state(), "running": True, "background": background, "loop": loop,
                           "speed": speed, "startedAt": timeutil.iso()}
            self._thread = threading.Thread(target=self._run, args=(self._mixer, self._stop, processor),
                                            name="wifiguard-replay", daemon=True)
            self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        with self._lock:
            thread, stop = self._thread, self._stop
        if thread is None:
            return
        stop.set()
        thread.join(timeout)

    def trigger(self, name: str) -> None:
        if not self.running or self._mixer is None:
            raise RuntimeError("not running")
        if not self.known(name):
            raise KeyError(name)
        self._mixer.add(name)

    def status(self) -> dict:
        with self._lock:
            state = dict(self._state)
        state["running"] = self.running
        if self._mixer is not None and state["running"]:
            state["triggered"] = self._mixer.active()
        return state

    # ------------------------------------------------------------------ thread

    def _set(self, **values) -> None:
        with self._lock:
            self._state.update(values)

    def _run(self, mixer: ReplayMixer, stop: threading.Event, processor: Processor) -> None:
        meter = _Meter()
        feed = _Feed()
        last_snapshot = 0.0
        raised = merged = 0
        with self.app.app_context():
            try:
                pipeline = Pipeline(stamp="capture", refresh_seconds=10.0)

                def tick() -> None:
                    nonlocal last_snapshot
                    if time.monotonic() - last_snapshot >= SNAPSHOT_SECONDS:
                        write_snapshot(meter, "running", "up", "up")
                        last_snapshot = time.monotonic()
                        self._set(framesAnalysed=meter.total, alertsRaised=raised, alertsMerged=merged)

                mixer.tick = tick
                for frame, _name in mixer.run(stop):
                    meter.add(frame)
                    flag = None
                    for event_id, created, _detection in pipeline.handle(frame):
                        flag = flag or event_id
                        if created:
                            raised += 1
                        else:
                            merged += 1
                    feed.record(frame, flag)
                pipeline.flush()
                self._set(framesAnalysed=meter.total, alertsRaised=raised, alertsMerged=merged)
            except Exception as exc:                     # noqa: BLE001 - report it on the dashboard, never die silently
                log.exception("replay runtime failed")
                self._set(error=f"{type(exc).__name__}: {exc}")
            finally:
                try:
                    write_snapshot(meter, "stopped", "down", "down")
                except Exception:                        # noqa: BLE001
                    log.exception("could not write the final snapshot")
                self._set(running=False)
