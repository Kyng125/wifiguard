"""Connects the engine to the database: observations go to the observed_* tables, detections go to the
alert and event manager. Detection logic itself never touches the database (report Section 3.6.3).

Needs a Flask app context (the services use the request-scoped connection). The capture thread in Phase 3
creates one context for its lifetime.
"""
import time
from datetime import datetime, timezone

from .. import db, timeutil
from ..services import events
from .engine import DetectionEngine, EngineConfig
from .frames import AccessPointSeen, ArpSeen, Detection, DeviceSeen, Frame
from .processor import Processor
from .reference import Reference


def _iso(ts: float) -> str:
    return timeutil.iso(datetime.fromtimestamp(ts, tz=timezone.utc))


class Pipeline:
    """frame -> engine -> database.

    stamp="capture" timestamps alerts with the frame's capture time (live capture, where it equals now).
    stamp="now" timestamps them with the current time (replaying an old pcap so the dashboard shows them as recent).
    """

    def __init__(self, engine: DetectionEngine | None = None, stamp: str = "capture",
                 write_interval: float = 5.0, refresh_seconds: float | None = 10.0, commit_seconds: float = 1.0):
        if stamp not in ("capture", "now"):
            raise ValueError("stamp must be 'capture' or 'now'")
        self.engine = engine or DetectionEngine(Reference.load(), EngineConfig.from_settings())
        self.stamp = stamp
        self.write_interval = write_interval
        self.refresh_seconds = refresh_seconds
        self.commit_seconds = commit_seconds
        self._written: dict[tuple, tuple[float, tuple]] = {}
        self._last_commit = time.monotonic()
        self._last_refresh = time.monotonic()
        self._dirty = False

    # ------------------------------------------------------------------ public

    def handle(self, frame: Frame) -> list[tuple[int, bool, Detection]]:
        """Process one frame. Returns (event_id, created, detection) for every rule match."""
        self._maybe_refresh()
        result = self.engine.process(frame)
        for observation in result.observations:
            self._persist(observation)
        matches = []
        for detection in result.detections:
            event_id, created = events.create_event(
                category=detection.category, description=detection.description, source=detection.source,
                target=detection.target, evidence=detection.evidence, ssid=detection.ssid, bssid=detection.bssid,
                channel=detection.channel, dedupe_key=detection.dedupe_key,
                cooldown_seconds=detection.cooldown_seconds,
                event_time=_iso(detection.ts) if self.stamp == "capture" else None, commit=False)
            matches.append((event_id, created, detection))
            self._dirty = True
        self._maybe_commit(force=bool(matches))
        return matches

    def flush(self) -> None:
        self._maybe_commit(force=True)

    def refresh(self) -> None:
        """Pick up inventory and threshold changes made on the dashboard."""
        self.engine.reference.reload_inventory()
        self.engine.configure(EngineConfig.from_settings())
        self._last_refresh = time.monotonic()

    # ----------------------------------------------------------------- internals

    def _maybe_refresh(self) -> None:
        if self.refresh_seconds and time.monotonic() - self._last_refresh >= self.refresh_seconds:
            self.refresh()

    def _maybe_commit(self, force: bool = False) -> None:
        if self._dirty and (force or time.monotonic() - self._last_commit >= self.commit_seconds):
            db.get_db().commit()
            self._dirty = False
            self._last_commit = time.monotonic()

    def _should_write(self, key: tuple, values: tuple, ts: float) -> bool:
        """Coalesce repeats: a beacon arrives ~10 times a second, the database needs it every few seconds."""
        previous = self._written.get(key)
        if previous and previous[1] == values and ts - previous[0] < self.write_interval:
            return False
        self._written[key] = (ts, values)
        if len(self._written) > 5000:
            self._written = dict(list(self._written.items())[-2500:])
        return True

    def _persist(self, obs) -> None:
        conn = db.get_db()
        stamp = _iso(obs.ts)
        if isinstance(obs, AccessPointSeen):
            if not self._should_write(("ap", obs.bssid), (obs.ssid, obs.channel, obs.security_mode), obs.ts):
                return
            conn.execute(
                "INSERT INTO observed_access_points (ssid, bssid, channel, signal_strength, security_mode, first_seen, last_seen) "
                "VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(bssid) DO UPDATE SET "
                "ssid = COALESCE(excluded.ssid, ssid), channel = COALESCE(excluded.channel, channel), "
                "signal_strength = COALESCE(excluded.signal_strength, signal_strength), "
                "security_mode = COALESCE(excluded.security_mode, security_mode), last_seen = excluded.last_seen",
                (obs.ssid, obs.bssid, obs.channel, obs.signal, obs.security_mode, stamp, stamp))
        elif isinstance(obs, DeviceSeen):
            if not self._should_write(("device", obs.mac), (obs.bssid,), obs.ts):
                return
            conn.execute(
                "INSERT INTO observed_devices (mac_address, associated_bssid, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(mac_address) DO UPDATE SET associated_bssid = excluded.associated_bssid, last_seen = excluded.last_seen",
                (obs.mac, obs.bssid, stamp, stamp))
        elif isinstance(obs, ArpSeen):
            if not self._should_write(("arp", obs.ip, obs.mac), (), obs.ts):
                return
            conn.execute(
                "INSERT INTO arp_bindings (ip_address, mac_address, first_seen, last_seen) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(ip_address, mac_address) DO UPDATE SET last_seen = excluded.last_seen",
                (obs.ip, obs.mac, stamp, stamp))
        self._dirty = True


def replay(path: str, pipeline: Pipeline, processor: Processor | None = None) -> dict:
    """Feed a pcap/pcapng file through the pipeline. Returns a summary of what happened."""
    from scapy.utils import PcapReader
    processor = processor or Processor()
    alerts, merged = [], 0
    reader = PcapReader(path)
    try:
        for packet in reader:
            frame = processor.process(packet)
            if frame is None:
                continue
            for event_id, created, detection in pipeline.handle(frame):
                if created:
                    alerts.append((events.display_id(event_id), detection.category, detection.source))
                else:
                    merged += 1
    finally:
        reader.close()
    pipeline.flush()
    return {"frames": processor.parsed, "ignored": processor.ignored, "dropped": processor.dropped,
            "alerts": alerts, "merged": merged}
