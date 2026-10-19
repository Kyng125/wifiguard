"""Frame sources: where frames come from. Today that is recorded pcap files replayed at their original pace.

A source only has to turn something into `Frame` objects with a capture time. The engine, rules and pipeline never
know whether a frame came from a file or a radio. A live-capture source (the original Phase 3, see
docs/live-capture-backup.md) would be a second implementation of the same idea, so nothing downstream changes.

Replay rebases time: each scenario starts "now" and its frames are stamped with the moment they are released, so
the engine, the dashboard and the alert timestamps all see ordinary live-looking traffic. Looping a scenario, or
layering an attack on top of the baseline, therefore never makes time run backwards.
"""
import heapq
import queue
import re
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Iterator

from .frames import Frame
from .processor import Processor

BASELINE = "baseline"
TICK_SECONDS = 0.25          # longest the mixer sleeps before checking for a newly triggered scenario or a stop request
_ID = re.compile(r"^[A-Za-z0-9_-]+$")

# What the bundled scenarios are and what each should raise. They match the demo dataset (seed_demo.py).
SCENARIO_INFO = {
    "baseline": {
        "label": "Normal activity",
        "description": "Beacons from the authorised access points, known clients and stable ARP. Raises no alerts.",
        "expects": None, "background": True,
    },
    "deauth": {
        "label": "Deauthentication flood",
        "description": "150 deauthentication frames from the Admin Block access point in 8 seconds.",
        "expects": "deauth_flood", "background": False,
    },
    "arp_conflict": {
        "label": "ARP conflict",
        "description": "The Registry laptop's IP address is claimed by a second MAC address.",
        "expects": "arp_conflict", "background": False,
    },
    "rogue_ap": {
        "label": "Rogue access point",
        "description": "An unauthorised access point advertises the Campus-WiFi network name.",
        "expects": "rogue_ap", "background": False,
    },
    "unknown_device": {
        "label": "Unrecognised device",
        "description": "A client that is not on the authorised list joins the Lab 1 access point.",
        "expects": "unauthorised_device", "background": False,
    },
}


# ----------------------------------------------------------------------------- scenario files

def scenario_files(directory: str | Path, name: str) -> list[str]:
    """The pcap files that make up a scenario: `name.pcap` and, if present, `name-arp.pcap` (ARP uses its own link type)."""
    base = Path(directory)
    files = [base / f"{name}.pcap", base / f"{name}.pcapng", base / f"{name}-arp.pcap"]
    return [str(f) for f in files if f.is_file()]


def list_scenarios(directory: str | Path) -> list[dict]:
    """Every scenario available: the bundled ones that have files, plus any other pcap dropped into the folder."""
    base = Path(directory)
    names = set()
    if base.is_dir():
        for f in base.iterdir():
            if f.suffix in (".pcap", ".pcapng") and not f.stem.endswith("-arp") and _ID.match(f.stem):
                names.add(f.stem)
    ordered = [n for n in SCENARIO_INFO if n in names] + sorted(names - set(SCENARIO_INFO))
    out = []
    for name in ordered:
        info = SCENARIO_INFO.get(name, {})
        out.append({
            "id": name,
            "label": info.get("label", name.replace("_", " ").replace("-", " ").capitalize()),
            "description": info.get("description", "A recorded capture placed in the replay folder."),
            "expects": info.get("expects"),
            "background": info.get("background", False),
            "bundled": name in SCENARIO_INFO,
        })
    return out


def frames_from_files(paths: list[str], processor: Processor) -> Iterator[Frame]:
    """Frames from one or more pcap files merged into capture-time order, read one packet at a time."""
    from scapy.utils import PcapReader

    def one(path: str) -> Iterator[Frame]:
        reader = PcapReader(path)
        try:
            for packet in reader:
                frame = processor.process(packet)
                if frame is not None:
                    yield frame
        finally:
            reader.close()

    return heapq.merge(*(one(p) for p in paths), key=lambda f: f.ts)


# ------------------------------------------------------------------------------------- mixer

@dataclass
class _Stream:
    name: str
    background: bool
    frames: Iterator[Frame]
    wall0: float                      # when the stream began, on the wall clock
    first: float | None = None        # capture time of its first frame
    prev: float | None = None
    shift: float = 0.0                # time removed by capping long silences
    pending: Frame | None = None
    due: float = 0.0                  # wall-clock time at which `pending` is released


class ReplayMixer:
    """Releases frames from one background stream and any number of triggered streams on the wall clock.

    - `background` (a scenario id, or None) plays first and, if `loop`, restarts whenever it ends.
    - `add(name)` starts another scenario now, layered on top of whatever is playing.
    - Frames come out in release order with `ts` set to the release time, so time never goes backwards.
    - Silences longer than `max_gap` seconds are shortened, so a recording with a long pause does not stall a demo.
    - `speed` scales time: 2.0 releases the recording twice as fast, which also doubles its frame rates.

    `clock`, `wait` and `open_stream` are injectable so the pacing can be tested without sleeping.
    """

    def __init__(self, open_stream: Callable[[str], Iterator[Frame]], background: str | None = BASELINE,
                 loop: bool = True, speed: float = 1.0, max_gap: float = 2.0,
                 clock: Callable[[], float] = time.time, wait: Callable[[float], bool] | None = None,
                 tick: Callable[[], None] | None = None):
        if speed <= 0:
            raise ValueError("speed must be positive")
        self.open_stream = open_stream
        self.background = background
        self.loop = loop
        self.speed = speed
        self.max_gap = max_gap
        self.clock = clock
        self.wait = wait
        self.tick = tick
        self._inbox: queue.SimpleQueue = queue.SimpleQueue()
        self._streams: list[_Stream] = []
        self.finished_background = False

    # thread-safe: call from any thread
    def add(self, name: str) -> None:
        self._inbox.put(name)

    def active(self) -> list[str]:
        """Names of the triggered (non-background) scenarios still playing."""
        return [s.name for s in list(self._streams) if not s.background and s.pending is not None]

    # ------------------------------------------------------------------ internals

    def _open(self, name: str, background: bool) -> None:
        stream = _Stream(name, background, self.open_stream(name), self.clock())
        self._advance(stream)
        if stream.pending is not None:
            self._streams.append(stream)
        elif background:
            self.finished_background = True       # an empty recording must not be restarted in a tight loop

    def _advance(self, s: _Stream) -> None:
        frame = next(s.frames, None)
        if frame is None:
            s.pending = None
            return
        if s.first is None:
            s.first = s.prev = frame.ts
        gap = (frame.ts - s.prev) / self.speed
        if gap > self.max_gap:
            s.shift += gap - self.max_gap
        s.prev = frame.ts
        s.pending = frame
        s.due = s.wall0 + (frame.ts - s.first) / self.speed - s.shift

    def run(self, stop: threading.Event) -> Iterator[tuple[Frame, str]]:
        wait = self.wait or stop.wait
        if self.background:
            self._open(self.background, True)
        while not stop.is_set():
            if self.tick:
                self.tick()
            while True:
                try:
                    self._open(self._inbox.get_nowait(), False)
                except queue.Empty:
                    break
            self._streams = [s for s in self._streams if s.pending is not None]
            if self.background and self.loop and not self.finished_background and not any(s.background for s in self._streams):
                self._open(self.background, True)
            live = self._streams
            if not live:
                if wait(TICK_SECONDS):
                    return
                continue
            stream = min(live, key=lambda s: s.due)
            delay = stream.due - self.clock()
            if delay > 0:
                if wait(min(delay, TICK_SECONDS)):
                    return
                continue                          # a scenario may have been triggered meanwhile; look again
            frame = stream.pending
            frame.ts = stream.due
            yield frame, stream.name
            self._advance(stream)
