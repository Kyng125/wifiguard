"""Detection engine (report Sections 3.6.2, 3.6.3 and 3.10).

    raw frame --processor.parse()--> Frame --DetectionEngine.process()--> detections + observations
                                                                              |
                          pipeline.Pipeline writes them through the event manager and the observed_* tables

Everything except `pipeline` is pure Python with no database or network access, so each rule can be
tested with synthetic frames and pcap files.
"""
from .engine import DetectionEngine, EngineConfig, Result
from .frames import Detection, Frame
from .processor import parse, parse_arp, parse_dot11
from .reference import AuthorisedAP, Reference

__all__ = [
    "AuthorisedAP", "Detection", "DetectionEngine", "EngineConfig", "Frame", "Reference", "Result",
    "parse", "parse_arp", "parse_dot11",
]
