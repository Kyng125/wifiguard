"""The detection engine: runs every rule over each frame and keeps the in-memory reference up to date."""
from dataclasses import dataclass, field

from .frames import AccessPointSeen, ArpSeen, Detection, DeviceSeen, EngineStats, Frame, Observation
from .reference import Reference
from .rules import ArpConflictRule, DeauthFloodRule, RogueApRule, UnauthorisedDeviceRule


@dataclass
class EngineConfig:
    deauth_enabled: bool = True
    deauth_threshold: int = 100
    deauth_window_seconds: int = 10
    deauth_cooldown_seconds: int = 60
    arp_enabled: bool = True
    arp_cooldown_seconds: int = 60
    rogue_ap_enabled: bool = True
    rogue_ap_cooldown_seconds: int = 300
    device_enabled: bool = True
    device_cooldown_seconds: int = 300

    @classmethod
    def from_settings(cls) -> "EngineConfig":
        """Read the thresholds from system_settings. Needs a Flask app context."""
        from ..services import settings as st
        return cls(
            deauth_enabled=st.get_bool("rule.deauth.enabled"),
            deauth_threshold=st.get_int("rule.deauth.threshold"),
            deauth_window_seconds=st.get_int("rule.deauth.window_seconds"),
            deauth_cooldown_seconds=st.get_int("rule.deauth.cooldown_seconds"),
            arp_enabled=st.get_bool("rule.arp.enabled"),
            arp_cooldown_seconds=st.get_int("rule.arp.cooldown_seconds"),
            rogue_ap_enabled=st.get_bool("rule.rogue_ap.enabled"),
            rogue_ap_cooldown_seconds=st.get_int("rule.rogue_ap.cooldown_seconds"),
            device_enabled=st.get_bool("rule.unauthorised_device.enabled"),
            device_cooldown_seconds=st.get_int("rule.unauthorised_device.cooldown_seconds"),
        )


@dataclass
class Result:
    detections: list[Detection] = field(default_factory=list)
    observations: list[Observation] = field(default_factory=list)


class DetectionEngine:
    def __init__(self, reference: Reference | None = None, config: EngineConfig | None = None):
        self.reference = reference or Reference()
        self.stats = EngineStats()
        self.rules: list = []
        self.configure(config or EngineConfig())

    def configure(self, config: EngineConfig) -> None:
        """Apply new thresholds. Existing windows and cool-downs are kept, so a live change does not reset detection."""
        self.config = config
        if not self.rules:
            self.rules = [DeauthFloodRule(), ArpConflictRule(), RogueApRule(), UnauthorisedDeviceRule()]
        deauth, arp, rogue, device = self.rules
        deauth.enabled, deauth.threshold = config.deauth_enabled, config.deauth_threshold
        deauth.window_seconds, deauth.cooldown_seconds = config.deauth_window_seconds, config.deauth_cooldown_seconds
        arp.enabled, arp.cooldown_seconds = config.arp_enabled, config.arp_cooldown_seconds
        rogue.enabled, rogue.cooldown_seconds = config.rogue_ap_enabled, config.rogue_ap_cooldown_seconds
        device.enabled, device.cooldown_seconds = config.device_enabled, config.device_cooldown_seconds

    def process(self, frame: Frame) -> Result:
        """Apply the rules relevant to this frame, then update what has been observed."""
        self.stats.frames += 1
        self.stats.by_kind[frame.kind] = self.stats.by_kind.get(frame.kind, 0) + 1
        result = Result()
        for rule in self.rules:
            result.detections.extend(rule.evaluate(frame, self.reference))
        self.stats.detections += len(result.detections)
        self._observe(frame, result.observations)
        return result

    def _observe(self, frame: Frame, out: list[Observation]) -> None:
        ref = self.reference
        if frame.kind in ("beacon", "probe_response") and frame.bssid:
            ref.observed_aps.add(frame.bssid)
            out.append(AccessPointSeen(frame.bssid, frame.ssid, frame.channel, frame.signal,
                                       frame.security_mode, frame.ts))
        if frame.station and frame.bssid in ref.authorised_aps:
            ref.observed_devices.add(frame.station)
            out.append(DeviceSeen(frame.station, frame.bssid, frame.ts))
        if frame.kind == "arp_reply" and ArpConflictRule.valid_binding(frame.arp_sender_ip, frame.arp_sender_mac):
            ref.arp_table[frame.arp_sender_ip] = frame.arp_sender_mac
            out.append(ArpSeen(frame.arp_sender_ip, frame.arp_sender_mac, frame.ts))
        elif frame.kind == "arp_request" and ArpConflictRule.valid_binding(frame.arp_sender_ip, frame.arp_sender_mac):
            # A request teaches a binding for an IP not seen before, but never overwrites or raises a conflict.
            if frame.arp_sender_ip not in ref.arp_table:
                ref.arp_table[frame.arp_sender_ip] = frame.arp_sender_mac
                out.append(ArpSeen(frame.arp_sender_ip, frame.arp_sender_mac, frame.ts))
