"""The four detection rules (report Section 3.10).

Each rule is a small object with private state (windows, cool-downs) and one method,
`evaluate(frame, reference) -> list[Detection]`. Rules only READ the reference; the engine updates it
after all rules have seen the frame, so "first time seen" checks see the state from before the frame.
All times come from the frame's capture timestamp, so replaying a pcap behaves exactly like live capture.
"""
from collections import Counter, deque
from ipaddress import ip_address

from .frames import BROADCAST, Detection, Frame, is_group_mac, is_locally_administered
from .reference import Reference

# Weakest to strongest. A registered access point that now advertises a lower rank is a downgrade.
SECURITY_RANK = {"Open": 0, "WEP": 1, "WPA": 2, "WPA2": 3, "WPA2/WPA3": 4, "WPA3": 5}


class Cooldown:
    """Per-key quiet period so a rule does not re-fire on every frame of a sustained event."""

    def __init__(self):
        self._until: dict[str, float] = {}
        self._calls = 0

    def ready(self, key: str, now: float, seconds: int) -> bool:
        """True (and starts the cool-down) if `key` is not currently cooling down."""
        if seconds <= 0:
            return True
        if self._until.get(key, float("-inf")) > now:
            return False
        self._until[key] = now + seconds
        self._calls += 1
        if self._calls % 2000 == 0:                  # keep memory bounded on long runs
            self._until = {k: t for k, t in self._until.items() if t > now}
        return True


class DeauthFloodRule:
    """3.10.1: count deauthentication frames per BSSID in a sliding window."""
    id = "deauth"

    def __init__(self, enabled=True, threshold=100, window_seconds=10, cooldown_seconds=60,
                 include_disassociation=False):
        self.enabled, self.threshold = enabled, threshold
        self.window_seconds, self.cooldown_seconds = window_seconds, cooldown_seconds
        self.include_disassociation = include_disassociation
        self._windows: dict[str, deque] = {}
        self._cooldown = Cooldown()

    def evaluate(self, frame: Frame, ref: Reference) -> list[Detection]:
        kinds = ("deauthentication", "disassociation") if self.include_disassociation else ("deauthentication",)
        if not self.enabled or frame.kind not in kinds:
            return []
        key = frame.bssid or frame.transmitter
        if not key:
            return []
        window = self._windows.setdefault(key, deque())
        window.append((frame.ts, frame.receiver, frame.reason_code))
        horizon = frame.ts - self.window_seconds
        while window and window[0][0] < horizon:
            window.popleft()
        if len(window) < self.threshold or not self._cooldown.ready(key, frame.ts, self.cooldown_seconds):
            return []
        count = len(window)
        receivers = Counter(r for _, r, _ in window if r)
        reasons = Counter(c for _, _, c in window if c is not None)
        target = receivers.most_common(1)[0][0] if receivers else BROADCAST
        evidence = {"frameCount": count, "windowSeconds": self.window_seconds, "threshold": self.threshold,
                    "reasonCode": reasons.most_common(1)[0][0] if reasons else None,
                    "distinctTargets": len(receivers)}
        return [Detection(
            category="deauth_flood", source=key, target=target, bssid=frame.bssid, channel=frame.channel,
            ssid=None, ts=frame.ts, rule=self.id, dedupe_key=f"deauth_flood:{key}",
            cooldown_seconds=self.cooldown_seconds, evidence=evidence,
            description=(f"{count} deauthentication frames detected within a {self.window_seconds}-second window "
                         f"(threshold: {self.threshold} frames)"))]


class ArpConflictRule:
    """3.10.2: an ARP reply that gives a known IP address a different MAC address."""
    id = "arp"

    def __init__(self, enabled=True, cooldown_seconds=60):
        self.enabled, self.cooldown_seconds = enabled, cooldown_seconds
        self._cooldown = Cooldown()

    @staticmethod
    def valid_binding(ip: str | None, mac: str | None) -> bool:
        """Ignore ARP probes (0.0.0.0), link-local and group addresses: they are not real bindings."""
        if not ip or not mac or is_group_mac(mac) or mac == "00:00:00:00:00:00":
            return False
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        return not (addr.is_unspecified or addr.is_multicast or addr.is_loopback or addr.is_link_local)

    def evaluate(self, frame: Frame, ref: Reference) -> list[Detection]:
        if not self.enabled or frame.kind != "arp_reply":
            return []
        ip, mac = frame.arp_sender_ip, frame.arp_sender_mac
        if not self.valid_binding(ip, mac):
            return []
        previous = ref.arp_table.get(ip)
        if previous is None or previous == mac or not self._cooldown.ready(ip, frame.ts, self.cooldown_seconds):
            return []
        return [Detection(
            category="arp_conflict", source=ip, target=mac, ts=frame.ts, rule=self.id,
            dedupe_key=f"arp_conflict:{ip}", cooldown_seconds=self.cooldown_seconds,
            evidence={"ip": ip, "previousMac": previous, "newMac": mac},
            description=f"{ip} moved from {previous} to {mac}")]


class RogueApRule:
    """3.10.3: a known or institutional SSID from an unauthorised BSSID.

    Also flags an authorised BSSID that now advertises WEAKER security than it is registered with, which is what a
    cloned-BSSID evil twin looks like. Channel changes alone are not alerted (access points legitimately
    auto-select channels); the channel is recorded in the evidence.
    """
    id = "rogue_ap"

    def __init__(self, enabled=True, cooldown_seconds=300):
        self.enabled, self.cooldown_seconds = enabled, cooldown_seconds
        self._cooldown = Cooldown()

    def evaluate(self, frame: Frame, ref: Reference) -> list[Detection]:
        if not self.enabled or frame.kind not in ("beacon", "probe_response") or not frame.bssid:
            return []
        bssid, ssid, mode = frame.bssid, frame.ssid, frame.security_mode
        registered = ref.authorised_aps.get(bssid)
        if registered is None:
            if not ssid or ssid not in ref.known_ssids:
                return []                            # a neighbouring network: observed, not alerted
            modes = ref.authorised_modes(ssid)
            reason = "unauthorised_bssid"
            description = (f"Access point {bssid} is advertising {ssid} on channel {frame.channel} with {mode}"
                           + (f"; authorised access points use {'/'.join(modes)}" if modes else ""))
            extra = {"authorisedSecurityModes": modes} if modes else {}
        else:
            expected = registered.security_mode
            if (expected not in SECURITY_RANK or mode not in SECURITY_RANK
                    or SECURITY_RANK[mode] >= SECURITY_RANK[expected]):
                return []
            reason = "security_downgrade"
            description = (f"Authorised access point {bssid} is advertising {ssid or 'a hidden network'} with {mode} "
                           f"but is registered with {expected}")
            extra = {"authorisedSecurityModes": [expected]}
        if not self._cooldown.ready(bssid, frame.ts, self.cooldown_seconds):
            return []
        evidence = {"ssid": ssid, "channel": frame.channel, "securityMode": mode, "reason": reason, **extra}
        if frame.signal is not None:
            evidence["signal"] = frame.signal
        return [Detection(
            category="rogue_ap", source=bssid, target=ssid, ssid=ssid, bssid=bssid, channel=frame.channel,
            ts=frame.ts, rule=self.id, dedupe_key=f"rogue_ap:{bssid}", cooldown_seconds=self.cooldown_seconds,
            evidence=evidence, description=description)]


class UnauthorisedDeviceRule:
    """3.10.4: a client MAC on one of OUR access points that is neither authorised nor already observed.

    Clients of neighbouring networks are ignored: a monitor-mode adapter hears every network on the channel,
    and alerting on those would flood the dashboard. The frame must belong to an authorised BSSID.
    """
    id = "unauthorised_device"

    def __init__(self, enabled=True, cooldown_seconds=300):
        self.enabled, self.cooldown_seconds = enabled, cooldown_seconds
        self._cooldown = Cooldown()

    def evaluate(self, frame: Frame, ref: Reference) -> list[Detection]:
        mac = frame.station
        if not self.enabled or not mac or frame.bssid not in ref.authorised_aps:
            return []
        if mac in ref.authorised_devices or mac in ref.observed_devices or ref.is_access_point(mac):
            return []
        if not self._cooldown.ready(mac, frame.ts, self.cooldown_seconds):
            return []
        return [Detection(
            category="unauthorised_device", source=mac, target=frame.bssid, bssid=frame.bssid,
            ssid=ref.authorised_aps[frame.bssid].ssid, channel=frame.channel, ts=frame.ts, rule=self.id,
            dedupe_key=f"unauthorised_device:{mac}", cooldown_seconds=self.cooldown_seconds,
            evidence={"associatedBssid": frame.bssid, "randomisedAddress": is_locally_administered(mac)},
            description=f"Device {mac} associated with {frame.bssid} and is not on the authorised list")]
