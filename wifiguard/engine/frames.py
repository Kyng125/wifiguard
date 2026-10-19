"""Normalised data passed between the packet processor, the rules and the pipeline."""
from dataclasses import dataclass, field

BROADCAST = "FF:FF:FF:FF:FF:FF"

# Frame kinds produced by the processor.
MGMT_KINDS = ("beacon", "probe_request", "probe_response", "association_request", "association_response",
              "reassociation_request", "reassociation_response", "authentication", "deauthentication",
              "disassociation", "management_other")


def is_group_mac(mac: str | None) -> bool:
    """True for broadcast/multicast addresses (least-significant bit of the first octet is 1)."""
    return bool(mac) and bool(int(mac[:2], 16) & 1)


def is_locally_administered(mac: str | None) -> bool:
    """Randomised (private) addresses set the locally-administered bit (0x02) of the first octet."""
    return bool(mac) and bool(int(mac[:2], 16) & 2)


@dataclass(slots=True)
class Frame:
    """One captured frame reduced to the fields the rules need (never the payload)."""
    ts: float                         # capture time, seconds since the epoch
    frame_type: str                   # management | data | arp   (matches frame_samples.frame_type)
    kind: str                         # beacon, deauthentication, data, arp, ...
    transmitter: str | None = None
    receiver: str | None = None
    bssid: str | None = None
    ssid: str | None = None
    channel: int | None = None
    signal: int | None = None         # dBm
    security_mode: str | None = None  # Open | WEP | WPA | WPA2 | WPA3 | WPA2/WPA3 (beacons, probe responses)
    reason_code: int | None = None    # deauthentication / disassociation
    station: str | None = None        # the client MAC this frame shows to be present, if any
    arp_op: int | None = None         # 1 request, 2 reply
    arp_sender_ip: str | None = None
    arp_sender_mac: str | None = None
    arp_target_ip: str | None = None
    arp_target_mac: str | None = None


@dataclass(slots=True)
class Detection:
    """A rule match, handed to the alert and event manager (events.create_event)."""
    category: str
    source: str
    target: str | None
    description: str
    evidence: dict
    ssid: str | None = None
    bssid: str | None = None
    channel: int | None = None
    dedupe_key: str | None = None
    cooldown_seconds: int | None = None
    ts: float = 0.0
    rule: str = ""


@dataclass(slots=True)
class AccessPointSeen:
    bssid: str
    ssid: str | None
    channel: int | None
    signal: int | None
    security_mode: str | None
    ts: float


@dataclass(slots=True)
class DeviceSeen:
    mac: str
    bssid: str | None
    ts: float


@dataclass(slots=True)
class ArpSeen:
    ip: str
    mac: str
    ts: float


Observation = AccessPointSeen | DeviceSeen | ArpSeen


@dataclass(slots=True)
class EngineStats:
    frames: int = 0
    by_kind: dict = field(default_factory=dict)
    detections: int = 0
    dropped: int = 0                  # malformed frames the processor discarded
