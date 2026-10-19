"""Packet-processing module (report Section 3.6.2): raw Scapy packet -> normalised Frame.

Only header fields are read. Payloads are never stored, logged or returned. Malformed or incomplete
frames yield None (and are counted by Processor) instead of raising.
"""
import logging
import re

from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Deauth, Dot11Disas, Dot11Elt, Dot11ProbeResp, RadioTap
from scapy.layers.l2 import ARP

from .frames import Frame, is_group_mac

log = logging.getLogger(__name__)

_MAC = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$")

MGMT_SUBTYPES = {
    0: "association_request", 1: "association_response", 2: "reassociation_request",
    3: "reassociation_response", 4: "probe_request", 5: "probe_response", 8: "beacon",
    10: "disassociation", 11: "authentication", 12: "deauthentication",
}
# Management frames that prove a client is present (the unauthorised-device rule uses these).
STATION_MGMT = {"association_request", "reassociation_request", "authentication"}

# RSN authentication-and-key-management suite types (IEEE 802.11-2020, Table 9-190)
AKM_SAE = {8, 9, 24, 25}
AKM_PSK = {2, 4, 6}
AKM_OWE = {18}


def _mac(value) -> str | None:
    if not value:
        return None
    text = str(value).upper()
    return text if _MAC.match(text) else None


def _elements(pkt) -> dict:
    """Information elements as {id: value bytes}; vendor elements (221) are collected in a list.

    The elements are walked as raw type-length-value bytes instead of through Scapy's Dot11Elt chain, because Scapy
    stops chaining after some element subclasses and its subclasses differ between versions.
    """
    first = pkt.getlayer(Dot11Elt)
    found: dict = {}
    if first is None:
        return found
    raw = bytes(first)
    i = 0
    while i + 2 <= len(raw):
        element_id, length = raw[i], raw[i + 1]
        if i + 2 + length > len(raw):
            break                                    # truncated or trailing checksum bytes
        info = raw[i + 2:i + 2 + length]
        if element_id == 221:
            found.setdefault(221, []).append(info)
        else:
            found.setdefault(element_id, info)
        i += 2 + length
    return found


def _ssid(elements: dict) -> str | None:
    raw = elements.get(0)
    if not raw or not raw.strip(b"\x00"):
        return None  # hidden network
    return raw.decode("utf-8", errors="replace")


def _akm_types(rsn: bytes) -> set[int]:
    """AKM suite types from an RSN element; empty set if it is truncated."""
    try:
        offset = 2 + 4                               # version, group cipher suite
        pairwise = int.from_bytes(rsn[offset:offset + 2], "little")
        offset += 2 + 4 * pairwise
        count = int.from_bytes(rsn[offset:offset + 2], "little")
        offset += 2
        suites = [rsn[offset + 4 * i: offset + 4 * i + 4] for i in range(count)]
        return {s[3] for s in suites if len(s) == 4 and s[:3] == b"\x00\x0f\xac"}
    except (IndexError, ValueError):
        return set()


def security_mode(elements: dict, capability: int) -> str:
    """Classify the security mode advertised in a beacon or probe response."""
    rsn = elements.get(48)
    if rsn is not None:
        akms = _akm_types(rsn)
        if akms & AKM_SAE:
            return "WPA2/WPA3" if (akms - AKM_SAE - AKM_OWE) else "WPA3"
        if akms and akms <= AKM_OWE:
            return "Unknown"                         # Enhanced Open: encrypted but unauthenticated
        return "WPA2"
    if any(v[:4] == b"\x00\x50\xf2\x01" for v in elements.get(221, [])):
        return "WPA"
    return "WEP" if capability & 0x10 else "Open"


def freq_to_channel(mhz: int | None) -> int | None:
    if not mhz:
        return None
    if mhz == 2484:
        return 14
    if 2412 <= mhz <= 2472:
        return (mhz - 2407) // 5
    if 5000 <= mhz <= 5895:
        return (mhz - 5000) // 5
    if 5955 <= mhz <= 7115:                          # 6 GHz
        return (mhz - 5950) // 5
    return None


def _channel(pkt, elements: dict, hint: int | None) -> int | None:
    ds = elements.get(3)
    if ds:
        return ds[0]
    ht = elements.get(61)
    if ht:
        return ht[0]
    radiotap = pkt.getlayer(RadioTap)
    if radiotap is not None:
        channel = freq_to_channel(getattr(radiotap, "ChannelFrequency", None))
        if channel:
            return channel
    return hint


def _signal(pkt) -> int | None:
    radiotap = pkt.getlayer(RadioTap)
    value = getattr(radiotap, "dBm_AntSignal", None) if radiotap is not None else None
    return int(value) if value is not None else None


def parse_dot11(pkt, channel_hint: int | None = None) -> Frame | None:
    """802.11 management and data frames. Control frames and unknown subtypes return None."""
    dot11 = pkt.getlayer(Dot11)
    if dot11 is None:
        return None
    ts = float(pkt.time)
    addr1, addr2, addr3 = _mac(dot11.addr1), _mac(dot11.addr2), _mac(dot11.addr3)
    flags = int(dot11.FCfield) & 3                   # bit 0 to-DS, bit 1 from-DS

    if dot11.type == 0:                              # management
        kind = MGMT_SUBTYPES.get(dot11.subtype, "management_other")
        frame = Frame(ts=ts, frame_type="management", kind=kind, transmitter=addr2, receiver=addr1, bssid=addr3,
                      signal=_signal(pkt))
        if kind in ("beacon", "probe_response"):
            elements = _elements(pkt)
            layer = pkt.getlayer(Dot11Beacon) or pkt.getlayer(Dot11ProbeResp)
            frame.ssid = _ssid(elements)
            frame.channel = _channel(pkt, elements, channel_hint)
            frame.security_mode = security_mode(elements, int(layer.cap) if layer is not None else 0)
            frame.bssid = addr3 or addr2
        else:
            frame.channel = _channel(pkt, {}, channel_hint)
        if kind in ("deauthentication", "disassociation"):
            layer = pkt.getlayer(Dot11Deauth) or pkt.getlayer(Dot11Disas)
            frame.reason_code = int(layer.reason) if layer is not None else None
        if kind in STATION_MGMT and addr2 and addr2 != addr3 and not is_group_mac(addr2):
            frame.station = addr2
        return frame

    if dot11.type == 2:                              # data
        if flags == 1:                               # station -> AP
            bssid, station = addr1, addr2
        elif flags == 2:                             # AP -> station
            bssid, station = addr2, addr1
        elif flags == 0:                             # ad hoc / direct: no AP, so no association
            bssid, station = addr3, None
        else:                                        # WDS bridge
            bssid, station = None, None
        if station and (is_group_mac(station) or station == bssid):
            station = None
        return Frame(ts=ts, frame_type="data", kind="data", transmitter=addr2, receiver=addr1, bssid=bssid,
                     channel=_channel(pkt, {}, channel_hint), signal=_signal(pkt), station=station)
    return None


def parse_arp(pkt) -> Frame | None:
    """ARP request or reply (Ethernet, or 802.11 data once decrypted)."""
    arp = pkt.getlayer(ARP)
    if arp is None or int(arp.op) not in (1, 2):
        return None
    return Frame(
        ts=float(pkt.time), frame_type="arp", kind="arp_request" if int(arp.op) == 1 else "arp_reply",
        arp_op=int(arp.op), arp_sender_ip=str(arp.psrc), arp_sender_mac=_mac(arp.hwsrc),
        arp_target_ip=str(arp.pdst), arp_target_mac=_mac(arp.hwdst),
        transmitter=_mac(arp.hwsrc), receiver=_mac(arp.hwdst),
    )


def parse(pkt, channel_hint: int | None = None) -> Frame | None:
    """Parse any packet. Raises on malformed input; use Processor for the discard-and-count behaviour."""
    if pkt.haslayer(ARP):
        return parse_arp(pkt)
    if pkt.haslayer(Dot11):
        return parse_dot11(pkt, channel_hint)
    return None


class Processor:
    """Wraps parse() with the report's behaviour: malformed frames are discarded with a debug log."""

    def __init__(self, channel_hint: int | None = None):
        self.channel_hint = channel_hint
        self.parsed = 0
        self.ignored = 0
        self.dropped = 0

    def process(self, pkt) -> Frame | None:
        try:
            frame = parse(pkt, self.channel_hint)
        except Exception as exc:                     # noqa: BLE001 - one bad frame must never stop capture
            self.dropped += 1
            log.debug("discarded malformed frame: %s", exc)
            return None
        if frame is None:
            self.ignored += 1
        else:
            self.parsed += 1
        return frame
