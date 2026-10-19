"""Synthetic 802.11 and ARP frames for tests, demos and the sample pcap files.

Used to prove each rule without an adapter: build frames here, write them to a pcap, replay the pcap.
All frames are fabricated; nothing here transmits anything.
"""
import struct

from scapy.layers.dot11 import (
    Dot11, Dot11AssoReq, Dot11Auth, Dot11Beacon, Dot11Deauth, Dot11Elt, Dot11ProbeResp, RadioTap,
)
from scapy.layers.l2 import ARP, Ether
from scapy.utils import wrpcap

BROADCAST = "ff:ff:ff:ff:ff:ff"
CCMP = b"\x00\x0f\xac\x04"
OUI_AKM = {"psk": 2, "sae": 8, "8021x": 1, "owe": 18}


def channel_to_mhz(channel: int) -> int:
    return 2484 if channel == 14 else 2407 + 5 * channel if channel <= 13 else 5000 + 5 * channel


def rsn_element(*akms: str) -> bytes:
    suites = b"".join(b"\x00\x0f\xac" + bytes([OUI_AKM[a]]) for a in akms)
    return (struct.pack("<H", 1) + CCMP + struct.pack("<H", 1) + CCMP
            + struct.pack("<H", len(akms)) + suites + struct.pack("<H", 0))


def wpa1_element() -> bytes:
    return b"\x00\x50\xf2\x01" + struct.pack("<H", 1)


SECURITY = {                                          # mode -> (capability field, extra information elements)
    "Open": (0x0401, []),
    "WEP": (0x0411, []),
    "WPA": (0x0411, [Dot11Elt(ID=221, info=wpa1_element())]),
    "WPA2": (0x0411, [Dot11Elt(ID=48, info=rsn_element("psk"))]),
    "WPA3": (0x0411, [Dot11Elt(ID=48, info=rsn_element("sae"))]),
    "WPA2/WPA3": (0x0411, [Dot11Elt(ID=48, info=rsn_element("psk", "sae"))]),
}


def _radiotap(channel: int | None, signal: int | None):
    present, kwargs = [], {}
    if channel is not None:
        present.append("Channel")
        kwargs.update(ChannelFrequency=channel_to_mhz(channel), ChannelFlags=0x0080)
    if signal is not None:
        present.append("dBm_AntSignal")
        kwargs["dBm_AntSignal"] = signal
    return RadioTap(present="+".join(present), **kwargs) if present else RadioTap()


def _stamp(pkt, ts: float):
    pkt.time = ts
    return pkt


def _elements(ssid: str | None, channel: int | None, security: str):
    items = [Dot11Elt(ID=0, info=(ssid or "").encode())]
    if channel is not None:
        items.append(Dot11Elt(ID=3, info=bytes([channel])))
    items.extend(SECURITY[security][1])
    chain = items[0]
    for item in items[1:]:
        chain = chain / item
    return chain


def beacon(bssid: str, ssid: str | None, channel: int = 6, security: str = "WPA2", ts: float = 0.0, signal: int = -55):
    pkt = (_radiotap(channel, signal)
           / Dot11(type=0, subtype=8, addr1=BROADCAST, addr2=bssid, addr3=bssid)
           / Dot11Beacon(cap=SECURITY[security][0])
           / _elements(ssid, channel, security))
    return _stamp(pkt, ts)


def probe_response(bssid: str, ssid: str, station: str, channel: int = 6, security: str = "WPA2", ts: float = 0.0):
    pkt = (_radiotap(channel, -60)
           / Dot11(type=0, subtype=5, addr1=station, addr2=bssid, addr3=bssid)
           / Dot11ProbeResp(cap=SECURITY[security][0])
           / _elements(ssid, channel, security))
    return _stamp(pkt, ts)


def deauth(bssid: str, station: str = BROADCAST, reason: int = 7, ts: float = 0.0, channel: int = 6):
    """A deauthentication frame as sent by (or spoofed as) the access point."""
    pkt = (_radiotap(channel, -45)
           / Dot11(type=0, subtype=12, addr1=station, addr2=bssid, addr3=bssid)
           / Dot11Deauth(reason=reason))
    return _stamp(pkt, ts)


def association_request(station: str, bssid: str, ssid: str = "Campus-WiFi", ts: float = 0.0, channel: int = 6):
    pkt = (_radiotap(channel, -58)
           / Dot11(type=0, subtype=0, addr1=bssid, addr2=station, addr3=bssid)
           / Dot11AssoReq(cap=0x0411, listen_interval=10)
           / Dot11Elt(ID=0, info=ssid.encode()))
    return _stamp(pkt, ts)


def authentication(station: str, bssid: str, ts: float = 0.0, channel: int = 6):
    pkt = (_radiotap(channel, -58)
           / Dot11(type=0, subtype=11, addr1=bssid, addr2=station, addr3=bssid)
           / Dot11Auth(algo=0, seqnum=1, status=0))
    return _stamp(pkt, ts)


def data_to_ap(station: str, bssid: str, ts: float = 0.0, channel: int = 6):
    """A data frame from a client to its access point (to-DS). Header only; the payload is irrelevant."""
    pkt = _radiotap(channel, -50) / Dot11(type=2, subtype=0, FCfield=1, addr1=bssid, addr2=station, addr3=BROADCAST)
    return _stamp(pkt, ts)


def data_from_ap(station: str, bssid: str, ts: float = 0.0, channel: int = 6):
    pkt = _radiotap(channel, -50) / Dot11(type=2, subtype=0, FCfield=2, addr1=station, addr2=bssid, addr3=BROADCAST)
    return _stamp(pkt, ts)


def arp_reply(ip: str, mac: str, ts: float = 0.0, target_ip: str = "192.168.1.1", target_mac: str = "00:11:22:33:44:55"):
    pkt = (Ether(src=mac, dst=target_mac)
           / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=target_mac, pdst=target_ip))
    return _stamp(pkt, ts)


def arp_request(ip: str, mac: str, ts: float = 0.0, target_ip: str = "192.168.1.1"):
    pkt = Ether(src=mac, dst=BROADCAST) / ARP(op=1, hwsrc=mac, psrc=ip, hwdst="00:00:00:00:00:00", pdst=target_ip)
    return _stamp(pkt, ts)


def write_pcap(path: str, packets: list) -> list[str]:
    """Write frames to pcap file(s) in time order.

    802.11 frames (RadioTap) and ARP frames (Ethernet) have different link types and a pcap holds one, exactly as a
    real run uses two interfaces. Mixed input is split: `x.pcap` for 802.11, `x-arp.pcap` for ARP.
    Returns the paths written.
    """
    wifi = sorted((p for p in packets if p.haslayer(RadioTap)), key=lambda p: float(p.time))
    wired = sorted((p for p in packets if not p.haslayer(RadioTap)), key=lambda p: float(p.time))
    written = []
    if wifi:
        wrpcap(path, wifi)
        written.append(path)
    if wired:
        target = path if not wifi else path[:-5] + "-arp.pcap" if path.endswith(".pcap") else path + "-arp"
        wrpcap(target, wired)
        written.append(target)
    return written


# --------------------------------------------------------------------------- scenarios
# These match the demo database (seed_demo.py). Times start at t0 and run for about a minute.

def _inventory():
    from .. import seed_demo
    aps = [a for a in seed_demo.ACCESS_POINTS if a[6] and a[7] == 0]          # authorised and online
    devices = [(d[1], d[2], d[4]) for d in seed_demo.NAMED_AUTHORISED if d[5] == 0]
    return aps, devices


def baseline(t0: float) -> list:
    """Ordinary activity on the authorised network: beacons, known clients, stable ARP. Expect NO alerts."""
    aps, devices = _inventory()
    ap_by_loc = {a[0]: a for a in aps}
    out = []
    for second in range(60):
        for loc, ssid, bssid, channel, security, *_ in aps:
            out.append(beacon(bssid, ssid, channel, security, t0 + second + 0.1))
    for mac, ip, loc in devices:
        _loc, ssid, bssid, channel, *_ = ap_by_loc[loc]
        for second in range(0, 60, 3):
            out.append(data_to_ap(mac, bssid, t0 + second + 0.5, channel))
            out.append(arp_reply(ip, mac, t0 + second + 0.6))
        out.append(association_request(mac, bssid, ssid, t0 + 1.2, channel))
    # Normal roaming/reconnects: a handful of deauthentication frames, far below the threshold.
    for i in range(8):
        out.append(deauth("28:6C:07:4A:11:F4", devices[2][0], reason=3, ts=t0 + 10 + i * 4))
    return out


def deauth_flood(t0: float, bssid: str = "28:6C:07:4A:11:F4", frames: int = 150, seconds: float = 8.0) -> list:
    return [deauth(bssid, BROADCAST, 7, t0 + i * seconds / frames) for i in range(frames)]


def arp_conflict(t0: float) -> list:
    """The registry laptop's IP is suddenly claimed by another MAC (seed: Registry-Laptop 192.168.1.15)."""
    return [arp_reply("192.168.1.15", "A4:83:E7:2D:90:16", t0),
            arp_reply("192.168.1.15", "B2:44:0F:8E:63:D9", t0 + 2)]


def rogue_ap(t0: float, bssid: str = "7C:10:C9:5E:3A:A1") -> list:
    return [beacon(bssid, "Campus-WiFi", 6, "WPA2", t0 + i * 0.1) for i in range(20)]


def unknown_device(t0: float, mac: str = "DE:AD:BE:EF:00:21") -> list:
    return [authentication(mac, "28:6C:07:4A:12:08", t0, 11),
            association_request(mac, "28:6C:07:4A:12:08", "Campus-WiFi", t0 + 0.05, 11),
            data_to_ap(mac, "28:6C:07:4A:12:08", t0 + 0.5, 11)]


SCENARIOS = {
    "baseline": baseline, "deauth": deauth_flood, "arp_conflict": arp_conflict,
    "rogue_ap": rogue_ap, "unknown_device": unknown_device,
}
