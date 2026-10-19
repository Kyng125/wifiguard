"""Seeded, varied traffic for the evaluation trials.

Every trial draws its parameters from the documented ranges in RANGES with its own random generator, so a run is
reproducible from its seed and the trials within a run are not copies of each other. All frames are fabricated header-only
frames built with Scapy; nothing here transmits anything.

Each attack's first malicious frame is at time 0.0 of its own packet list, which is how the harness knows the true start.
"""
import random
from dataclasses import dataclass, field

from ..engine import synthetic as syn

BEACON_HZ = 10                       # real access points beacon about every 102.4 ms (10 per second)
NEIGHBOUR = ("TECNO-MiFi-2F81", "9A:4B:21:C7:0D:36", 11, "WPA2")      # matches the demo data: a neighbouring network

# Documented in docs/evaluation.md and written into every export, so the report can state the test conditions.
RANGES = {
    "normal": {
        "beacons_per_second_per_access_point": BEACON_HZ,
        "client_data_frames_per_second": "0.5 to 3 per known client",
        "arp_reply_every_seconds": "5 to 15 per known client",
        "client_reconnects": "0 to 2 (authentication, association, with 1 to 3 roaming deauthentication frames)",
        "other_benign_deauthentication_frames": "0 to 12 in total, below the threshold",
        "neighbouring_network": "beacons and client data from a network that is not ours",
    },
    "deauth": {
        "frames": "120 to 300", "duration_seconds": "4 to 9",
        "target": "broadcast (50%) or one known client", "source": "a random authorised access point (spoofed)",
        "note": "intensities are above the configured threshold; see the sweep for behaviour at and below it",
    },
    "arp_conflict": {
        "spoofed_replies": "1 to 3 claiming a known client's IP address", "spacing_seconds": "0.5 to 3",
        "attacker_mac": "random locally administered address",
    },
    "rogue_ap": {
        "beacons_per_second": BEACON_HZ, "duration_seconds": "2 to 5", "channel": "1, 6 or 11",
        "variants": "75% unauthorised BSSID with a known network name (Open, WPA2 or WPA3); "
                    "25% authorised BSSID cloned with weaker security (WPA2 instead of WPA3)",
    },
    "unknown_device": {
        "address": "random vendor address (50%) or random locally administered address (50%)",
        "access_point": "a random authorised access point",
        "sequence": "authentication, association, data (50%) or data only (50%)",
    },
}


@dataclass
class Inventory:
    """What the demo database contains (see seed_demo.py): our online access points and known clients."""
    aps: list = field(default_factory=list)          # (location, ssid, bssid, channel, security, ...)
    devices: list = field(default_factory=list)      # (mac, ip, location)

    @classmethod
    def demo(cls) -> "Inventory":
        aps, devices = syn._inventory()
        return cls(aps, devices)

    def ap_for(self, location):
        return next(a for a in self.aps if a[0] == location)


@dataclass
class Attack:
    packets: list
    params: dict
    expects: str                    # the alert category the rule should raise


def _random_mac(rng: random.Random, locally_administered: bool) -> str:
    octets = [rng.randrange(256) for _ in range(6)]
    octets[0] = (octets[0] | 0x02) & 0xFE if locally_administered else octets[0] & 0xFC
    return ":".join(f"{o:02X}" for o in octets)


# ------------------------------------------------------------------------------------------ normal

def normal(rng: random.Random, seconds: float, inv: Inventory) -> tuple[list, dict]:
    """Ordinary activity on and around the authorised network. Returns (packets, summary of what was generated)."""
    pkts: list = []

    def beacons(bssid, ssid, channel, security, signal):
        t = rng.uniform(0, 1 / BEACON_HZ)
        while t < seconds:
            pkts.append(syn.beacon(bssid, ssid, channel, security, t, signal))
            t += (1 / BEACON_HZ) * rng.uniform(0.96, 1.04)

    for _loc, ssid, bssid, channel, security, signal, *_ in inv.aps:
        beacons(bssid, ssid, channel, security, signal or -55)
    beacons(NEIGHBOUR[1], NEIGHBOUR[0], NEIGHBOUR[2], NEIGHBOUR[3], -79)

    by_loc = {a[0]: a for a in inv.aps}
    reconnects = 0
    for mac, ip, loc in inv.devices:
        _l, ssid, bssid, channel, *_ = by_loc[loc]
        t = rng.expovariate(rng.uniform(0.5, 3))
        while t < seconds:
            pkts.append(syn.data_to_ap(mac, bssid, t, channel))
            t += rng.expovariate(rng.uniform(0.5, 3))
        t = rng.uniform(0, 10)
        while t < seconds:
            pkts.append(syn.arp_reply(ip, mac, t))
            t += rng.uniform(5, 15)
        for _ in range(rng.randint(0, 2)):                # a reconnect, preceded by a short roaming burst
            t = rng.uniform(1, max(seconds - 1, 2))
            for k in range(rng.randint(1, 3)):
                pkts.append(syn.deauth(bssid, mac, 3, t - 0.3 + k * 0.05, channel))
            pkts.append(syn.authentication(mac, bssid, t, channel))
            pkts.append(syn.association_request(mac, bssid, ssid, t + 0.05, channel))
            reconnects += 1

    other = rng.randint(0, 12)
    for _ in range(other):
        _l, _s, bssid, channel, *_ = rng.choice(inv.aps)
        pkts.append(syn.deauth(bssid, rng.choice(inv.devices)[0], rng.choice((1, 3, 8)), rng.uniform(0, seconds), channel))

    neighbour_client = _random_mac(rng, False)            # someone else's phone on the neighbour's network
    t = rng.expovariate(1.0)
    while t < seconds:
        pkts.append(syn.data_to_ap(neighbour_client, NEIGHBOUR[1], t, NEIGHBOUR[2]))
        t += rng.expovariate(1.0)

    pkts.sort(key=lambda p: float(p.time))
    return pkts, {"reconnects": reconnects, "other_deauth_frames": other}


# ------------------------------------------------------------------------------------------ attacks

def _deauth(rng, inv):
    _l, _s, bssid, channel, *_ = rng.choice(inv.aps)
    frames, seconds = rng.randint(120, 300), round(rng.uniform(4, 9), 2)
    target = syn.BROADCAST if rng.random() < 0.5 else rng.choice(inv.devices)[0]
    times = sorted([0.0] + [rng.uniform(0, seconds) for _ in range(frames - 1)])
    packets = [syn.deauth(bssid, target, 7, t, channel) for t in times]
    return Attack(packets, {"bssid": bssid, "frames": frames, "seconds": seconds,
                            "target": "broadcast" if target == syn.BROADCAST else "client"}, "deauth_flood")


def _arp(rng, inv):
    _mac, ip, _loc = rng.choice(inv.devices)
    attacker = _random_mac(rng, True)
    replies = rng.randint(1, 3)
    t, packets = 0.0, []
    for _ in range(replies):
        packets.append(syn.arp_reply(ip, attacker, t))
        t += rng.uniform(0.5, 3)
    return Attack(packets, {"ip": ip, "attacker": attacker, "replies": replies}, "arp_conflict")


def _rogue(rng, inv):
    seconds = round(rng.uniform(2, 5), 2)
    if rng.random() < 0.25:                                # evil twin: an authorised BSSID with weaker security
        wpa3 = [a for a in inv.aps if a[4] == "WPA3"]
        _l, ssid, bssid, channel, *_ = rng.choice(wpa3)
        security, variant = "WPA2", "downgrade"
    else:
        ssid = "Campus-WiFi" if rng.random() < 0.75 else rng.choice(("Campus-WiFi-Staff", "Campus-WiFi-Guest"))
        bssid, channel = _random_mac(rng, False), rng.choice((1, 6, 11))
        security, variant = rng.choice(("Open", "WPA2", "WPA3")), "unauthorised"
    count = max(1, int(seconds * BEACON_HZ))
    packets = [syn.beacon(bssid, ssid, channel, security, i / BEACON_HZ, -60) for i in range(count)]
    return Attack(packets, {"variant": variant, "bssid": bssid, "ssid": ssid, "channel": channel,
                            "security": security, "seconds": seconds}, "rogue_ap")


def _unknown(rng, inv):
    _l, ssid, bssid, channel, *_ = rng.choice(inv.aps)
    randomised = rng.random() < 0.5
    mac = _random_mac(rng, randomised)
    if rng.random() < 0.5:
        packets = [syn.authentication(mac, bssid, 0.0, channel), syn.association_request(mac, bssid, ssid, 0.05, channel),
                   syn.data_to_ap(mac, bssid, 0.5, channel)]
        sequence = "auth+assoc+data"
    else:
        packets = [syn.data_to_ap(mac, bssid, 0.1 * i, channel) for i in range(4)]
        sequence = "data"
    return Attack(packets, {"mac": mac, "bssid": bssid, "randomised": randomised, "sequence": sequence},
                  "unauthorised_device")


BUILDERS = {"deauth": _deauth, "arp_conflict": _arp, "rogue_ap": _rogue, "unknown_device": _unknown}


def attack(scenario: str, rng: random.Random, inv: Inventory) -> Attack:
    return BUILDERS[scenario](rng, inv)


def deauth_burst(frames: int, seconds: float, inv: Inventory, bssid: str | None = None) -> list:
    """A deauthentication burst of an exact size, for the threshold sweep."""
    _l, _s, default_bssid, channel, *_ = inv.aps[1]
    bssid = bssid or default_bssid
    return [syn.deauth(bssid, syn.BROADCAST, 7, i * seconds / max(frames - 1, 1), channel) for i in range(frames)]
