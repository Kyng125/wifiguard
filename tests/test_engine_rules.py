"""The four detection rules, on synthetic frames. No database and no Flask: the rules are pure."""
import pytest

from wifiguard.engine import AuthorisedAP, DetectionEngine, EngineConfig, Reference, parse
from wifiguard.engine import synthetic as syn
from wifiguard.engine.frames import AccessPointSeen, ArpSeen, DeviceSeen
from wifiguard.services.events import REQUIRED_EVIDENCE

LIB, ADMIN, STAFF = "28:6C:07:4A:11:E0", "28:6C:07:4A:11:F4", "28:6C:07:4A:12:30"
LAPTOP, UNKNOWN = "A4:83:E7:2D:90:16", "9A:2E:77:1B:C4:05"
ROGUE = "7C:10:C9:5E:3A:92"
NEIGHBOUR = "9A:4B:21:C7:0D:36"


def reference() -> Reference:
    return Reference(
        institutional_ssid="Campus-WiFi",
        authorised_aps={LIB: AuthorisedAP("Campus-WiFi", 1, "WPA3"), ADMIN: AuthorisedAP("Campus-WiFi", 6, "WPA3"),
                        STAFF: AuthorisedAP("Campus-WiFi-Staff", 6, "WPA2")},
        authorised_devices={LAPTOP},
        arp_table={"192.168.1.15": LAPTOP},
    )


def engine(**config) -> DetectionEngine:
    return DetectionEngine(reference(), EngineConfig(**config))


def run(eng: DetectionEngine, packets) -> list:
    out = []
    for packet in packets:
        out.extend(eng.process(parse(packet)).detections)
    return out


# ------------------------------------------------------------------ deauthentication

def test_below_threshold_is_quiet_and_at_threshold_alerts():
    assert run(engine(), syn.deauth_flood(1000.0, ADMIN, frames=99, seconds=9.0)) == []
    (d,) = run(engine(), syn.deauth_flood(1000.0, ADMIN, frames=100, seconds=9.0))
    assert d.category == "deauth_flood" and d.source == ADMIN and d.target == syn.BROADCAST.upper()
    assert d.evidence["frameCount"] == 100 and d.evidence["threshold"] == 100 and d.evidence["windowSeconds"] == 10
    assert d.evidence["reasonCode"] == 7
    assert d.description == "100 deauthentication frames detected within a 10-second window (threshold: 100 frames)"


def test_slow_trickle_never_alerts():
    # 1 frame a second for 5 minutes: never more than 10 inside any 10-second window
    assert run(engine(), [syn.deauth(ADMIN, ts=2000.0 + i) for i in range(300)]) == []


def test_window_slides_old_frames_drop_out():
    packets = [syn.deauth(ADMIN, ts=3000.0 + i * 0.5) for i in range(60)]       # 2 frames/s: 21 fit in an inclusive 10 s window
    assert run(engine(deauth_threshold=22), packets) == []
    assert len(run(engine(deauth_threshold=21), packets)) == 1


def test_window_edge_is_inclusive():
    # frames exactly `window` seconds apart are still inside the window
    packets = [syn.deauth(ADMIN, ts=4000.0), syn.deauth(ADMIN, ts=4010.0)]
    assert len(run(engine(deauth_threshold=2), packets)) == 1
    packets = [syn.deauth(ADMIN, ts=4000.0), syn.deauth(ADMIN, ts=4010.001)]
    assert run(engine(deauth_threshold=2), packets) == []


def test_sustained_flood_alerts_once_per_cooldown():
    flood = [syn.deauth(ADMIN, ts=5000.0 + i * 0.1) for i in range(1300)]       # 130 seconds of flooding
    found = run(engine(), flood)
    assert [round(d.ts - 5000.0) for d in found] == [10, 70, 130]               # 10 s in, then every 60 s
    assert all(d.cooldown_seconds == 60 and d.dedupe_key == f"deauth_flood:{ADMIN}" for d in found)


def test_floods_on_different_access_points_are_independent():
    packets = syn.deauth_flood(6000.0, ADMIN) + syn.deauth_flood(6000.0, LIB)
    assert sorted(d.source for d in run(engine(), packets)) == sorted([ADMIN, LIB])


def test_disassociation_is_not_counted_by_default():
    from scapy.layers.dot11 import Dot11, Dot11Disas, RadioTap
    frames = []
    for i in range(150):
        pkt = RadioTap() / Dot11(type=0, subtype=10, addr1=syn.BROADCAST, addr2=ADMIN, addr3=ADMIN) / Dot11Disas(reason=8)
        pkt.time = 7000.0 + i * 0.05
        frames.append(pkt)
    assert run(engine(), frames) == []


def test_deauth_rule_can_be_disabled_and_reconfigured_live():
    assert run(engine(deauth_enabled=False), syn.deauth_flood(8000.0)) == []
    eng = engine()
    eng.configure(EngineConfig(deauth_threshold=10))
    assert len(run(eng, syn.deauth_flood(9000.0, frames=30, seconds=3))) == 1


# ------------------------------------------------------------------------------ ARP

def test_matching_binding_is_quiet_and_new_ips_are_learned():
    eng = engine()
    assert run(eng, [syn.arp_reply("192.168.1.15", LAPTOP, 1.0), syn.arp_reply("192.168.1.77", UNKNOWN, 2.0)]) == []
    assert eng.reference.arp_table["192.168.1.77"] == UNKNOWN


def test_conflicting_reply_alerts_with_both_macs():
    (d,) = run(engine(), [syn.arp_reply("192.168.1.15", "B2:44:0F:8E:63:D1", 10.0)])
    assert d.category == "arp_conflict" and d.source == "192.168.1.15" and d.target == "B2:44:0F:8E:63:D1"
    assert d.evidence == {"ip": "192.168.1.15", "previousMac": LAPTOP, "newMac": "B2:44:0F:8E:63:D1"}
    assert d.description == f"192.168.1.15 moved from {LAPTOP} to B2:44:0F:8E:63:D1"


def test_arp_requests_never_alert_or_overwrite():
    eng = engine()
    assert run(eng, [syn.arp_request("192.168.1.15", "B2:44:0F:8E:63:D1", 10.0)]) == []
    assert eng.reference.arp_table["192.168.1.15"] == LAPTOP


def test_arp_probes_and_group_addresses_are_ignored():
    packets = [syn.arp_reply("0.0.0.0", UNKNOWN, 1.0), syn.arp_reply("169.254.3.3", UNKNOWN, 2.0),
               syn.arp_reply("192.168.1.15", "FF:FF:FF:FF:FF:FF", 3.0), syn.arp_reply("192.168.1.15", "00:00:00:00:00:00", 4.0)]
    assert run(engine(), packets) == []


def test_arp_conflict_cooldown_and_flip_back():
    eng = engine(arp_cooldown_seconds=60)
    packets = [syn.arp_reply("192.168.1.15", UNKNOWN, 100.0), syn.arp_reply("192.168.1.15", LAPTOP, 110.0),
               syn.arp_reply("192.168.1.15", UNKNOWN, 120.0), syn.arp_reply("192.168.1.15", LAPTOP, 200.0)]
    assert [d.ts for d in run(eng, packets)] == [100.0, 200.0]      # the flips at 110 and 120 are inside the cool-down


# ------------------------------------------------------------------------- rogue AP

def test_authorised_access_points_are_quiet():
    packets = [syn.beacon(LIB, "Campus-WiFi", 1, "WPA3", 1.0), syn.beacon(STAFF, "Campus-WiFi-Staff", 6, "WPA2", 2.0)]
    assert run(engine(), packets) == []


def test_unauthorised_bssid_with_institutional_ssid_alerts():
    (d,) = run(engine(), [syn.beacon(ROGUE, "Campus-WiFi", 6, "WPA2", 10.0)])
    assert (d.category, d.source, d.target, d.channel, d.bssid) == ("rogue_ap", ROGUE, "Campus-WiFi", 6, ROGUE)
    assert d.evidence["ssid"] == "Campus-WiFi" and d.evidence["securityMode"] == "WPA2" and d.evidence["channel"] == 6
    assert d.evidence["authorisedSecurityModes"] == ["WPA3"] and d.evidence["reason"] == "unauthorised_bssid"
    assert d.description == (f"Access point {ROGUE} is advertising Campus-WiFi on channel 6 with WPA2; "
                             "authorised access points use WPA3")


def test_probe_response_also_counts():
    assert len(run(engine(), [syn.probe_response(ROGUE, "Campus-WiFi", UNKNOWN, 6, "WPA2", 1.0)])) == 1


def test_a_neighbouring_network_is_observed_not_alerted():
    eng = engine()
    packets = [syn.beacon(NEIGHBOUR, "TECNO-MiFi-2F81", 11, "WPA2", 1.0), syn.beacon("AA:AA:AA:00:00:01", "", 6, "WPA2", 2.0)]
    assert run(eng, packets) == []
    assert NEIGHBOUR in eng.reference.observed_aps


def test_other_authorised_ssid_is_protected_too():
    assert len(run(engine(), [syn.beacon(ROGUE, "Campus-WiFi-Staff", 6, "WPA2", 1.0)])) == 1


def test_cloned_bssid_with_weaker_security_alerts_but_stronger_or_equal_does_not():
    (d,) = run(engine(), [syn.beacon(LIB, "Campus-WiFi", 1, "Open", 1.0)])
    assert d.evidence["reason"] == "security_downgrade" and d.evidence["securityMode"] == "Open"
    assert d.evidence["authorisedSecurityModes"] == ["WPA3"] and d.source == LIB
    assert run(engine(), [syn.beacon(STAFF, "Campus-WiFi-Staff", 6, "WPA3", 1.0)]) == []    # upgrade
    assert run(engine(), [syn.beacon(STAFF, "Campus-WiFi-Staff", 6, "WPA2", 1.0)]) == []    # same


def test_a_channel_change_on_an_authorised_ap_is_not_an_alert():
    assert run(engine(), [syn.beacon(LIB, "Campus-WiFi", 11, "WPA3", 1.0)]) == []


def test_rogue_beacons_alert_once_per_cooldown():
    packets = [syn.beacon(ROGUE, "Campus-WiFi", 6, "WPA2", 1000.0 + i * 0.1) for i in range(5000)]   # ~500 s of beacons
    assert [round(d.ts - 1000.0) for d in run(engine(), packets)] == [0, 300]


# --------------------------------------------------------------------- unauthorised device

def test_authorised_device_is_quiet_unknown_device_alerts_once():
    eng = engine()
    assert run(eng, [syn.association_request(LAPTOP, ADMIN, ts=1.0)]) == []
    (d,) = run(eng, [syn.association_request(UNKNOWN, LIB, "Campus-WiFi", 2.0)])
    assert (d.category, d.source, d.target, d.bssid, d.ssid) == ("unauthorised_device", UNKNOWN, LIB, LIB, "Campus-WiFi")
    assert d.evidence == {"associatedBssid": LIB, "randomisedAddress": True}
    assert d.description == f"Device {UNKNOWN} associated with {LIB} and is not on the authorised list"
    assert run(eng, [syn.data_to_ap(UNKNOWN, LIB, 3.0), syn.association_request(UNKNOWN, LIB, ts=4.0)]) == []


def test_device_seen_first_in_a_data_frame_is_detected():
    assert len(run(engine(), [syn.data_to_ap(UNKNOWN, ADMIN, 1.0)])) == 1


def test_clients_of_neighbouring_networks_are_ignored():
    eng = engine()
    assert run(eng, [syn.data_to_ap(UNKNOWN, NEIGHBOUR, 1.0), syn.association_request(UNKNOWN, ROGUE, ts=2.0)]) == []
    assert UNKNOWN not in eng.reference.observed_devices          # not even recorded: they are not our clients


def test_access_points_and_group_addresses_are_never_devices():
    eng = engine()
    eng.reference.observed_aps.add(NEIGHBOUR)
    assert run(eng, [syn.data_from_ap(syn.BROADCAST, ADMIN, 1.0), syn.data_to_ap(NEIGHBOUR, ADMIN, 2.0)]) == []


def test_probe_requests_alone_are_not_an_association():
    from scapy.layers.dot11 import Dot11, Dot11ProbeReq, RadioTap
    pkt = RadioTap() / Dot11(type=0, subtype=4, addr1=ADMIN, addr2=UNKNOWN, addr3=ADMIN) / Dot11ProbeReq()
    pkt.time = 1.0
    assert run(engine(), [pkt]) == []


def test_device_randomised_flag_is_false_for_a_manufacturer_address():
    (d,) = run(engine(), [syn.association_request("3C:52:82:99:00:01", LIB, ts=1.0)])
    assert d.evidence["randomisedAddress"] is False


def test_device_rule_needs_registered_access_points():
    eng = DetectionEngine(Reference(institutional_ssid="Campus-WiFi"), EngineConfig())
    assert run(eng, [syn.association_request(UNKNOWN, LIB, ts=1.0)]) == []


# --------------------------------------------------------------------------- engine

def test_every_detection_carries_the_evidence_keys_the_event_manager_requires():
    eng = engine()
    packets = (syn.deauth_flood(10.0, ADMIN) + [syn.arp_reply("192.168.1.15", UNKNOWN, 20.0),
               syn.beacon(ROGUE, "Campus-WiFi", 6, "WPA2", 30.0), syn.association_request(UNKNOWN, LIB, ts=40.0)])
    found = run(eng, packets)
    assert {d.category for d in found} == set(REQUIRED_EVIDENCE)
    for d in found:
        assert set(REQUIRED_EVIDENCE[d.category]) <= set(d.evidence), d.category


def test_observations_describe_what_was_seen():
    eng = engine()
    result = eng.process(parse(syn.beacon(NEIGHBOUR, "TECNO-MiFi-2F81", 11, "WPA2", 1.0)))
    assert result.observations == [AccessPointSeen(NEIGHBOUR, "TECNO-MiFi-2F81", 11, -55, "WPA2", 1.0)]
    assert eng.process(parse(syn.data_to_ap(LAPTOP, ADMIN, 2.0))).observations == [DeviceSeen(LAPTOP, ADMIN, 2.0)]
    assert eng.process(parse(syn.arp_reply("192.168.1.99", UNKNOWN, 3.0))).observations == [ArpSeen("192.168.1.99", UNKNOWN, 3.0)]


def test_baseline_scenario_raises_no_alerts():
    eng = engine()
    eng.reference.authorised_aps = {  # the demo inventory
        "28:6C:07:4A:11:E0": AuthorisedAP("Campus-WiFi", 1, "WPA3"), "28:6C:07:4A:11:F4": AuthorisedAP("Campus-WiFi", 6, "WPA3"),
        "28:6C:07:4A:12:08": AuthorisedAP("Campus-WiFi", 11, "WPA3"), "28:6C:07:4A:12:1C": AuthorisedAP("Campus-WiFi", 1, "WPA3"),
        "28:6C:07:4A:12:30": AuthorisedAP("Campus-WiFi-Staff", 6, "WPA2")}
    from wifiguard import seed_demo
    eng.reference.authorised_devices = {d[1] for d in seed_demo.NAMED_AUTHORISED}
    eng.reference.arp_table = {d[2]: d[1] for d in seed_demo.NAMED_AUTHORISED}
    assert run(eng, syn.baseline(1000.0)) == []
    assert eng.stats.frames > 500 and eng.stats.detections == 0


@pytest.mark.parametrize("scenario,expected", [("deauth", "deauth_flood"), ("arp_conflict", "arp_conflict"),
                                               ("rogue_ap", "rogue_ap"), ("unknown_device", "unauthorised_device")])
def test_each_attack_scenario_raises_exactly_its_alert(scenario, expected):
    eng = engine()
    eng.reference.authorised_aps["28:6C:07:4A:12:08"] = AuthorisedAP("Campus-WiFi", 11, "WPA3")
    found = run(eng, syn.SCENARIOS[scenario](1000.0))
    assert [d.category for d in found] == [expected]
