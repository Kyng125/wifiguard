"""Packet processor: raw frames -> normalised Frame. No database; frames are synthetic and round-tripped through pcap files."""
import pytest
from scapy.utils import PcapReader

from wifiguard.engine import parse
from wifiguard.engine import synthetic as syn
from wifiguard.engine.frames import is_group_mac, is_locally_administered
from wifiguard.engine.processor import Processor, freq_to_channel

AP = "28:6C:07:4A:11:F4"
STA = "3C:52:82:1A:7B:09"


def via_pcap(tmp_path, *packets):
    """Write to a real pcap and read back, so parsing is tested on dissected bytes, not in-memory objects."""
    path = str(tmp_path / "t.pcap")
    syn.write_pcap(path, list(packets))
    reader = PcapReader(path)
    try:
        return [parse(p) for p in reader]
    finally:
        reader.close()


@pytest.mark.parametrize("mode", ["Open", "WEP", "WPA", "WPA2", "WPA3", "WPA2/WPA3"])
def test_security_mode_is_recognised(tmp_path, mode):
    (frame,) = via_pcap(tmp_path, syn.beacon(AP, "Campus-WiFi", 11, mode, ts=10.0))
    assert frame.kind == "beacon" and frame.security_mode == mode
    assert (frame.ssid, frame.channel, frame.bssid, frame.signal) == ("Campus-WiFi", 11, AP, -55)
    assert frame.ts == pytest.approx(10.0)


def test_probe_response_is_parsed_like_a_beacon(tmp_path):
    (frame,) = via_pcap(tmp_path, syn.probe_response(AP, "Campus-WiFi", STA, 1, "WPA3", ts=5.0))
    assert (frame.kind, frame.ssid, frame.security_mode, frame.channel) == ("probe_response", "Campus-WiFi", "WPA3", 1)


def test_hidden_ssid_is_none(tmp_path):
    (frame,) = via_pcap(tmp_path, syn.beacon(AP, "", 6, "WPA2", ts=1.0))
    assert frame.ssid is None


def test_channel_falls_back_to_radiotap_frequency_then_hint():
    pkt = syn.beacon(AP, "x", 6, "WPA2")
    pkt = pkt.__class__(bytes(pkt))                      # keep DS element
    assert parse(pkt).channel == 6
    no_ds = syn.data_to_ap(STA, AP, channel=11)          # data frames have no elements: radiotap decides
    assert parse(no_ds).channel == 11
    bare = syn.data_to_ap(STA, AP, channel=None)
    assert parse(bare, channel_hint=3).channel == 3


def test_frequency_to_channel():
    assert [freq_to_channel(f) for f in (2412, 2437, 2472, 2484, 5180, 5955)] == [1, 6, 13, 14, 36, 1]
    assert freq_to_channel(None) is None and freq_to_channel(1234) is None


def test_deauthentication_fields(tmp_path):
    (frame,) = via_pcap(tmp_path, syn.deauth(AP, STA, reason=4, ts=2.0))
    assert (frame.kind, frame.bssid, frame.receiver, frame.reason_code) == ("deauthentication", AP, STA, 4)
    assert frame.station is None


def test_station_comes_from_association_authentication_and_data(tmp_path):
    frames = via_pcap(
        tmp_path,
        syn.association_request(STA, AP, ts=1.0),
        syn.authentication(STA, AP, ts=2.0),
        syn.data_to_ap(STA, AP, ts=3.0),
        syn.data_from_ap(STA, AP, ts=4.0),
    )
    assert [f.kind for f in frames] == ["association_request", "authentication", "data", "data"]
    assert all(f.station == STA and f.bssid == AP for f in frames)


def test_broadcast_and_ap_addresses_are_never_stations():
    assert parse(syn.data_from_ap(syn.BROADCAST, AP)).station is None
    assert parse(syn.data_to_ap(AP, AP)).station is None
    response = syn.authentication(AP, AP)                 # an authentication frame sent BY the access point
    assert parse(response).station is None


def test_ad_hoc_and_wds_frames_have_no_station():
    from scapy.layers.dot11 import Dot11, RadioTap
    for flags in (0, 3):
        pkt = RadioTap() / Dot11(type=2, subtype=0, FCfield=flags, addr1=AP, addr2=STA, addr3=AP)
        pkt.time = 1.0
        assert parse(pkt).station is None


def test_probe_requests_do_not_count_as_presence():
    from scapy.layers.dot11 import Dot11, Dot11Elt, Dot11ProbeReq, RadioTap
    pkt = (RadioTap() / Dot11(type=0, subtype=4, addr1=syn.BROADCAST, addr2=STA, addr3=syn.BROADCAST)
           / Dot11ProbeReq() / Dot11Elt(ID=0, info=b"Campus-WiFi"))
    pkt.time = 1.0
    frame = parse(pkt)
    assert frame.kind == "probe_request" and frame.station is None


def test_arp_reply_and_request(tmp_path):
    reply, request = via_pcap(tmp_path, syn.arp_reply("192.168.1.15", STA, ts=1.0), syn.arp_request("192.168.1.9", AP, ts=2.0))
    assert (reply.kind, reply.arp_op, reply.arp_sender_ip, reply.arp_sender_mac) == ("arp_reply", 2, "192.168.1.15", STA)
    assert (request.kind, request.arp_op, request.arp_sender_ip) == ("arp_request", 1, "192.168.1.9")


def test_control_frames_and_other_protocols_are_ignored():
    from scapy.layers.dot11 import Dot11, RadioTap
    from scapy.layers.inet import IP, UDP
    from scapy.layers.l2 import Ether
    ack = RadioTap() / Dot11(type=1, subtype=13, addr1=STA)
    ack.time = 1.0
    assert parse(ack) is None
    assert parse(Ether() / IP() / UDP()) is None


def test_processor_discards_and_counts_malformed_input():
    processor = Processor()
    assert processor.process(object()) is None           # not a packet at all: dropped, never raises
    assert processor.process(syn.beacon(AP, "x", 6, "WPA2")) is not None
    assert (processor.parsed, processor.dropped) == (1, 1)


def test_truncated_rsn_element_does_not_crash():
    from scapy.layers.dot11 import Dot11Elt
    pkt = syn.beacon(AP, "x", 6, "Open") / Dot11Elt(ID=48, info=b"\x01\x00\x00")
    frame = parse(pkt)
    assert frame.security_mode == "WPA2"                 # an RSN element exists; its suites are unreadable


def test_mac_helpers():
    assert is_group_mac("FF:FF:FF:FF:FF:FF") and is_group_mac("01:00:5E:00:00:01") and not is_group_mac(STA)
    assert is_locally_administered("9A:2E:77:1B:C4:05") and not is_locally_administered(STA)
