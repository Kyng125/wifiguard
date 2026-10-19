"""Demo dataset. Mirrors the shared sample dataset used for the frontend prototype, with times
relative to 'now' so the dashboard always looks live. Not for production use."""
from datetime import timedelta

from . import db, timeutil
from .services import events

DATA_TABLES = [
    "event_log", "security_events", "device_notes", "frame_samples", "monitor_snapshots", "test_runs",
    "arp_bindings", "observed_devices", "observed_access_points", "authorised_devices", "authorised_access_points",
]

# location, ssid, bssid, channel, security, signal, authorised, last seen (minutes ago)
ACCESS_POINTS = [
    ("Library", "Campus-WiFi", "28:6C:07:4A:11:E0", 1, "WPA3", -48, True, 0),
    ("Admin Block", "Campus-WiFi", "28:6C:07:4A:11:F4", 6, "WPA3", -52, True, 0),
    ("Lab 1", "Campus-WiFi", "28:6C:07:4A:12:08", 11, "WPA3", -61, True, 0),
    ("Lab 2", "Campus-WiFi", "28:6C:07:4A:12:1C", 1, "WPA3", -66, True, 0),
    ("Staff Room", "Campus-WiFi-Staff", "28:6C:07:4A:12:30", 6, "WPA2", -58, True, 0),
    ("Hostel", "Campus-WiFi-Guest", "28:6C:07:4A:12:44", 11, "WPA2", None, True, 180),
    (None, "Campus-WiFi", "7C:10:C9:5E:3A:92", 6, "WPA2", -63, False, 0),
    (None, "TECNO-MiFi-2F81", "9A:4B:21:C7:0D:36", 11, "WPA2", -79, False, 0),
]
ONLINE_AP = {"Library": "28:6C:07:4A:11:E0", "Admin Block": "28:6C:07:4A:11:F4", "Lab 1": "28:6C:07:4A:12:08",
             "Lab 2": "28:6C:07:4A:12:1C", "Staff Room": "28:6C:07:4A:12:30"}

# owner label, mac, ip, device type, ap location, minutes since last seen, first seen (minutes ago)
NAMED_AUTHORISED = [
    ("Lab1-PC-07", "3C:52:82:1A:7B:09", "192.168.1.21", "desktop", "Lab 1", 0, 60 * 24 * 40),
    ("Library-Kiosk-02", "3C:52:82:1A:7B:5E", "192.168.1.34", "desktop", "Library", 0, 60 * 24 * 40),
    ("Registry-Laptop", "A4:83:E7:2D:90:16", "192.168.1.15", "laptop", "Admin Block", 0, 60 * 24 * 40),
    ("Staff-Phone-01", "8C:79:F5:30:E1:4B", "192.168.1.58", "phone", "Staff Room", 0, 60 * 24 * 25),
    ("Head-Printer-1", "00:1B:A9:77:20:C3", "192.168.1.9", "printer", "Admin Block", 0, 60 * 24 * 90),
    ("Lab2-PC-03", "3C:52:82:1A:80:11", "192.168.1.27", "desktop", "Lab 2", 45, 60 * 24 * 40),
]
# (mac, ap location, minutes since last seen, first seen minutes ago, label for log)
UNRECOGNISED = [
    ("9A:2E:77:1B:C4:05", "Lab 1", 1, 14),
    ("E6:18:A9:03:5D:42", "Library", 2, 35),
    ("9A:2E:77:1B:C4:06", "Lab 1", 1, 60 * 24 * 3),
    ("E6:18:A9:03:5D:43", "Library", 3, 60 * 24 * 3),
]
UNDER_REVIEW = [
    ("52:0D:E4:68:A1:7F", "Library", 1, 300),
    ("52:0D:E4:68:A1:80", "Library", 2, 60 * 24 * 3),
]
SCENARIO_PLAN = {  # scenario: (trials, detected, base seconds, cpu, memory)
    "normal_baseline": (10, 1, None, 21, 38),
    "deauth": (10, 10, 2.4, 44, 49),
    "arp_conflict": (10, 9, 3.1, 36, 47),
    "rogue_ap": (10, 10, 4.8, 33, 46),
    "unknown_device": (10, 10, 1.9, 31, 45),
}
DELTAS = [-0.4, -0.2, 0, 0.2, 0.4, -0.4, -0.2, 0.2, 0.4, 0]  # sums to 0, so the mean equals the base


def _wipe(conn):
    for table in DATA_TABLES:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence WHERE name IN (%s)" % ",".join("?" * len(DATA_TABLES)), DATA_TABLES)


def _t(**delta) -> str:
    return timeutil.iso(timeutil.now() - timedelta(**delta))


def seed(reset: bool = False) -> dict:
    conn = db.get_db()
    if conn.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] or \
            conn.execute("SELECT COUNT(*) FROM observed_devices").fetchone()[0]:
        if not reset:
            raise RuntimeError("The database already contains data. Use --reset to replace it with the demo data.")
    if reset:
        _wipe(conn)
    stamp = timeutil.iso()

    # Access points
    for loc, ssid, bssid, ch, sec, signal, authorised, mins in ACCESS_POINTS:
        first = _t(days=60) if authorised else (_t(minutes=8) if bssid.startswith("7C") else _t(days=2))
        conn.execute(
            "INSERT INTO observed_access_points (ssid, bssid, channel, signal_strength, security_mode, first_seen, last_seen) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)", (ssid, bssid, ch, signal, sec, first, _t(minutes=mins, seconds=3 if mins == 0 else 0)))
        if authorised:
            conn.execute(
                "INSERT INTO authorised_access_points (ssid, bssid, channel, security_mode, description, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?)", (ssid, bssid, ch, sec, loc, stamp))

    # Devices
    aps = list(ONLINE_AP.values())

    def add_device(mac, bssid, last_min, first_min, review="none", authorised=None, ip=None):
        conn.execute(
            "INSERT INTO observed_devices (mac_address, associated_bssid, review_state, first_seen, last_seen) VALUES (?, ?, ?, ?, ?)",
            (mac, bssid, review, _t(minutes=first_min), _t(minutes=last_min, seconds=2 if last_min == 0 else 0)))
        if authorised:
            conn.execute("INSERT INTO authorised_devices (mac_address, owner_label, device_type, created_at) VALUES (?, ?, ?, ?)",
                         (mac, authorised[0], authorised[1], stamp))
        if ip:
            conn.execute("INSERT INTO arp_bindings (ip_address, mac_address, first_seen, last_seen, trusted) VALUES (?, ?, ?, ?, 1)",
                         (ip, mac, _t(minutes=first_min), _t(minutes=last_min)))

    ap_by_loc = {loc: bssid for loc, _s, bssid, *_ in ACCESS_POINTS if loc}
    for label, mac, ip, dtype, loc, last, first in NAMED_AUTHORISED:
        add_device(mac, ap_by_loc[loc], last, first, authorised=(label, dtype), ip=ip)
    for i in range(30):  # filler brings authorised devices to 36
        lab = i < 20
        mac = f"{'3C:52:82' if lab else 'A4:83:E7'}:2B:00:{i + 1:02X}"
        label = f"Lab-PC-{i + 1:02d}" if lab else f"Staff-Laptop-{i - 19:02d}"
        last = (25 + i * 3) if i in (4, 11, 23) else 0   # three more offline devices
        add_device(mac, aps[i % 5], last, 60 * 24 * 30, authorised=(label, "desktop" if lab else "laptop"), ip=f"192.168.1.{100 + i}")
    for mac, loc, last, first in UNRECOGNISED:
        add_device(mac, ap_by_loc[loc], last, first)
    for mac, loc, last, first in UNDER_REVIEW:
        add_device(mac, ap_by_loc[loc], last, first, review="under_review")
    conn.execute("INSERT INTO device_notes (mac_address, text, author, created_at) VALUES (?, ?, ?, ?)",
                 ("52:0D:E4:68:A1:7F", "Guest tablet seen in the library. Owner to confirm.", "admin", _t(hours=4)))
    # The ARP conflict: 192.168.1.15 now also claimed by another MAC.
    conn.execute("INSERT INTO arp_bindings (ip_address, mac_address, first_seen, last_seen, trusted) VALUES (?, ?, ?, ?, 0)",
                 ("192.168.1.15", "B2:44:0F:8E:63:D1", _t(minutes=22), _t(minutes=22)))

    # Alerts: five open, three closed. Times are relative to now.
    deauth_first = timeutil.now() - timedelta(minutes=2)

    def at(base, seconds):
        return timeutil.iso(base + timedelta(seconds=seconds))

    events.create_event(
        event_id=1054, category="deauth_flood", severity="high", status="investigating", occurrences=3,
        source="28:6C:07:4A:11:F4", target="FF:FF:FF:FF:FF:FF", bssid="28:6C:07:4A:11:F4", ssid="Campus-WiFi", channel=6,
        description="184 deauthentication frames detected within a 10-second window (threshold: 100 frames)",
        evidence={"frameCount": 184, "windowSeconds": 10, "threshold": 100, "reasonCode": 7},
        event_time=timeutil.iso(deauth_first), last_seen=at(deauth_first, 38), dedupe_key="deauth_flood:28:6C:07:4A:11:F4",
        timeline=[("detected", "Event started", at(deauth_first, 0)), ("threshold", "Threshold exceeded (184 frames in 10 s)", at(deauth_first, 10)),
                  ("generated", "Alert generated", at(deauth_first, 10)), ("merged", "Repeated within the 60-second cool-down; merged into this alert.", at(deauth_first, 24)),
                  ("merged", "Repeated within the 60-second cool-down; merged into this alert.", at(deauth_first, 38)),
                  ("status", "Status changed from new to investigating", _t(minutes=1))], commit=False)
    rogue_t = timeutil.now() - timedelta(minutes=8)
    events.create_event(
        event_id=1053, category="rogue_ap", severity="critical", source="7C:10:C9:5E:3A:92", bssid="7C:10:C9:5E:3A:92",
        ssid="Campus-WiFi", channel=6,
        description="Access point 7C:10:C9:5E:3A:92 is advertising Campus-WiFi on channel 6 with WPA2; authorised access points use WPA3",
        evidence={"ssid": "Campus-WiFi", "channel": 6, "securityMode": "WPA2", "authorisedSecurityModes": ["WPA3"]},
        event_time=timeutil.iso(rogue_t), dedupe_key="rogue_ap:7C:10:C9:5E:3A:92", commit=False)
    events.create_event(
        event_id=1052, category="unauthorised_device", severity="medium", source="9A:2E:77:1B:C4:05", bssid="28:6C:07:4A:12:08",
        ssid="Campus-WiFi", channel=11,
        description="Device 9A:2E:77:1B:C4:05 associated with 28:6C:07:4A:12:08 and is not on the authorised list",
        evidence={"associatedBssid": "28:6C:07:4A:12:08", "randomisedAddress": True}, event_time=_t(minutes=14),
        dedupe_key="unauthorised_device:9A:2E:77:1B:C4:05", commit=False)
    events.create_event(
        event_id=1051, category="arp_conflict", severity="high", source="192.168.1.15", target="B2:44:0F:8E:63:D1",
        description="192.168.1.15 moved from A4:83:E7:2D:90:16 to B2:44:0F:8E:63:D1",
        evidence={"ip": "192.168.1.15", "previousMac": "A4:83:E7:2D:90:16", "newMac": "B2:44:0F:8E:63:D1"},
        event_time=_t(minutes=22), dedupe_key="arp_conflict:192.168.1.15", commit=False)
    events.create_event(
        event_id=1050, category="unauthorised_device", severity="medium", status="investigating", source="E6:18:A9:03:5D:42",
        bssid="28:6C:07:4A:11:E0", ssid="Campus-WiFi", channel=1,
        description="Device E6:18:A9:03:5D:42 associated with 28:6C:07:4A:11:E0 and is not on the authorised list",
        evidence={"associatedBssid": "28:6C:07:4A:11:E0", "randomisedAddress": True}, event_time=_t(minutes=35),
        dedupe_key="unauthorised_device:E6:18:A9:03:5D:42",
        timeline=[("detected", "Event started", _t(minutes=35)), ("generated", "Alert generated", _t(minutes=35)),
                  ("status", "Status changed from new to investigating", _t(minutes=30))], commit=False)
    events.create_event(
        event_id=1049, category="arp_conflict", severity="high", status="resolved", source="192.168.1.40",
        target="C6:1D:5A:77:02:8E", description="192.168.1.40 moved from 3C:52:82:1A:7B:77 to C6:1D:5A:77:02:8E",
        evidence={"ip": "192.168.1.40", "previousMac": "3C:52:82:1A:7B:77", "newMac": "C6:1D:5A:77:02:8E"},
        event_time=_t(days=1, hours=1), dedupe_key="arp_conflict:192.168.1.40",
        timeline=[("detected", "Event started", _t(days=1, hours=1)), ("generated", "Alert generated", _t(days=1, hours=1)),
                  ("note", "Device was replaced after a fault; new MAC is expected.", _t(days=1)),
                  ("status", "Status changed from new to resolved", _t(days=1))], commit=False)
    events.create_event(
        event_id=1048, category="deauth_flood", severity="high", status="false_positive", source="28:6C:07:4A:12:1C",
        bssid="28:6C:07:4A:12:1C", ssid="Campus-WiFi", channel=1,
        description="112 deauthentication frames detected within a 10-second window (threshold: 100 frames)",
        evidence={"frameCount": 112, "windowSeconds": 10, "threshold": 100, "reasonCode": 4}, event_time=_t(days=2),
        dedupe_key="deauth_flood:28:6C:07:4A:12:1C",
        timeline=[("detected", "Event started", _t(days=2)), ("generated", "Alert generated", _t(days=2)),
                  ("note", "Burst matches a scheduled access point restart.", _t(days=2, minutes=-5)),
                  ("status", "Status changed from new to false_positive", _t(days=2, minutes=-5))], commit=False)
    events.create_event(
        event_id=1047, category="unauthorised_device", severity="medium", status="resolved", source="C2:7E:11:90:AB:34",
        bssid="28:6C:07:4A:12:30", ssid="Campus-WiFi-Staff", channel=6,
        description="Device C2:7E:11:90:AB:34 associated with 28:6C:07:4A:12:30 and is not on the authorised list",
        evidence={"associatedBssid": "28:6C:07:4A:12:30", "randomisedAddress": True}, event_time=_t(days=3),
        dedupe_key="unauthorised_device:C2:7E:11:90:AB:34", commit=False)
    # resolved_at for the closed ones
    conn.execute("UPDATE security_events SET resolved_at = last_seen WHERE status IN ('resolved','false_positive')")

    # Evaluation sample (clearly flagged as sample data)
    runs = 0
    for n, (scenario, (trials, detected, base, cpu, mem)) in enumerate(SCENARIO_PLAN.items()):
        for trial in range(1, trials + 1):
            start = timeutil.now() - timedelta(days=5 - n, minutes=trial * 3)
            if scenario == "normal_baseline":
                hit = trial == 4  # one false alert in the baseline
            elif scenario == "arp_conflict":
                hit = trial != trials  # the last trial is missed
            else:
                hit = True
            alert_time = None
            if hit and base is not None:
                alert_time = timeutil.iso(start + timedelta(seconds=base + DELTAS[trial - 1]))
            conn.execute(
                "INSERT INTO test_runs (scenario, trial, event_start, alert_time, detected, cpu_percent, memory_percent, notes, is_sample, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?)",
                (scenario, trial, timeutil.iso(start), alert_time, int(hit), cpu + DELTAS[trial - 1], mem + DELTAS[trial - 1],
                 "Sample data" if trial == 1 else None, stamp))
            runs += 1

    # Runtime state and a short frame feed (stand-ins for the capture side)
    history = [980, 1120, 1050, 1310, 1180, 1420, 1290, 1350, 1210, 1280, 1190, 1260]   # then 1,284 now
    for i, pps in enumerate(history):
        conn.execute(
            "INSERT INTO monitor_snapshots (at, packets_total, packets_per_sec, mgmt_count, data_count, arp_count, engine_state, "
            "monitor_state, arp_state, current_channel, cpu_percent, memory_percent) VALUES (?, ?, ?, 0, 0, 0, 'running', 'up', 'up', 6, 33, 48)",
            (_t(seconds=(len(history) - i) * 10), 120000 + i * 700, pps))
    conn.execute(
        "INSERT INTO monitor_snapshots (at, packets_total, packets_per_sec, mgmt_count, data_count, arp_count, engine_state, "
        "monitor_state, arp_state, current_channel, cpu_percent, memory_percent) VALUES (?, 128492, 1284, 61240, 58310, 8942, "
        "'running', 'up', 'up', 6, 34, 48)", (stamp,))
    feed = [
        ("management", "beacon", "28:6C:07:4A:11:F4", "FF:FF:FF:FF:FF:FF", "28:6C:07:4A:11:F4", 6, None),
        ("management", "deauthentication", "28:6C:07:4A:11:F4", "FF:FF:FF:FF:FF:FF", "28:6C:07:4A:11:F4", 6, 1054),
        ("management", "probe-response", "28:6C:07:4A:12:30", "8C:79:F5:30:E1:4B", "28:6C:07:4A:12:30", 6, None),
        ("arp", "reply", "A4:83:E7:2D:90:16", "FF:FF:FF:FF:FF:FF", None, None, None),
        ("data", "data", "3C:52:82:1A:7B:09", "28:6C:07:4A:12:08", "28:6C:07:4A:12:08", 11, None),
        ("management", "association-request", "9A:2E:77:1B:C4:05", "28:6C:07:4A:12:08", "28:6C:07:4A:12:08", 11, 1052),
        ("arp", "reply", "B2:44:0F:8E:63:D1", "FF:FF:FF:FF:FF:FF", None, None, 1051),
        ("management", "beacon", "7C:10:C9:5E:3A:92", "FF:FF:FF:FF:FF:FF", "7C:10:C9:5E:3A:92", 6, 1053),
    ]
    for i in range(24):
        f = feed[i % len(feed)]
        conn.execute(
            "INSERT INTO frame_samples (at, frame_type, subtype, source, destination, bssid, channel, flag_event_id) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?)", (_t(seconds=(24 - i) * 2), *f))
    conn.commit()
    return {
        "accessPoints": len(ACCESS_POINTS), "devices": 42, "alerts": 8, "testRuns": runs,
    }
