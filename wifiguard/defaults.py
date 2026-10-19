"""Default values for system_settings. Stored as text; typed on read."""

DEFAULT_SETTINGS = {
    # General
    "system_name": "WiFiGuard",
    "timezone": "Africa/Lagos",
    "refresh_interval_seconds": "5",
    # The institution's own Wi-Fi name. Any access point advertising it from an unauthorised BSSID is
    # treated as a suspected rogue (report Section 3.10.3 uses `institutional_ssid`).
    "institutional_ssid": "Campus-WiFi",
    # Monitoring (channel_mode: locked = first channel only; hopping = cycle through the list)
    "monitor_interface": "wlan0mon",
    "arp_interface": "eth0",
    "channels": "6",
    "channel_mode": "locked",
    "channel_dwell_ms": "300",
    # Detection rules
    "rule.deauth.enabled": "1",
    "rule.deauth.threshold": "100",
    "rule.deauth.window_seconds": "10",
    "rule.deauth.cooldown_seconds": "60",
    "rule.arp.enabled": "1",
    "rule.arp.cooldown_seconds": "60",
    "rule.rogue_ap.enabled": "1",
    "rule.rogue_ap.cooldown_seconds": "300",
    "rule.unauthorised_device.enabled": "1",
    "rule.unauthorised_device.cooldown_seconds": "300",
    # Severity per category (editable later; read-only in the UI for now)
    "severity.rogue_ap": "critical",
    "severity.deauth_flood": "high",
    "severity.arp_conflict": "high",
    "severity.unauthorised_device": "medium",
    # Derived-state windows
    "active_window_minutes": "5",
    "offline_after_minutes": "10",
    "ap_offline_after_minutes": "10",
    # Data and sessions
    "retention_days": "30",
    "session_timeout_minutes": "30",
}

# Maps the API rule id to (category, setting prefix, human name, description)
RULES = {
    "deauth": {
        "category": "deauth_flood",
        "name": "Possible deauthentication flood",
        "description": "Counts deauthentication frames per BSSID in a sliding window and alerts when the threshold is reached.",
        "editable": ["threshold", "windowSeconds", "cooldownSeconds"],
    },
    "arp": {
        "category": "arp_conflict",
        "name": "ARP mapping conflict",
        "description": "Alerts when an ARP reply gives an IP address a different MAC address than before.",
        "editable": ["cooldownSeconds"],
    },
    "rogue_ap": {
        "category": "rogue_ap",
        "name": "Possible rogue access point",
        "description": "Alerts when your network name (or another known access point name) is advertised by an access point that is not on the authorised list, or when an authorised access point advertises weaker security than registered.",
        "editable": ["cooldownSeconds"],
    },
    "unauthorised_device": {
        "category": "unauthorised_device",
        "name": "Unrecognised device",
        "description": "Alerts the first time a device that is neither authorised nor already observed appears on one of your authorised access points. Silent until at least one access point is authorised.",
        "editable": ["cooldownSeconds"],
    },
}

CATEGORY_TO_RULE = {meta["category"]: rule_id for rule_id, meta in RULES.items()}
