"""What the rules compare traffic against: the authorised inventory and what has been seen so far.

Held in memory so the rules never query the database per packet (report Section 3.6.3). The pipeline
refreshes the authorised lists periodically, so changes made on the dashboard take effect without a restart.
"""
from dataclasses import dataclass, field


@dataclass(slots=True)
class AuthorisedAP:
    ssid: str
    channel: int | None = None
    security_mode: str | None = None


@dataclass
class Reference:
    institutional_ssid: str = ""
    authorised_aps: dict[str, AuthorisedAP] = field(default_factory=dict)      # BSSID -> record
    authorised_devices: set[str] = field(default_factory=set)                  # MAC addresses
    observed_devices: set[str] = field(default_factory=set)                    # clients already seen on our APs
    observed_aps: set[str] = field(default_factory=set)                        # every BSSID ever heard
    arp_table: dict[str, str] = field(default_factory=dict)                    # IP -> MAC

    @property
    def known_ssids(self) -> set[str]:
        """SSIDs that only an authorised access point may advertise."""
        names = {ap.ssid for ap in self.authorised_aps.values() if ap.ssid}
        if self.institutional_ssid:
            names.add(self.institutional_ssid)
        return names

    def authorised_modes(self, ssid: str | None) -> list[str]:
        return sorted({ap.security_mode for ap in self.authorised_aps.values()
                       if ap.ssid == ssid and ap.security_mode})

    def is_access_point(self, mac: str | None) -> bool:
        return mac in self.authorised_aps or mac in self.observed_aps

    # ------------------------------------------------------------ database

    def reload_inventory(self) -> None:
        """Re-read the administrator-maintained lists. Needs a Flask app context."""
        from .. import db
        from ..services import settings as st
        self.institutional_ssid = st.get("institutional_ssid")
        self.authorised_aps = {
            r["bssid"]: AuthorisedAP(r["ssid"], r["channel"], r["security_mode"])
            for r in db.rows("SELECT ssid, bssid, channel, security_mode FROM authorised_access_points")
        }
        self.authorised_devices = {r["mac_address"] for r in db.rows("SELECT mac_address FROM authorised_devices")}

    @classmethod
    def load(cls) -> "Reference":
        """Load the full starting state from the database. Needs a Flask app context."""
        from .. import db
        ref = cls()
        ref.reload_inventory()
        ref.observed_devices = {r["mac_address"] for r in db.rows("SELECT mac_address FROM observed_devices")}
        ref.observed_aps = {r["bssid"] for r in db.rows("SELECT bssid FROM observed_access_points")}
        # The current binding for an IP is the one seen most recently.
        for r in db.rows("SELECT ip_address, mac_address FROM arp_bindings ORDER BY last_seen ASC, id ASC"):
            ref.arp_table[r["ip_address"]] = r["mac_address"]
        return ref
