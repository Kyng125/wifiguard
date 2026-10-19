"""Vendor lookup from a MAC address. Derived at read time, never stored.

Randomised (locally administered) addresses are reported as private. Real lookups use
Scapy's bundled OUI database when Scapy is installed; otherwise the vendor is unknown (None).
DEMO_VENDORS only labels the made-up addresses used by the demo seed data.
"""
from functools import lru_cache

from ..validators import is_randomised

DEMO_VENDORS = {
    "3C:52:82": "Intel",
    "A4:83:E7": "Apple",
    "8C:79:F5": "Samsung",
    "00:1B:A9": "Brother",
}


@lru_cache(maxsize=4096)
def vendor(mac: str) -> str | None:
    if is_randomised(mac):
        return "Private (randomised)"
    if mac[:8] in DEMO_VENDORS:
        return DEMO_VENDORS[mac[:8]]
    try:
        from scapy.config import conf  # optional dependency

        name = conf.manufdb._get_manuf(mac)
        if name and name != mac and name.lower() != "unknown":
            return name
    except Exception:
        pass
    return None
