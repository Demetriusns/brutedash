"""netmon/assets.py -- "know the network": the asset inventory.

Every LAN device brutedash has ever seen, enriched with everything it can
learn without touching the device: hostname (DHCP option 12 / mDNS .local
names, observed by capture.py), OS guess (TTL heuristics), vendor (MAC
OUI prefix), and open ports (from the self vulnerability scan).

refresh_assets() folds the raw observation tables into the `assets`
table; the dashboard reads get_assets(). Deterministic throughout --
nothing here decides what is malicious, it just describes what is there.
"""

import os
import re
import time

from . import db as dbm

# MAC OUI (first 3 octets) -> vendor. Loaded from the local oui.txt file
# beside this module -- no external API. Enough to turn "b8:27:eb:.."
# into "Raspberry Pi" without any network lookup.
# (OUI data: IEEE registration, hand-picked common prefixes.)

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")


def _load_oui_table():
    """Load the local OUI vendor table (netmon/oui.txt, no external API).

    The file is the single source of truth; a missing or unreadable file
    just means vendor lookups return '' -- the inventory works without it.
    """
    table = {}
    try:
        path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "oui.txt")
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                prefix, _, vendor = line.partition("|")
                prefix, vendor = prefix.strip().lower(), vendor.strip()
                if len(prefix) == 8 and vendor:
                    table[prefix] = vendor
    except OSError:
        pass
    return table


OUI_VENDORS = _load_oui_table()

def vendor_for_mac(mac):
    """Vendor from the MAC OUI prefix, or '' when unknown.

    Locally-administered (randomized) MACs -- the second hex digit of the
    first octet is 2, 6, a, or e -- have no real OUI, so they always
    return '' instead of a wrong guess.
    """
    mac = (mac or "").strip().lower()
    if not _MAC_RE.match(mac):
        return ""
    first_octet = int(mac[:2], 16)
    if first_octet & 0x02:
        return ""  # randomized / locally administered: no real OUI
    return OUI_VENDORS.get(mac[:8], "")


def os_guess_for_ttl(ttl):
    """OS guess from an observed IP TTL. Heuristic, best-effort.

    Common initial TTLs: 64 (Linux/macOS/Android/iOS/*BSD), 128
    (Windows), 255 (network gear). One LAN hop decrements by 1, so a
    small window around each is used; anything else is '' (unknown).
    """
    try:
        ttl = int(ttl)
    except (TypeError, ValueError):
        return ""
    if 60 <= ttl <= 64:
        return "Linux / macOS / Android / iOS"
    if 124 <= ttl <= 128:
        return "Windows"
    if 250 <= ttl <= 255:
        return "Network gear"
    return ""


def refresh_assets():
    """Rebuild the assets table from everything observed.

    Combines: arp_observations (MAC/IP/first/last seen), device_hostnames
    (DHCP/mDNS names), device_ttl (OS guess), device_names (friendly
    names are NOT stored here -- the dashboard joins them separately),
    and scan_findings (open ports). Returns the number of assets.
    """
    now = time.time()
    ip2mac = dbm.ip_to_mac_map()
    mac2ip = {}
    for ip, mac in ip2mac.items():
        mac2ip.setdefault(mac, []).append(ip)
    hostnames = dbm.device_hostname_map()
    ttls = dbm.device_ttl_map()
    open_ports = {}
    for f in dbm.list_scan_findings(status="open", limit=10000):
        open_ports.setdefault(f["mac"] or f["ip"], []).append({
            "port": f["port"], "service": f["service"], "risk": f["risk"]})

    rows = []
    for dev in dbm.known_devices(limit=1000):
        mac = dev["mac"]
        ips = mac2ip.get(mac, [])
        ip = dev.get("last_ip") or (ips[0] if ips else "")
        hn, hn_src = hostnames.get(mac, ("", ""))
        # OS guess: prefer the TTL of the device's current IP.
        ttl = ttls.get(ip)
        if ttl is None:
            for other in ips:
                if other in ttls:
                    ttl = ttls[other]
                    break
        rows.append({
            "mac": mac, "ip": ip,
            "first_seen": dev.get("first_seen"),
            "last_seen": dev.get("last_seen"),
            "hostname": hn, "hostname_source": hn_src,
            "os_guess": os_guess_for_ttl(ttl) if ttl else "",
            "vendor": vendor_for_mac(mac),
            "open_ports": open_ports.get(mac) or open_ports.get(ip) or [],
            "updated_ts": now,
        })
    dbm.refresh_assets(rows)
    return len(rows)


def get_assets():
    """Enriched inventory for the dashboard, newest activity first.

    Refreshes the table when it's stale (>1h) -- best-effort, never
    breaks the read.
    """
    try:
        if dbm.assets_stale():
            refresh_assets()
    except Exception:
        pass
    return dbm.get_assets()
