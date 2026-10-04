"""netmon/topology.py -- the visual network map: who is on the LAN and how
they connect.

build_topology() returns {gateway, nodes, edges} for the dashboard's Map
view. Nodes come from the asset inventory; the gateway is the default
gateway seen in DHCP option 3, falling back to the most-connected LAN
node. Edges carry byte counts so the UI can weight them; "active" marks
edges with traffic in the last few minutes for the flow animation.

Device classification is best-guess only (OUI vendor, DHCP/mDNS
hostnames, DNS traffic hints, open ports) -- the dashboard lets Demetrius
re-label any device with one click, and the correction persists per-MAC
in the device_types table, surviving re-discovery. Deterministic
throughout: nothing here decides what is malicious.
"""

import time

from . import db as dbm

# Canonical device types. "ap" covers switches and access points (both
# are the boxes the traffic physically passes through).
DEVICE_TYPES = ("phone", "laptop", "desktop", "tv", "printer", "iot",
                "ap", "router", "server", "unknown")

TYPE_LABELS = {
    "phone": "Phone", "laptop": "Laptop", "desktop": "Desktop",
    "tv": "TV / streaming", "printer": "Printer", "iot": "Smart home / IoT",
    "ap": "Switch / access point", "router": "Router",
    "server": "Server", "unknown": "Unknown",
}

# Inline emoji icons -- no image assets needed.
TYPE_ICONS = {
    "phone": "\U0001F4F1", "laptop": "\U0001F4BB",
    "desktop": "\U0001F5A5\uFE0F", "tv": "\U0001F4FA",
    "printer": "\U0001F5A8\uFE0F", "iot": "\U0001F50C",
    "ap": "\U0001F4E1", "router": "\U0001F310",
    "server": "\U0001F5C4\uFE0F", "unknown": "\u2753",
}


def valid_dtype(dtype):
    """True for a known device-type key (the re-label allowlist)."""
    return (dtype or "").strip().lower() in DEVICE_TYPES


def _is_lan_ip(ip):
    """True for RFC1918 addresses (the LAN we draw)."""
    try:
        parts = str(ip).split(".")
        if len(parts) != 4:
            return False
        o = [int(p) for p in parts]
    except (ValueError, TypeError):
        return False
    a, b = o[0], o[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


# Hostname keyword -> type. Checked in order; the first hit wins.
# (hostname is the strongest signal -- it is what the device calls itself)
_HOSTNAME_HINTS = (
    (("roku", "firetv", "fire-tv", "chromecast", "appletv", "apple-tv",
       "smart-tv", "smarttv", "kodi", "plex", "shield-tv", "nvidia-shield"),
     "tv"),
    (("printer", "print", "laserjet", "officejet", "deskjet"), "printer"),
    (("echo", "alexa", "googlehome", "google-home", "nest", "ring",
       "wyze", "arlo", "eufy", "tuya", "smartplug", "thermostat",
       "doorbell", "vivint"), "iot"),
    (("server", "nas", "synology", "qnap", "pihole", "pi-hole",
       "proxmox", "homelab", "unraid"), "server"),
    (("iphone", "ipad"), "phone"),
    (("pixel", "galaxy", "-android"), "phone"),
    (("laptop", "notebook", "macbook", "thinkpad", "xps"), "laptop"),
    (("desktop", "workstation", "tower", "imac", "mac-mini",
       "macmini"), "desktop"),
)

_PRINTER_VENDORS = ("canon", "epson", "brother", "xerox", "lexmark",
                    "kyocera", "seiko epson")
_AP_VENDORS = ("ubiquiti", "unifi", "netgear", "tp-link", "tplink",
               "linksys", "d-link", "dlink", "mikrotik", "aruba",
               "ruckus", "cisco")
_IOT_VENDORS = ("espressif", "tuya", "wyze")
_PC_VENDORS = ("dell", "hewlett", "hp ", "lenovo", "asus", "acer",
               "msi", "gigabyte")

# DNS query substrings -> traffic hint. Streaming services and Apple
# infrastructure are the two patterns worth noticing on a home LAN.
_STREAMING_TOKENS = ("netflix", "nflxvideo", "nflxso", "hulu", "disneyplus",
                     "hbomax", "max.", "primevideo", "youtube", "youtu",
                     "youtu.be", "roku", "plxtv", "plex")
_APPLE_TOKENS = ("apple.com", "icloud.com", "mzstatic.com",
                 "push.apple.com")


def classify_device(mac, vendor="", hostname="", os_guess="",
                    open_ports=(), is_gateway=False, dns_hints=()):
    """Best-guess device type. Returns (dtype, source).

    source is "manual" when Demetrius pinned it, else "auto". Precedence:
    his pin > gateway > hostname keywords > DNS traffic hints > vendor
    keywords > open ports > OS guess. Anything ambiguous stays
    "unknown" -- a wrong guess is cheap to fix, but no guess is honest.
    """
    mac = (mac or "").strip().lower()
    override = dbm.device_type_map().get(mac)
    if override in DEVICE_TYPES:
        return override, "manual"
    if is_gateway:
        return "router", "auto"
    hn = (hostname or "").lower()
    ven = (vendor or "").lower()
    hints = set(dns_hints or ())
    for keywords, dtype in _HOSTNAME_HINTS:
        if any(k in hn for k in keywords):
            return dtype, "auto"
    if "streaming" in hints:
        return "tv", "auto"
    if "apple" in hints and "mac" not in hn and "desktop" not in hn:
        # iPhones/iPads are the Apple things phoning home constantly;
        # a Mac that says so in its hostname was caught above.
        return "phone", "auto"
    if any(v in ven for v in _PRINTER_VENDORS):
        return "printer", "auto"
    if any(v in ven for v in _AP_VENDORS):
        return "ap", "auto"
    if any(v in ven for v in _IOT_VENDORS):
        return "iot", "auto"
    if "raspberry" in ven:
        return "server", "auto"
    ports = set()
    for p in (open_ports or ()):
        try:
            ports.add(int(p.get("port") if isinstance(p, dict) else p))
        except (TypeError, ValueError):
            continue
    if 9100 in ports or 631 in ports:
        return "printer", "auto"  # JetDirect / IPP: it's a printer
    if "windows" in (os_guess or "").lower() and any(
            v in ven for v in _PC_VENDORS):
        return "laptop", "auto"  # best guess; one click fixes it
    return "unknown", "auto"


def dns_hints_for_ips(ips, hours=24, limit=5000):
    """{ip: set(hints)} from recent DNS queries. Bounded by `limit`.

    hints are "streaming" (Netflix/YouTube/etc. lookups) and "apple"
    (Apple/iCloud infrastructure). Cheap traffic-pattern signals for
    the classifier.
    """
    ips = set(ips or ())
    if not ips:
        return {}
    cutoff = time.time() - hours * 3600
    out = {}
    try:
        rows = dbm.query(
            "SELECT src_ip, name FROM dns_queries WHERE ts > ?"
            " ORDER BY ts DESC LIMIT ?", (cutoff, limit))
    except Exception:
        return {}
    for src_ip, name in rows:
        if src_ip not in ips:
            continue
        lname = (name or "").lower()
        if any(t in lname for t in _STREAMING_TOKENS):
            out.setdefault(src_ip, set()).add("streaming")
        if any(t in lname for t in _APPLE_TOKENS):
            out.setdefault(src_ip, set()).add("apple")
    return out


def gateway_info():
    """(ip, mac) of the default gateway, or (None, None).

    Prefers the gateway seen in DHCP option 3 (capture.py stores it);
    falls back to the most-connected LAN node (most distinct LAN peers
    in the last 24h) -- on a home network that is the router.
    """
    ip2mac = dbm.ip_to_mac_map()
    gw_ip = None
    try:
        gw_ip = dbm.get_meta("dhcp_gateway_ip")
    except Exception:
        gw_ip = None
    if gw_ip and _is_lan_ip(gw_ip):
        return gw_ip, ip2mac.get(gw_ip, "")
    # Fallback: the LAN IP talking to the most other LAN IPs.
    cutoff = time.time() - 86400
    peers = {}
    try:
        rows = dbm.query(
            "SELECT src_ip, dst_ip FROM flows WHERE ts > ?", (cutoff,))
    except Exception:
        rows = []
    for src, dst in rows:
        if _is_lan_ip(src) and _is_lan_ip(dst) and src != dst:
            peers.setdefault(src, set()).add(dst)
            peers.setdefault(dst, set()).add(src)
    if not peers:
        return None, None
    best = max(peers, key=lambda ip: len(peers[ip]))
    return best, ip2mac.get(best, "")


def _device_bytes(window_s):
    """{(ip): (up_bytes, down_bytes)} for the window. Best-effort."""
    cutoff = time.time() - window_s
    up, down = {}, {}
    try:
        rows = dbm.query(
            "SELECT src_ip, dst_ip, SUM(bytes) FROM flows WHERE ts > ?"
            " GROUP BY src_ip, dst_ip", (cutoff,))
    except Exception:
        rows = []
    for src, dst, nbytes in rows:
        n = nbytes or 0
        if _is_lan_ip(src):
            up[src] = up.get(src, 0) + n
        if _is_lan_ip(dst):
            down[dst] = down.get(dst, 0) + n
    return up, down


def _alert_counts_24h(ips):
    """{ip: count} of alerts in the last 24h naming each IP.

    Word-boundary match: "192.168.1.1" must not match "192.168.1.10".
    """
    import re as _re
    ips = set(ips or ())
    if not ips:
        return {}
    cutoff = time.time() - 86400
    patterns = {ip: _re.compile(r"\b" + _re.escape(ip) + r"\b")
                for ip in ips}
    counts = {}
    try:
        rows = dbm.query(
            "SELECT title, detail FROM alerts WHERE ts > ?", (cutoff,))
    except Exception:
        rows = []
    for title, detail in rows:
        blob = f"{title or ''} {detail or ''}"
        for ip, pat in patterns.items():
            if pat.search(blob):
                counts[ip] = counts.get(ip, 0) + 1
    return counts


def build_topology(window_min=60):
    """{gateway, nodes, edges} for the Map view.

    nodes: one per known asset (mac, ip, name, hostname, vendor,
    os_guess, dtype, dtype_source, up/down MB in the window, alerts in
    the last 24h, first_seen, open_ports).
    edges: {a, b, bytes, active} keyed by MAC (IP fallback); one per
    device<->gateway pair plus LAN-local device pairs with observed
    flows. `active` means traffic in the last 5 minutes (drives the
    flow animation).
    """
    from . import assets as assetsm
    try:
        assets_list = assetsm.get_assets()
    except Exception:
        assets_list = []
    names = dbm.device_name_map()
    gw_ip, gw_mac = gateway_info()
    ip2mac = dbm.ip_to_mac_map()
    window_s = max(60, int(window_min or 60)) * 60
    up, down = _device_bytes(window_s)
    _up5, _down5 = _device_bytes(300)
    active_ips = {ip for ip in set(_up5) | set(_down5)
                  if _up5.get(ip, 0) + _down5.get(ip, 0) > 0}
    ips = [a.get("ip") for a in assets_list if a.get("ip")]
    hints = dns_hints_for_ips(ips)
    alert_counts = _alert_counts_24h(ips)

    def node_key(mac, ip):
        return (mac or "").lower() or (ip or "")

    nodes = []
    for a in assets_list:
        mac = (a.get("mac") or "").lower()
        ip = a.get("ip") or ""
        is_gw = bool(gw_ip and ip == gw_ip) or bool(
            gw_mac and mac and mac == gw_mac.lower())
        dtype, dsource = classify_device(
            mac, vendor=a.get("vendor"), hostname=a.get("hostname"),
            os_guess=a.get("os_guess"), open_ports=a.get("open_ports"),
            is_gateway=is_gw, dns_hints=hints.get(ip, ()))
        u, d = up.get(ip, 0), down.get(ip, 0)
        nodes.append({
            "key": node_key(mac, ip),
            "mac": mac, "ip": ip,
            "name": names.get(mac, ""),
            "hostname": a.get("hostname") or "",
            "vendor": a.get("vendor") or "",
            "os_guess": a.get("os_guess") or "",
            "dtype": dtype, "dtype_source": dsource,
            "icon": TYPE_ICONS.get(dtype, TYPE_ICONS["unknown"]),
            "type_label": TYPE_LABELS.get(dtype, dtype),
            "is_gateway": is_gw,
            "up_mb": round(u / 1e6, 2), "down_mb": round(d / 1e6, 2),
            "alerts_24h": alert_counts.get(ip, 0),
            "first_seen": a.get("first_seen") or 0,
            "open_ports": a.get("open_ports") or [],
        })

    # Edges: device<->gateway, plus LAN-local device pairs with flows.
    pair_bytes = {}
    pair_active = set()
    try:
        rows = dbm.query(
            "SELECT src_ip, dst_ip, SUM(bytes),"
            " MAX(CASE WHEN ts > ? THEN 1 ELSE 0 END)"
            " FROM flows WHERE ts > ? GROUP BY src_ip, dst_ip",
            (time.time() - 300, time.time() - window_s))
    except Exception:
        rows = []
    for src, dst, nbytes, active in rows:
        if not (_is_lan_ip(src) and _is_lan_ip(dst)) or src == dst:
            continue
        a, b = node_key(ip2mac.get(src, ""), src), \
            node_key(ip2mac.get(dst, ""), dst)
        if a == b:
            continue
        key = tuple(sorted((a, b)))
        pair_bytes[key] = pair_bytes.get(key, 0) + (nbytes or 0)
        if active:
            pair_active.add(key)

    gw_key = node_key(gw_mac, gw_ip) if (gw_ip or gw_mac) else None
    edges = []
    for (a, b), nbytes in pair_bytes.items():
        involves_gw = gw_key is not None and gw_key in (a, b)
        edges.append({"a": a, "b": b, "bytes": nbytes,
                      "active": (a, b) in pair_active,
                      "kind": "gateway" if involves_gw else "lan"})
    # Every device gets a gateway spoke even with no observed flows,
    # so the gateway never renders disconnected from its LAN.
    if gw_key:
        have_spoke = {e["a"] for e in edges if e["kind"] == "gateway"
                      and e["b"] == gw_key} | \
                     {e["b"] for e in edges if e["kind"] == "gateway"
                      and e["a"] == gw_key}
        for n in nodes:
            nk = node_key(n["mac"], n["ip"])
            if n.get("is_gateway"):
                continue
            if nk and nk != gw_key and nk not in have_spoke:
                edges.append({"a": nk, "b": gw_key, "bytes": 0,
                              "active": False, "kind": "gateway"})
    edges.sort(key=lambda e: e["bytes"], reverse=True)
    edges = edges[:120]  # bound the render on busy networks

    gateway = None
    if gw_ip or gw_mac:
        gateway = {"ip": gw_ip or "", "mac": (gw_mac or "").lower(),
                   "key": gw_key}
    return {"gateway": gateway, "nodes": nodes, "edges": edges,
            "window_min": window_min,
            "types": [{"key": t, "label": TYPE_LABELS[t],
                       "icon": TYPE_ICONS[t]} for t in DEVICE_TYPES]}
