"""netmon/detect.py -- periodic detection rules over stored flows.

The live port-scan check runs inline in capture.py (it needs per-packet
SYN timing). Everything here runs on a schedule against the flows table:

  traffic_spike this 5-minute bucket moved far more bytes than usual
  unusual_port outbound traffic to a port outside the common set
  beaconing steady, clockwork check-ins with one outside address
  new_external_ip first-ever contact with an outside address (baseline)
  volume_anomaly known address suddenly moving far more than its baseline
  dns_lookup_burst one domain looked up hundreds of times in minutes
  dns_tunneling many distinct subdomains of one parent (tunnel shape)
  new_busy_domain never-seen domain suddenly looked up a lot
  new_device a never-seen device joined the local network
  arp_spoof ARP lies: one MAC claiming many IPs, or an IP changing MAC
  behavior_deviation a device moving far more than its own learned
    hourly baseline (per-device profiles -- quiet-first)

Every alert carries plain-English fields (meaning / is_this_normal /
what_to_do) so a non-technical reader can understand it. Each rule
checks the alerts table first so it only fires once per cooldown window
instead of spamming.
"""


import ipaddress
import time

from. import db as dbm


def _whole_network():
    """True when capture is relaying the whole LAN (see capture.py)."""
    try:
        from .capture import whole_network_mode
        return whole_network_mode()
    except Exception:
        return False


_LOCAL_IPS_CACHE = None


def _device_label(ip):
    """Plain-English label for an alert: 'this computer (ip)' or 'device ip'."""
    global _LOCAL_IPS_CACHE
    if _LOCAL_IPS_CACHE is None:
        try:
            from .capture import get_local_ips
            _LOCAL_IPS_CACHE = get_local_ips()
        except Exception:
            _LOCAL_IPS_CACHE = set()
    if ip and ip in _LOCAL_IPS_CACHE:
        return f"this computer ({ip})"
    return f"device {ip}" if ip else "a device on your network"


def _device_sentence(ip):
    """_device_label capitalized for the start of a sentence."""
    label = _device_label(ip)
    return label[0].upper() + label[1:] if label else label


# Ports a normal home machine talks to every day. Anything outbound to a
# port NOT on this list is worth a second look (not proof of evil -- game
# servers, dev tools, and VoIP apps all use odd ports).
COMMON_PORTS = {
    80, 443, # web
    53, # DNS
    123, # NTP time sync
    22, # SSH
    25, 465, 587, 993, 995, # email
    67, 68, # DHCP
    1900, 5353, # local discovery (SSDP/mDNS)
    3478, 3479, 3480, # STUN / video calls
    5222, 5223, # chat push notifications
}

# Windows NetBIOS chatter (network name lookups, file/printer sharing
# discovery). Completely normal *inside* a home network -- only worth
# flagging when it leaves the LAN, which never happens legitimately.
LAN_ONLY_PORTS = {137, 138, 139}


def _is_lan_ip(ip):
    """True for LAN-local addresses (never the public internet)."""
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False


SPIKE_WINDOW = 300 # compare the last 5 minutes...
SPIKE_BASELINE = 3600 #... against the previous hour
SPIKE_FACTOR = 5.0 # alert when recent >= 5x the hourly average
SPIKE_COOLDOWN = 1800
PORT_COOLDOWN = 3600


BEACON_WINDOW = 3600 # look back one hour, in 5-minute buckets
BEACON_BUCKET = 300
BEACON_MIN_BUCKETS = 8 # active in at least 8 of 12 buckets
BEACON_COOLDOWN = 3600


# --- baseline / first-contact checks (phase 3) -------------------------
BASELINE_WINDOW = 3600 # per-IP traffic over the last hour...
BASELINE_MIN_BYTES = 1_000_000 #... >1 MB to a never-seen IP is worth noting
BASELINE_COOLDOWN = 86400 # 24h per IP
VOLUME_MIN_BYTES = 50_000_000 # volume alerts need >50 MB absolute...
VOLUME_FACTOR = 10.0 #... AND >10x the 7-day hourly baseline
VOLUME_BASELINE_SECS = 7 * 86400
VOLUME_COOLDOWN = 86400


# --- DNS checks (phase 3) ----------------------------------------------
DNS_WINDOW = 600 # last 10 minutes of lookups
DNS_BURST_COUNT = 200 # >200 lookups of one domain: burst/misconfig
DNS_TUNNEL_SUBDOMAINS = 25 # >25 distinct subdomains of one parent: tunnel shape
DNS_NEW_DOMAIN_COUNT = 50 # never-seen domain with >50 lookups
DNS_COOLDOWN = 3600


# --- LAN device checks (phase 3) ---------------------------------------
ARP_NEW_WINDOW = 3600 # ARP sightings over the last hour
ARP_NEW_COOLDOWN = 86400 # 24h per MAC
ARP_SPOOF_WINDOW = 1800 # ARP sightings over the last 30 minutes
ARP_SPOOF_MIN_IPS = 3 # one MAC claiming 3+ IPs looks like spoofing
ARP_SPOOF_COOLDOWN = 3600


# --- per-device behavior deviation (phase 3.5: quiet-first) -------------
# Each device gets a learned baseline of "how much it normally moves in
# each hour of the day" (see db.device_profiles). This rule fires only
# when a device moves >=4x its own baseline AND clears a 250 MB absolute
# floor, so idle devices can't page over pocket change, and devices
# younger than 24h are left to the probation_watch rule. AI narrates,
# code decides: the LLM never invents a baseline, only explains this one.
BEHAVIOR_WINDOW = 3600 # compare the last hour...
BEHAVIOR_FACTOR = 4.0 # ...against >=4x this device's learned hourly normal
BEHAVIOR_MIN_BYTES = 250_000_000 # ...plus a 250 MB absolute floor
BEHAVIOR_MIN_DAYS = 3 # the baseline hour needs 3+ days behind it
BEHAVIOR_COOLDOWN = 86400 # one alert per device per day


def _is_external_ip(ip):
    """True for public-internet addresses (not LAN, loopback, multicast)."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _suppressed(kind, text):
    """Allowlist check: True if the user whitelisted this pattern, in
    which case the rule stays silent. Never breaks detection."""
    try:
        return dbm.is_allowlisted(kind, text)
    except Exception:
        return False


def _parent_domain(name):
    """Last two labels of a DNS name: s1.mail.example.com -> example.com."""
    labels = name.strip().strip(".").lower().split(".")
    if len(labels) >= 2:
        return ".".join(labels[-2:])
    return labels[0] if labels else ""


def check_traffic_spike(now=None):
    """Alert when recent throughput dwarfs the recent baseline."""
    now = now or time.time()
    recent = dbm.query(
        "SELECT COALESCE(SUM(bytes),0) FROM flows WHERE ts >?",
        (now - SPIKE_WINDOW,))
    base = dbm.query(
        "SELECT COALESCE(SUM(bytes),0) FROM flows"
        " WHERE ts >? AND ts <=?",
        (now - SPIKE_WINDOW - SPIKE_BASELINE, now - SPIKE_WINDOW))
    recent_bytes = recent[0][0] or 0
    base_bytes = base[0][0] or 0
    if base_bytes <= 0 or recent_bytes < base_bytes * SPIKE_FACTOR:
        return None
    if dbm.recent_alert_kind("traffic_spike", "throughput", SPIKE_COOLDOWN):
        return None
    baseline_avg = base_bytes / (SPIKE_BASELINE / 60)
    recent_avg = recent_bytes / (SPIKE_WINDOW / 60)
    detail = (f"Moved {recent_bytes/1e6:.1f} MB in the last 5 minutes vs a"
              f" baseline of ~{baseline_avg/1e6:.1f} MB/min over the previous"
              " hour.")
    wn = _whole_network()
    dbm.add_alert(
        "traffic_spike", "Medium",
        "Unusual surge in network traffic", detail,
        meaning=(("Your network suddenly moved far more data than"
                  " usual -- like a water bill jumping 5x in one month."
                  " Something moved a lot of data in a short time.")
                 if wn else
                 ("This machine suddenly sent or received far more data than"
                  " usual -- like a water bill jumping 5x in one month."
                  " Something moved a lot of data in a short time.")),
        is_normal=("This is normal if someone was downloading a large file,"
                   " backing up photos, updating a game, or on a long video"
                   " call. It is not normal if nobody was using the"
                   + ("network." if wn else "computer.")),
        what_to_do=("Think about what was running in the last few minutes."
                    " If nothing explains it, check the per-device traffic"
                    " on the dashboard to see which device moved the data."),
        ts=now)
    return detail


def check_unusual_ports(now=None):
    """Flag outbound flows to ports outside the common set, per device."""
    now = now or time.time()
    rows = dbm.query(
        "SELECT src_ip, dst_ip, dst_port, SUM(bytes) FROM flows"
        " WHERE ts >? AND direction='outbound' AND proto IN ('TCP','UDP')"
        " GROUP BY src_ip, dst_ip, dst_port",
        (now - 900,))
    fired = []
    for src_ip, dst_ip, dst_port, nbytes in rows:
        if dst_port in COMMON_PORTS:
            continue
        if dst_port in LAN_ONLY_PORTS and _is_lan_ip(dst_ip):
            continue  # normal Windows chatter inside the home network
        key = f"{src_ip}:{dst_ip}:{dst_port}"
        if _suppressed("unusual_port", key):
            continue
        if dbm.recent_alert_kind("unusual_port", key, PORT_COOLDOWN):
            continue
        mb = (nbytes or 0) / 1e6
        dev = _device_label(src_ip)
        dev_s = _device_sentence(src_ip)
        dbm.add_alert(
            "unusual_port", "Medium",
            f"Talking on an unusual channel (port {dst_port})",
            f"{dev_s} sent traffic to {dst_ip} on port {dst_port}"
            f" ({mb:.2f} MB in the last 15 min).",
            meaning=(f"{dev_s} talked to the outside world on a channel"
                     " (called a 'port') that everyday apps don't use. Think"
                     " of ports like TV channels -- most apps use the popular"
                     " ones, and this one used an obscure channel."),
            is_normal=("Often fine: games, work VPNs, video-chat apps, and"
                       " developer tools all use unusual ports. It only"
                       " matters if you don't recognize the program or"
                       f" device ({dev}) doing it."),
            what_to_do=("Match the time to what that device was doing."
                        " Gaming or on a work call? Expected. Otherwise,"
                        " search the web for 'port {0}' to see what normally"
                        " uses it.".format(dst_port)),
            ts=now,
)
        fired.append(key)
    return fired

def check_beaconing(now=None):
    """Flag steady, clockwork check-ins with one outside address.

    Legit apps do this (email checking for new mail), but malware also
    "phones home" on a schedule -- so regular, frequent contact with an
    address is worth surfacing in plain language.
    """
    now = now or time.time()
    rows = dbm.query(
        "SELECT src_ip, dst_ip, CAST(ts /? AS INTEGER) AS bkt, SUM(bytes)"
        " FROM flows WHERE ts >? AND direction='outbound'"
        " AND proto IN ('TCP','UDP')"
        " GROUP BY src_ip, dst_ip, bkt",
        (BEACON_BUCKET, now - BEACON_WINDOW))
    per_pair = {}
    for src_ip, dst_ip, bkt, nbytes in rows:
        d = per_pair.setdefault((src_ip, dst_ip),
                                {"buckets": set(), "bytes": 0})
        d["buckets"].add(bkt)
        d["bytes"] += nbytes or 0
    fired = []
    for (src_ip, dst_ip), d in per_pair.items():
        buckets = sorted(d["buckets"])
        if len(buckets) < BEACON_MIN_BUCKETS:
            continue
        span_min = (buckets[-1] - buckets[0]) * (BEACON_BUCKET / 60)
        avg_every = span_min / max(len(buckets) - 1, 1)
        key = f"{src_ip}:{dst_ip}"
        if dbm.recent_alert_kind("beaconing", key, BEACON_COOLDOWN):
            continue
        mb = d["bytes"] / 1e6
        dev = _device_label(src_ip)
        dev_s = _device_sentence(src_ip)
        dbm.add_alert(
            "beaconing", "Medium",
            f"Repeated check-ins: {dev} with {dst_ip}",
            (f"{dev_s} contacted {dst_ip} in {len(buckets)} of the last"
             f" {BEACON_WINDOW // 60} minutes -- roughly every"
             f" {avg_every:.0f} minutes ({mb:.2f} MB total)."),
            meaning=(f"{dev_s} contacted the same outside address on a"
                     " steady schedule, like clockwork. Some of this is"
                     " routine -- apps checking for updates or new messages"
                     " -- but malware also 'phones home' this way, so a"
                     " regular heartbeat to an unknown address is worth a"
                     " look."),
            is_normal=("Normal if the address belongs to a service used on"
                       f" that device ({dev}) -- email, chat, cloud backup,"
                       " antivirus. Suspicious if you don't recognize the"
                       " address, especially when each check-in moves only a"
                       " tiny amount of data."),
            what_to_do=("Search the web for the address to see who owns it."
                        " If it's a service used on that device, you can"
                        " ignore this. If not, note when it started and"
                        " consider running an antivirus scan on the device."),
            ts=now,
)
        fired.append(key)
    return fired


def _hourly_bytes_by_pair(now, window=BASELINE_WINDOW):
    """{(src_ip, external dst_ip): bytes} for outbound TCP/UDP in `window`."""
    rows = dbm.query(
        "SELECT src_ip, dst_ip, SUM(bytes) FROM flows"
        " WHERE ts >? AND direction='outbound' AND proto IN ('TCP','UDP')"
        " GROUP BY src_ip, dst_ip",
        (now - window,))
    return {(s, ip): (nbytes or 0) for s, ip, nbytes in rows
            if s and _is_external_ip(ip)}


def check_baseline_anomalies(now=None):
    """Flag first-time contacts and IPs moving far more than their baseline.

    First part: an outside address this machine has never talked to before
    that suddenly moves real traffic (>1 MB in an hour) -- like a letter
    from a pen pal you've never heard of. Usually a new app or service;
    worth noting once.

    Second part: a known address whose last hour dwarfs its own 7-day
    hourly average (>10x and >50 MB absolute) -- like a faucet suddenly
    running full blast. Could be a big legitimate upload, or data quietly
    leaving the machine.
    """
    now = now or time.time()
    hourly = _hourly_bytes_by_pair(now)
    fired = []

    # 1) first time this device talked to this outside address
    for src_ip, ip in sorted(hourly):
        nbytes = hourly[(src_ip, ip)]
        if nbytes < BASELINE_MIN_BYTES:
            continue
        seen_key = f"{src_ip}|{ip}"
        if dbm.get_first_seen("ext_ip", seen_key) is not None:
            continue
        dbm.note_first_seen("ext_ip", seen_key, now)
        if dbm.recent_alert_kind("new_external_ip", seen_key,
                                  BASELINE_COOLDOWN):
            continue
        mb = nbytes / 1e6
        dev = _device_label(src_ip)
        dev_s = _device_sentence(src_ip)
        dbm.add_alert(
            "new_external_ip", "Low",
            f"First time {dev} talked to {ip}",
            (f"{dev_s} exchanged {mb:.1f} MB with {ip} in the last"
             " hour, and has no record of talking to it before."),
            meaning=(f"{dev_s} started talking to a new address on the"
                     " internet -- like getting a letter from a pen pal"
                     " you've never heard of. First contact isn't proof of"
                     " anything bad; new apps, games, and services do this"
                     " all the time."),
            is_normal=("Normal if something new was installed, updated, or"
                       f" opened on that device ({dev}) recently -- an app,"
                       " a game, a work tool. Worth a second look if nothing"
                       " new was started around that time."),
            what_to_do=("Think about what started running on that device in"
                        " the last day or two. If something matches, you can"
                        " ignore this. If not, search the web for the"
                        " address to see who owns it."),
            ts=now,
)
        fired.append(("new_external_ip", seen_key))

    # 2) known address suddenly moving far more than its own baseline
    for src_ip, ip in sorted(hourly):
        hour_bytes = hourly[(src_ip, ip)]
        if hour_bytes < VOLUME_MIN_BYTES:
            continue
        base = dbm.query(
            "SELECT COALESCE(SUM(bytes),0) FROM flows"
            " WHERE ts >? AND direction='outbound' AND src_ip=?"
            " AND dst_ip=? AND proto IN ('TCP','UDP')",
            (now - VOLUME_BASELINE_SECS, src_ip, ip))[0][0] or 0
        baseline_hourly = base / (VOLUME_BASELINE_SECS / 3600)
        if baseline_hourly <= 0:
            continue # zero baseline: covered by the first-seen check above
        if hour_bytes < baseline_hourly * VOLUME_FACTOR:
            continue
        vol_key = f"{src_ip}|{ip}"
        if dbm.recent_alert_kind("volume_anomaly", vol_key, VOLUME_COOLDOWN):
            continue
        dev = _device_label(src_ip)
        dev_s = _device_sentence(src_ip)
        dbm.add_alert(
            "volume_anomaly", "Medium",
            f"Unusually heavy traffic: {dev} with {ip}",
            (f"{dev_s} sent {hour_bytes/1e6:.0f} MB to {ip} in the last"
             f" hour -- more than {VOLUME_FACTOR:.0f}x its usual"
             f" ~{baseline_hourly/1e6:.1f} MB/hour over the past 7 days."),
            meaning=("One of your network's regular internet contacts"
                     f" suddenly received far more data from {dev} than"
                     " ever before -- like a faucet that was dripping and"
                     " is now running full blast. Sometimes that's a big"
                     " upload or backup; sometimes it's data quietly"
                     " leaving the device."),
            is_normal=("Normal if someone was uploading a large file,"
                       f" backing up photos, or syncing a cloud drive from"
                       f" that device ({dev}). Not normal if nobody was"
                       " doing anything data-heavy."),
            what_to_do=("Match the time to what that device was doing. If"
                        " someone was uploading or syncing, this is"
                        " expected. Otherwise, check which app sent the data"
                        " and consider running an antivirus scan."),
            ts=now,
)
        fired.append(("volume_anomaly", vol_key))
    return fired


def check_dns_anomalies(now=None):
    """Flag odd DNS lookup patterns over the last 10 minutes.

    (a) one domain looked up >200 times -- apps sometimes do this by
        mistake, but malware also abuses DNS to sneak data out.
    (b) >25 different subdomains of the same parent domain -- the classic
        shape of DNS tunneling (data hidden inside lookup names).
    (c) a never-before-seen domain suddenly looked up >50 times.
    """
    now = now or time.time()
    rows = dbm.query(
        "SELECT COALESCE(src_ip,'unknown'), name, COUNT(*) FROM dns_queries"
        " WHERE ts >? GROUP BY COALESCE(src_ip,'unknown'), name",
        (now - DNS_WINDOW,))
    counts = {(s, name): c for s, name, c in rows if name}
    names = dbm.query(
        "SELECT DISTINCT COALESCE(src_ip,'unknown'), name FROM dns_queries"
        " WHERE ts >?",
        (now - DNS_WINDOW,))
    fired = []

    # (a) lookup burst for a single domain, per device
    for src_ip, name in sorted(counts):
        if counts[(src_ip, name)] <= DNS_BURST_COUNT:
            continue
        key = f"{src_ip}|{name}"
        if dbm.recent_alert_kind("dns_lookup_burst", key, DNS_COOLDOWN):
            continue
        dev = _device_label(src_ip if src_ip != "unknown" else None)
        dev_s = _device_sentence(src_ip if src_ip != "unknown" else None)
        dbm.add_alert(
            "dns_lookup_burst", "Medium",
            f"Lots of lookups for {name} ({dev})",
            (f"{dev_s} looked up {name} {counts[(src_ip, name)]} times in"
             " the last 10 minutes."),
            meaning=(f"{dev_s} asked 'where is this address?' for the"
                     " same domain hundreds of times in a few minutes --"
                     " like calling directory assistance over and over for"
                     " the same number. Glitchy apps do this, but attackers"
                     " also abuse lookups to sneak data out."),
            is_normal=("Often just a misconfigured or chatty app retrying"
                       " too fast. Suspicious if the domain looks random or"
                       " you don't recognize it."),
            what_to_do=("Note which program was running on that device at"
                        " the time. If you recognize the domain as one of"
                        " its apps, you can ignore this; if not, search the"
                        " web for the domain."),
            ts=now,
)
        fired.append(("dns_lookup_burst", key))

    # (b) many distinct subdomains under one parent domain, per device
    subs = {}
    for src_ip, name in names:
        if not name:
            continue
        subs.setdefault((src_ip, _parent_domain(name)),
                        set()).add(name.strip().lower())
    for (src_ip, parent), qnames in sorted(subs.items()):
        if len(qnames) <= DNS_TUNNEL_SUBDOMAINS:
            continue
        key = f"{src_ip}|{parent}"
        if dbm.recent_alert_kind("dns_tunneling", key, DNS_COOLDOWN):
            continue
        dev = _device_label(src_ip if src_ip != "unknown" else None)
        dev_s = _device_sentence(src_ip if src_ip != "unknown" else None)
        dbm.add_alert(
            "dns_tunneling", "High",
            f"Possible DNS tunneling via {parent} ({dev})",
            (f"{dev_s} looked up {len(qnames)} different {parent} addresses"
             " in the last 10 minutes."),
            meaning=("Lots of strange, one-time-looking addresses under the"
                     " same domain were asked about in a hurry. That is the"
                     " classic shape of 'DNS tunneling' -- sneaking data out"
                     " of the network disguised as ordinary address lookups,"
                     " like passing notes written on the back of postcards."),
            is_normal=("Rarely normal on a home network. Some antivirus and"
                       " corporate security tools do rapid lookups like"
                       " this, but a home device usually has no reason to"
                       " ask about dozens of odd subdomains at once."),
            what_to_do=("Note the time and which program was running on"
                        f" that device ({dev}). If you don't recognize the"
                        " domain, search the web for it, and consider"
                        " disconnecting the device and running an antivirus"
                        " scan."),
            ts=now,
)
        fired.append(("dns_tunneling", key))

    # (c) first-seen domain suddenly popular, per device
    for src_ip, name in sorted(counts):
        if counts[(src_ip, name)] <= DNS_NEW_DOMAIN_COUNT:
            continue
        seen_key = f"{src_ip}|{name}"
        if dbm.get_first_seen("domain", seen_key) is not None:
            continue
        dbm.note_first_seen("domain", seen_key, now)
        if dbm.recent_alert_kind("new_busy_domain", seen_key, DNS_COOLDOWN):
            continue
        dev = _device_label(src_ip if src_ip != "unknown" else None)
        dev_s = _device_sentence(src_ip if src_ip != "unknown" else None)
        dbm.add_alert(
            "new_busy_domain", "Low",
            f"New domain getting lots of lookups: {name} ({dev})",
            (f"{dev_s} looked up {name} {counts[(src_ip, name)]} times in"
             " the last 10 minutes, and this is the first time it has"
             " shown up for that device."),
            meaning=(f"A domain {dev} never asked about before"
                     " suddenly got asked about dozens of times -- like a"
                     " stranger's name popping up all over your call log."
                     " New apps do this when they phone home for the first"
                     " time."),
            is_normal=("Normal if something new was just installed or"
                       f" opened on that device ({dev}). Worth a look if"
                       " nothing new was started."),
            what_to_do=("Think about what was opened on that device"
                        " recently. If something matches the domain, ignore"
                        " this. If not, search the web for the domain name."),
            ts=now,
)
        fired.append(("new_busy_domain", seen_key))
    return fired


def check_new_devices(now=None):
    """Flag hardware addresses never seen on the local network before.

    A new MAC means a new network card talked on the LAN -- usually a
    phone, laptop, or smart gadget joining. Like a new face on the block:
    mostly a neighbor, occasionally worth checking.
    """
    now = now or time.time()
    rows = dbm.query(
        "SELECT mac, ip, MAX(ts) FROM arp_observations WHERE ts >?"
        " GROUP BY mac",
        (now - ARP_NEW_WINDOW,))
    fired = []
    for mac, ip, _seen in rows:
        if not mac:
            continue
        if dbm.get_first_seen("mac", mac) is not None:
            continue
        dbm.note_first_seen("mac", mac, now)
        if _suppressed("new_device", mac):
            continue
        if dbm.recent_alert_kind("new_device", mac, ARP_NEW_COOLDOWN):
            continue
        detail = (f"A new device ({mac}) appeared on the local network"
                  + (f" as {ip}." if ip else "."))
        dbm.add_alert(
            "new_device", "Low",
            f"New device joined the network ({mac})",
            detail,
            meaning=("A device your network has never seen before just"
                     " showed up -- like a new face on the block. It could"
                     " be a phone, laptop, TV, or smart gadget connecting"
                     " for the first time."),
            is_normal=("Normal if you or someone at home just connected a"
                       " new or returning device -- a guest's phone, a new"
                       " TV, a smart plug. Not normal if nobody added"
                       " anything and you don't recognize it."),
            what_to_do=("Open your router's app or admin page and look at"
                        " the connected-devices list. If every device there"
                        " is yours, you can ignore this."),
            ts=now,
)
        fired.append(mac)
    return fired


def check_arp_spoof(now=None):
    """Flag ARP weirdness over the last 30 minutes.

    ARP is how devices on your local network introduce themselves ("I'm"
    192.168.1.5, talk to this hardware address"). An attacker can lie in
    these introductions to intercept other devices' traffic -- called ARP
    spoofing. Two shapes worth flagging: one hardware address claiming 3+
    different IPs, and an IP address suddenly answering with a different
    hardware address than the one first recorded.
    """
    now = now or time.time()
    fired = []

    # shape 1: one MAC claiming several different IPs
    rows = dbm.query(
        "SELECT mac, COUNT(DISTINCT ip) FROM arp_observations"
        " WHERE ts >? GROUP BY mac HAVING COUNT(DISTINCT ip) >=?",
        (now - ARP_SPOOF_WINDOW, ARP_SPOOF_MIN_IPS))
    for mac, nip in rows:
        if not mac:
            continue
        ips = sorted(r[0] for r in dbm.query(
            "SELECT DISTINCT ip FROM arp_observations"
            " WHERE ts >? AND mac =?", (now - ARP_SPOOF_WINDOW, mac))
            if r[0])
        if dbm.recent_alert_kind("arp_spoof", mac, ARP_SPOOF_COOLDOWN):
            continue
        dbm.add_alert(
            "arp_spoof", "High",
            "Possible ARP spoofing",
            (f"Hardware address {mac} claimed {nip} different local"
             f" addresses in the last 30 minutes: {', '.join(ips)}."),
            meaning=("One device on your network is introducing itself as"
                     " several different devices at once. That is how an"
                     " attacker pretends to be other devices so their"
                     " traffic flows through the attacker's machine -- like"
                     " someone putting several neighbors' nameplates on"
                     " their own door to intercept their mail."),
            is_normal=("Sometimes fine: routers, hotspots, and virtual"
                       " machines can legitimately answer for more than one"
                       " address. It is not normal for an ordinary laptop or"
                       " phone to do this."),
            what_to_do=("Check your router's device list for the hardware"
                        " address above. If you don't recognize the device,"
                        " disconnect it from the network and change your"
                        " Wi-Fi password."),
            ts=now,
)
        fired.append(("mac", mac))

    # shape 2: an IP answering with a different MAC than first recorded
    rows = dbm.query(
        "SELECT DISTINCT ip FROM arp_observations WHERE ts >?",
        (now - ARP_SPOOF_WINDOW,))
    for (ip,) in rows:
        if not ip:
            continue
        macs = sorted(r[0] for r in dbm.query(
            "SELECT DISTINCT mac FROM arp_observations"
            " WHERE ts >? AND ip =?", (now - ARP_SPOOF_WINDOW, ip))
            if r[0])
        if not macs:
            continue
        first_mac = dbm.get_first_seen("ip_mac", ip)
        if first_mac is None:
            dbm.note_first_seen("ip_mac", ip, macs[0])
            continue
        if all(m == first_mac for m in macs):
            continue
        others = sorted(set(macs) - {first_mac})
        if dbm.recent_alert_kind("arp_spoof", ip, ARP_SPOOF_COOLDOWN):
            continue
        dbm.add_alert(
            "arp_spoof", "High",
            "Possible ARP spoofing",
            (f"{ip} used to answer as {first_mac} but is now also answering"
             f" as {', '.join(others)}."),
            meaning=("A local address that used to belong to one device is"
                     " now being claimed by a different device. That can"
                     " mean someone is pretending to be another device on"
                     " your network to intercept its traffic -- like someone"
                     " answering another person's phone."),
            is_normal=("Can also happen innocently when a device was"
                       " replaced, or when the router handed an old address"
                       " to a new device. It is suspicious when nothing"
                       " changed on your network."),
            what_to_do=("Check your router's device list and make sure you"
                        " recognize every device. If anything looks"
                        " unfamiliar, disconnect it and change your Wi-Fi"
                        " password."),
            ts=now,
)
        fired.append(("ip", ip))
    return fired


def check_behavior_deviation(now=None):
    """Fire when a device moves far more than its own learned baseline.

    Every device behaves differently -- the TV streams all evening, the
    printer never talks to the internet -- so network-wide thresholds cry
    wolf. The learned profile answers "what's normal for THIS device at
    this hour", and the rule stays silent otherwise. Quiet is a feature.
    """
    now = now or time.time()
    fired = []

    # Keep the profiles fresh without a cron: rebuild at most every 6h.
    if dbm.device_profiles_stale(now):
        dbm.build_device_profiles(now)

    hour = time.localtime(now).tm_hour
    ip2mac = dbm.ip_to_mac_map()
    mac_to_ips = {}
    for ip, mac in ip2mac.items():
        mac_to_ips.setdefault(mac, []).append(ip)
    names = dbm.device_name_map()

    for mac, ips in sorted(mac_to_ips.items()):
        profile = dbm.get_device_profile(mac, hour)
        if not profile or profile["days"] < BEHAVIOR_MIN_DAYS:
            continue
        # Brand-new devices are on probation watch; this rule watches
        # devices that have lived here long enough to have a "normal".
        first = dbm.device_first_seen(mac)
        if first and now - first < 24 * 3600:
            continue

        placeholders = ",".join("?" for _ in ips)
        row = dbm.query(
            f"SELECT COALESCE(SUM(bytes),0) FROM flows"
            f" WHERE ts > ? AND (src_ip IN ({placeholders})"
            f" OR dst_ip IN ({placeholders}))",
            (now - BEHAVIOR_WINDOW, *ips, *ips))[0]
        observed = row[0] or 0
        baseline = profile["avg_bytes"] or 0
        threshold = max(baseline * BEHAVIOR_FACTOR, BEHAVIOR_MIN_BYTES)
        if observed < threshold:
            continue
        if dbm.recent_alert_kind("behavior_deviation", mac,
                                 BEHAVIOR_COOLDOWN):
            continue

        name = names.get(mac, "")
        label = name or f"device {mac}"
        multiple = max(1, round(observed / max(baseline, 1)))
        dbm.add_alert(
            "behavior_deviation", "Medium",
            f"{label} moved far more than its usual",
            (f"In the last hour {label} ({mac}) moved {observed/1e6:.0f}"
             f" MB -- about {multiple}x what it usually moves at this hour"
             f" ({baseline/1e6:.1f} MB, learned over {profile['days']}"
             f" days)."),
            meaning=(f"One of your devices is moving far more data than it"
                     f" usually does at this time of day -- like a roommate"
                     f" who normally takes a ten-minute shower suddenly"
                     f" running the water for two hours. Something on that"
                     f" device is unusually busy, or the device itself may"
                     f" be doing something you didn't ask it to do."),
            is_normal=("Normal if the device was doing something big -- a"
                       f" game or OS update, a cloud backup, uploading"
                       f" video. It is not normal if nobody touched it"
                       f" and nothing was scheduled."),
            what_to_do=("Think about what was running on that device in the"
                        " last hour. If nothing explains it, check the"
                        " per-device traffic on the dashboard to see where"
                        " the data went, and consider naming the device if"
                        " you haven't."),
            ts=now,
        )
        fired.append(("behavior_deviation", mac))
    return fired


def run_all(now=None):
    """Run every periodic rule once. Called on a schedule by run.py.

    `now` anchors the analysis window -- wall-clock for live capture,
    newest-packet time for pcap analysis."""
    check_traffic_spike(now=now)
    check_unusual_ports(now=now)
    check_beaconing(now=now)
    check_baseline_anomalies(now=now)
    check_dns_anomalies(now=now)
    check_new_devices(now=now)
    check_arp_spoof(now=now)
    check_behavior_deviation(now=now)
