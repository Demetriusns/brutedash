"""netmon/detect.py -- periodic detection rules over stored flows.

The live port-scan check runs inline in capture.py (it needs per-packet
SYN timing). Everything here runs on a schedule against the flows table:

  traffic_spike   this 5-minute bucket moved far more bytes than usual
  unusual_port    outbound traffic to a port outside the common set
  beaconing       steady, clockwork check-ins with one outside address

Every alert carries plain-English fields (meaning / is_this_normal /
what_to_do) so a non-technical reader can understand it. Each rule
checks the alerts table first so it only fires once per cooldown window
instead of spamming.
"""
import time

from . import db as dbm

# Ports a normal home machine talks to every day. Anything outbound to a
# port NOT on this list is worth a second look (not proof of evil -- game
# servers, dev tools, and VoIP apps all use odd ports).
COMMON_PORTS = {
    80, 443,                      # web
    53,                           # DNS
    123,                          # NTP time sync
    22,                           # SSH
    25, 465, 587, 993, 995,       # email
    67, 68,                       # DHCP
    1900, 5353,                   # local discovery (SSDP/mDNS)
    3478, 3479, 3480,             # STUN / video calls
    5222, 5223,                   # chat push notifications
}

SPIKE_WINDOW = 300        # compare the last 5 minutes ...
SPIKE_BASELINE = 3600     # ... against the previous hour
SPIKE_FACTOR = 5.0        # alert when recent >= 5x the hourly average
SPIKE_COOLDOWN = 1800
PORT_COOLDOWN = 3600

BEACON_WINDOW = 3600      # look back one hour, in 5-minute buckets
BEACON_BUCKET = 300
BEACON_MIN_BUCKETS = 8    # active in at least 8 of 12 buckets
BEACON_COOLDOWN = 3600


def check_traffic_spike(now=None):
    """Alert when recent throughput dwarfs the recent baseline."""
    now = now or time.time()
    recent = dbm.query(
        "SELECT COALESCE(SUM(bytes),0) FROM flows WHERE ts > ?",
        (now - SPIKE_WINDOW,))
    base = dbm.query(
        "SELECT COALESCE(SUM(bytes),0) FROM flows"
        " WHERE ts > ? AND ts <= ?",
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
    dbm.add_alert(
        "traffic_spike", "Medium",
        "Unusual surge in network traffic", detail,
        meaning=("This machine suddenly sent or received far more data than"
                 " usual -- like a water bill jumping 5x in one month."
                 " Something moved a lot of data in a short time."),
        is_normal=("This is normal if someone was downloading a large file,"
                   " backing up photos, updating a game, or on a long video"
                   " call. It is not normal if nobody was using the computer."),
        what_to_do=("Think about what was running in the last few minutes."
                    " If nothing explains it, open Task Manager (Windows) or"
                    " Activity Monitor (Mac) and check which app used the"
                    " network most."),
        ts=now)
    return detail


def check_unusual_ports(now=None):
    """Flag outbound flows to ports outside the common set."""
    now = now or time.time()
    rows = dbm.query(
        "SELECT DISTINCT dst_ip, dst_port, SUM(bytes) FROM flows"
        " WHERE ts > ? AND direction='outbound' AND proto IN ('TCP','UDP')"
        " GROUP BY dst_ip, dst_port",
        (now - 900,))
    fired = []
    for dst_ip, dst_port, nbytes in rows:
        if dst_port in COMMON_PORTS:
            continue
        key = f"{dst_ip}:{dst_port}"
        if dbm.recent_alert_kind("unusual_port", key, PORT_COOLDOWN):
            continue
        mb = (nbytes or 0) / 1e6
        dbm.add_alert(
            "unusual_port", "Medium",
            f"Talking on an unusual channel (port {dst_port})",
            f"Outbound traffic to {dst_ip} on port {dst_port}"
            f" ({mb:.2f} MB in the last 15 min).",
            meaning=("Your computer talked to the outside world on a channel"
                     " (called a 'port') that everyday apps don't use. Think"
                     " of ports like TV channels -- most apps use the popular"
                     " ones, and this one used an obscure channel."),
            is_normal=("Often fine: games, work VPNs, video-chat apps, and"
                       " developer tools all use unusual ports. It only"
                       " matters if you don't recognize the program doing it."),
            what_to_do=("Match the time to what you were doing. Gaming or on"
                        " a work call? Expected. Otherwise, search the web"
                        " for 'port {0}' to see what normally uses it."
                        .format(dst_port)),
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
        "SELECT dst_ip, CAST(ts / ? AS INTEGER) AS bkt, SUM(bytes)"
        " FROM flows WHERE ts > ? AND direction='outbound'"
        " AND proto IN ('TCP','UDP')"
        " GROUP BY dst_ip, bkt",
        (BEACON_BUCKET, now - BEACON_WINDOW))
    per_ip = {}
    for dst_ip, bkt, nbytes in rows:
        d = per_ip.setdefault(dst_ip, {"buckets": set(), "bytes": 0})
        d["buckets"].add(bkt)
        d["bytes"] += nbytes or 0
    fired = []
    for dst_ip, d in per_ip.items():
        buckets = sorted(d["buckets"])
        if len(buckets) < BEACON_MIN_BUCKETS:
            continue
        span_min = (buckets[-1] - buckets[0]) * (BEACON_BUCKET / 60)
        avg_every = span_min / max(len(buckets) - 1, 1)
        if dbm.recent_alert_kind("beaconing", dst_ip, BEACON_COOLDOWN):
            continue
        mb = d["bytes"] / 1e6
        dbm.add_alert(
            "beaconing", "Medium",
            f"Repeated check-ins with {dst_ip}",
            (f"Contacted {dst_ip} in {len(buckets)} of the last"
             f" {BEACON_WINDOW // 60} minutes -- roughly every"
             f" {avg_every:.0f} minutes ({mb:.2f} MB total)."),
            meaning=("Your computer contacted the same outside address on a"
                     " steady schedule, like clockwork. Some of this is"
                     " routine -- apps checking for updates or new messages"
                     " -- but malware also 'phones home' this way, so a"
                     " regular heartbeat to an unknown address is worth a"
                     " look."),
            is_normal=("Normal if the address belongs to a service you use"
                       " (email, chat, cloud backup, antivirus). Suspicious"
                       " if you don't recognize the address, especially when"
                       " each check-in moves only a tiny amount of data."),
            what_to_do=("Search the web for the address to see who owns it."
                        " If it's a service you use, you can ignore this. If"
                        " not, note when it started and consider running an"
                        " antivirus scan."),
            ts=now,
        )
        fired.append(dst_ip)
    return fired


def run_all(now=None):
    """Run every periodic rule once. Called on a schedule by run.py.

    `now` anchors the analysis window -- wall-clock for live capture,
    newest-packet time for pcap analysis."""
    check_traffic_spike(now=now)
    check_unusual_ports(now=now)
    check_beaconing(now=now)
