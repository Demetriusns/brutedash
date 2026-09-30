"""netmon/detect.py -- periodic detection rules over stored flows.

The live port-scan check runs inline in capture.py (it needs per-packet
SYN timing). Everything here runs on a schedule against the flows table:

  traffic_spike   this 5-minute bucket moved far more bytes than usual
  unusual_port    outbound traffic to a port outside the common set

Each rule checks the alerts table first so it only fires once per
cooldown window instead of spamming.
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
              " hour -- possible large upload/download, backup, or"
              " exfiltration worth checking.")
    dbm.add_alert("traffic_spike", "Medium",
                  "Unusual traffic spike", detail, ts=now)
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
            f"Unusual outbound port: {dst_port}",
            f"Outbound traffic to {dst_ip} on port {dst_port}"
            f" ({mb:.2f} MB in the last 15 min). Not a standard web/DNS/"
            "email port -- could be a game, dev tool, VPN, or something"
            " worth identifying.",
            ts=now,
        )
        fired.append(key)
    return fired


def run_all(now=None):
    """Run every periodic rule once. Called on a schedule by run.py.

    `now` anchors the analysis window -- wall-clock for live capture,
    newest-packet time for pcap analysis."""
    check_traffic_spike(now=now)
    check_unusual_ports(now=now)
