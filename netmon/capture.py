"""netmon/capture.py -- packets -> flow metadata (never packet contents).

Two input modes:
  live:  sniff this machine's interface with scapy (needs root: sudo)
  file:  read a .pcap (e.g. exported from Wireshark) -- great for testing
         and for "explain this capture" analysis.

Packets are rolled up into flows keyed by the 5-tuple
(src_ip, dst_ip, src_port, dst_port, proto) and flushed to SQLite every
FLUSH_INTERVAL seconds as (packets, bytes) counts per bucket.

Port-scan tracking happens inline: every TCP SYN is fed to a ScanTracker
with a sliding window; a burst of SYNs to many distinct ports from one
source raises an alert.
"""
import socket
import threading
import time

from . import db as dbm

try:
    from scapy.all import sniff, rdpcap, IP, IPv6, TCP, UDP
    HAVE_SCAPY = True
except ImportError:  # dashboard-only mode can run without scapy
    HAVE_SCAPY = False

FLUSH_INTERVAL = 15      # seconds between DB flushes
SCAN_WINDOW = 120        # seconds of SYN history kept per source
SCAN_PORT_THRESHOLD = 20  # distinct ports in window -> port scan alert
SCAN_COOLDOWN = 3600     # don't re-alert the same scanner for an hour


def get_local_ips():
    """IP addresses belonging to this machine (used for direction)."""
    ips = {"127.0.0.1", "::1"}
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))  # no traffic sent; just picks the route
        ips.add(s.getsockname()[0])
        s.close()
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            ip = info[4][0]
            if "." in ip:  # IPv4 only for the dashboard's purposes
                ips.add(ip)
    except Exception:
        pass
    return ips


class ScanTracker:
    """Sliding-window SYN-port tracker. One instance per capture run."""

    def __init__(self):
        self.history = {}  # src_ip -> list of (ts, dst_port)
        self.lock = threading.Lock()

    def observe(self, src_ip, dst_port, ts, is_syn):
        if not is_syn:
            return
        with self.lock:
            hist = self.history.setdefault(src_ip, [])
            hist.append((ts, dst_port))
            cutoff = ts - SCAN_WINDOW
            hist[:] = [(t, p) for t, p in hist if t >= cutoff]
            distinct_ports = {p for _, p in hist}
            if len(distinct_ports) >= SCAN_PORT_THRESHOLD:
                if not dbm.recent_alert_kind("port_scan", src_ip,
                                             SCAN_COOLDOWN):
                    dbm.add_alert(
                        "port_scan", "High",
                        f"Port scan from {src_ip}",
                        f"{src_ip} probed {len(distinct_ports)} distinct"
                        f" ports within {SCAN_WINDOW}s -- consistent with"
                        " an automated port scan.",
                        ts=ts,
                    )
                self.history[src_ip] = []  # reset after alerting


class FlowAggregator:
    """Accumulates per-packet metadata, flushes flow buckets to SQLite."""

    def __init__(self):
        self.local_ips = get_local_ips()
        self.flows = {}  # (src, dst, sport, dport, proto) -> [pkts, bytes, first, last]
        self.lock = threading.Lock()
        self.scans = ScanTracker()
        self.packets_seen = 0
        self.max_ts = 0  # newest packet timestamp seen (anchor for pcap mode)
        self.started_at = time.time()

    def _direction(self, src, dst):
        if src in self.local_ips:
            return "outbound"
        if dst in self.local_ips:
            return "inbound"
        return "local"

    def handle(self, pkt):
        """Process one scapy packet. Never touches payload bytes."""
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        src, dst = ip.src, ip.dst
        ts = float(getattr(pkt, "time", time.time()))
        proto, sport, dport, is_syn = "other", 0, 0, False
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            proto, sport, dport = "TCP", t.sport, t.dport
            is_syn = bool(t.flags & 0x02) and not bool(t.flags & 0x10)
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, sport, dport = "UDP", u.sport, u.dport
        try:
            size = len(pkt)
        except Exception:
            size = 0

        self.packets_seen += 1
        if ts > self.max_ts:
            self.max_ts = ts
        self.scans.observe(src, dport, ts, is_syn)

        key = (src, dst, sport, dport, proto)
        with self.lock:
            f = self.flows.get(key)
            if f is None:
                self.flows[key] = [1, size, ts, ts]
            else:
                f[0] += 1
                f[1] += size
                f[3] = ts

    def flush(self):
        """Write accumulated buckets to SQLite, reset counters.

        The bucket timestamp is the flow's last-seen packet time, not
        wall-clock time -- so pcap analysis keeps the capture's real
        timeline instead of flattening everything into "now"."""
        with self.lock:
            items = list(self.flows.items())
            self.flows = {}
        if not items:
            return 0
        rows = [
            (last, src, dst, sport, dport, proto, pkts, nbytes,
             self._direction(src, dst))
            for (src, dst, sport, dport, proto), (pkts, nbytes, _f, last)
            in items
        ]
        dbm.insert_flows(rows)
        return len(rows)


def _flush_loop(agg, stop_event):
    while not stop_event.wait(FLUSH_INTERVAL):
        try:
            agg.flush()
        except Exception:
            pass
    agg.flush()  # final flush on shutdown


def run_live(interface=None, stop_event=None):
    """Sniff live traffic until stop_event is set. Needs root."""
    if not HAVE_SCAPY:
        raise RuntimeError("scapy is not installed (pip install scapy)")
    agg = FlowAggregator()
    stop_event = stop_event or threading.Event()
    flusher = threading.Thread(target=_flush_loop, args=(agg, stop_event),
                               daemon=True)
    flusher.start()
    try:
        sniff(iface=interface, prn=agg.handle, store=False,
              stop_filter=lambda _p: stop_event.is_set())
    finally:
        stop_event.set()
        flusher.join(timeout=FLUSH_INTERVAL + 5)
    return agg


def run_pcap(path):
    """One-shot: process a pcap file, return (aggregator, alerts_raised)."""
    if not HAVE_SCAPY:
        raise RuntimeError("scapy is not installed (pip install scapy)")
    agg = FlowAggregator()
    for pkt in rdpcap(path):
        agg.handle(pkt)
    agg.flush()
    return agg
