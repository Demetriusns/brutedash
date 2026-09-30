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
    from scapy.all import sniff, rdpcap, IP, IPv6, TCP, UDP, DNS, Ether
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
                        f"Possible port scan from {src_ip}",
                        f"{src_ip} tried {len(distinct_ports)} different"
                        f" ports within {SCAN_WINDOW} seconds.",
                        meaning=("Another computer rapidly knocked on many"
                                 " different 'doors' (ports) of this machine"
                                 " -- like someone walking down a hallway"
                                 " trying every doorknob. That's how"
                                 " attackers look for a way in."),
                        is_normal=("On a home network this is rarely normal."
                                   " It can occasionally be your router or a"
                                   " security tool doing a health check, but"
                                   " treat it as suspicious until you know"
                                   " which device it was."),
                        what_to_do=("Find the device behind that address"
                                    " (your router's device list shows"
                                    " what's connected). If you don't"
                                    " recognize it, block it there and"
                                    " change your Wi-Fi password."),
                        ts=ts,
                    )
                self.history[src_ip] = []  # reset after alerting


class FlowAggregator:
    """Accumulates per-packet metadata, flushes flow buckets to SQLite.

    Also buffers observed DNS queries (UDP/53 with a DNS question) and
    IP/MAC observations (from the Ethernet header), which are written to
    the dns_queries and arp_observations tables on flush()."""

    def __init__(self):
        self.local_ips = get_local_ips()
        self.flows = {}  # (src, dst, sport, dport, proto) -> [pkts, bytes, first, last]
        self.dns_buf = []   # [(ts, name, qtype)]
        self.arp_buf = []   # [(ts, ip, mac)]
        self._mac_seen = set()  # (ip, mac) already buffered this run
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

    def _dns_query_row(self, pkt, ts):
        """Return a (ts, name, qtype) row for a DNS question, or None.

        Only called for UDP packets headed to port 53, so ordinary
        traffic never pays for DNS parsing.
        """
        try:
            dns = pkt.getlayer(DNS)
            if dns is None or getattr(dns, "qr", 1) != 0:
                return None  # not a query (response or no DNS layer)
            qd = getattr(dns, "qd", None)
            if qd is None:
                return None
            name = qd.qname
            if isinstance(name, bytes):
                name = name.decode("utf-8", "replace")
            name = str(name).rstrip(".")
            qtype = qd.qtype
            try:
                qtype = int(qtype)
            except (TypeError, ValueError):
                qtype = str(qtype)
            return (ts, name, qtype)
        except Exception:
            return None

    def handle(self, pkt):
        """Process one scapy packet. Never touches payload bytes."""
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        src, dst = ip.src, ip.dst
        ts = float(getattr(pkt, "time", time.time()))
        proto, sport, dport, is_syn = "other", 0, 0, False
        dns_row = None
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            proto, sport, dport = "TCP", t.sport, t.dport
            is_syn = bool(t.flags & 0x02) and not bool(t.flags & 0x10)
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, sport, dport = "UDP", u.sport, u.dport
            if u.dport == 53 and pkt.haslayer(DNS):
                dns_row = self._dns_query_row(pkt, ts)
        try:
            size = len(pkt)
        except Exception:
            size = 0

        eth = pkt.getlayer(Ether)
        mac = eth.src if eth is not None else None

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
            if dns_row is not None:
                self.dns_buf.append(dns_row)
            if mac is not None:
                pair = (src, mac)
                if pair not in self._mac_seen:
                    self._mac_seen.add(pair)
                    if len(self._mac_seen) > 5000:
                        # Bound memory on busy networks; already-buffered
                        # pairs will simply be recorded again.
                        self._mac_seen = {pair}
                    self.arp_buf.append((ts, src, mac))

    def flush(self):
        """Write accumulated buckets to SQLite, reset counters.

        The bucket timestamp is the flow's last-seen packet time, not
        wall-clock time -- so pcap analysis keeps the capture's real
        timeline instead of flattening everything into "now".

        DNS-query and IP/MAC observation buffers flush even when no flow
        rows exist; the last_flow_ts heartbeat is only written when at
        least one flow row was stored."""
        with self.lock:
            items = list(self.flows.items())
            self.flows = {}
            dns_rows = self.dns_buf
            self.dns_buf = []
            arp_rows = self.arp_buf
            self.arp_buf = []
        if dns_rows:
            dbm.insert_dns_queries(dns_rows)
        if arp_rows:
            dbm.insert_arp_observations(arp_rows)
        if not items:
            return 0
        rows = [
            (last, src, dst, sport, dport, proto, pkts, nbytes,
             self._direction(src, dst))
            for (src, dst, sport, dport, proto), (pkts, nbytes, _f, last)
            in items
        ]
        dbm.insert_flows(rows)
        dbm.set_meta("last_flow_ts", str(time.time()))
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
