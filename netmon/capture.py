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

Whole-network mode: set NETMON_WHOLE_NETWORK=1 when this machine is
relaying the LAN (e.g. via bettercap ARP spoofing, see netmon/wifimon.cap).
Traffic between other LAN devices and the internet is then classified as
outbound/inbound instead of local, so every detection rule analyzes every
device -- not just this machine. NETMON_LAN_SUBNET overrides the detected
LAN subnet (default: the /24 containing this machine's primary IP).
"""
import ipaddress
import os
import socket
import threading
import time

from . import db as dbm

try:
    from scapy.all import sniff, rdpcap, IP, IPv6, TCP, UDP, DNS, Ether
    HAVE_SCAPY = True
except ImportError:  # dashboard-only mode can run without scapy
    HAVE_SCAPY = False

try:
    from scapy.all import DHCP, BOOTP  # DHCP hostname (option 12)
    HAVE_DHCP = True
except ImportError:
    HAVE_DHCP = False

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


def whole_network_mode():
    """True when this machine relays the LAN (see module docstring)."""
    from . import config as cfgm
    return cfgm.whole_network_enabled()


def lan_subnet():
    """The LAN subnet for whole-network mode.

    NETMON_LAN_SUBNET overrides; otherwise the /24 containing this
    machine's primary IPv4 address. Returns an ipaddress network or
    None if it cannot be determined.
    """
    override = os.environ.get("NETMON_LAN_SUBNET", "").strip()
    if override:
        try:
            return ipaddress.ip_network(override, strict=False)
        except ValueError:
            pass
    for ip in get_local_ips():
        if "." not in ip or ip.startswith("127."):
            continue
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            continue
    return None


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
    the dns_queries and arp_observations tables on flush(). It also buffers
    hostname observations (DHCP option 12, mDNS .local names) and per-IP
    TTL sightings (OS guess via TTL heuristics) for the asset inventory."""

    def __init__(self):
        self.local_ips = get_local_ips()
        self.whole_network = whole_network_mode()
        self.lan = lan_subnet() if self.whole_network else None
        self.flows = {}  # (src, dst, sport, dport, proto) -> [pkts, bytes, first, last]
        self.dns_buf = []   # [(ts, src_ip, name, qtype)]
        self.arp_buf = []   # [(ts, ip, mac)]
        self.hostname_buf = []  # [(ts, mac, ip, hostname, source)]
        self.ttl_map = {}   # ip -> (ttl, ts); bounded below
        self.gateway_ip = None  # default gateway from DHCP option 3
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
        if self.whole_network and self.lan is not None:
            # Another LAN device talking to the internet: treat it like
            # this machine's own traffic so every rule analyzes it.
            try:
                s_in = ipaddress.ip_address(src) in self.lan
                d_in = ipaddress.ip_address(dst) in self.lan
            except ValueError:
                s_in = d_in = False
            if s_in and not d_in:
                return "outbound"
            if d_in and not s_in:
                return "inbound"
        return "local"

    def _dns_query_row(self, pkt, ts, src):
        """Return a (ts, src_ip, name, qtype) row for a DNS question, or None.

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
            return (ts, src, name, qtype)
        except Exception:
            return None

            return (ts, src, name, qtype)
        except Exception:
            return None

    def _dhcp_hostname_row(self, pkt, ts, src, eth_mac):
        """Return a (ts, mac, ip, hostname, "dhcp") row, or None.

        DHCP clients announce their hostname in option 12; the client's
        hardware address comes from the BOOTP chaddr field (the IP header
        is often 0.0.0.0 at this point, so the MAC is the useful key).
        """
        if not HAVE_DHCP:
            return None
        try:
            if not pkt.haslayer(DHCP):
                return None
            dhcp = pkt.getlayer(DHCP)
            hostname = None
            for opt in (getattr(dhcp, "options", None) or []):
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                key = opt[0]
                if key == "hostname" or key == 12:
                    hostname = opt[1]
                    break
            if not hostname:
                return None
            if isinstance(hostname, bytes):
                hostname = hostname.decode("utf-8", "replace")
            hostname = str(hostname).strip().strip("\x00")
            if not hostname:
                return None
            mac = eth_mac or ""
            try:
                bootp = pkt.getlayer(BOOTP)
                chaddr = getattr(bootp, "chaddr", b"")
                if chaddr and len(chaddr) >= 6:
                    mac = ":".join(f"{b:02x}" for b in chaddr[:6])
            except Exception:
                pass
            return (ts, (mac or "").lower(), src, hostname, "dhcp")
        except Exception:
            return None

    def _dhcp_router_ip(self, pkt):
        """Default gateway from DHCP option 3 (router), or None.

        DHCP OFFER/ACK packets from the LAN's DHCP server carry the
        router option -- that's the gateway every device routes through.
        Stored to meta on flush; the topology map uses it, falling back
        to the most-connected LAN node when no DHCP was observed.
        """
        if not HAVE_DHCP:
            return None
        try:
            if not pkt.haslayer(DHCP):
                return None
            dhcp = pkt.getlayer(DHCP)
            for opt in (getattr(dhcp, "options", None) or []):
                if not isinstance(opt, tuple) or len(opt) < 2:
                    continue
                if opt[0] == "router" or opt[0] == 3:
                    val = opt[1]
                    if isinstance(val, (list, tuple)):
                        val = val[0] if val else None
                    if isinstance(val, bytes):
                        try:
                            val = val.decode("ascii", "replace")
                        except Exception:
                            return None
                    val = str(val).strip() if val else ""
                    # sanity: dotted quad, not 0.0.0.0
                    parts = val.split(".")
                    if (len(parts) == 4
                            and all(p.isdigit() and 0 <= int(p) <= 255
                                    for p in parts)
                            and val != "0.0.0.0"):
                        return val
        except Exception:
            pass
        return None

    def _mdns_hostname_rows(self, pkt, ts, src, eth_mac):
        """mDNS (.local) name sightings -> [(ts, mac, ip, name, "mdns")].

        Devices announce themselves on UDP/5353 ("myprinter.local").
        Service names (_http._tcp.local) are skipped; only plain host
        labels are kept.
        """
        rows = []
        try:
            dns = pkt.getlayer(DNS)
            if dns is None:
                return rows
            candidates = []
            qd = getattr(dns, "qd", None)
            if qd is not None and getattr(qd, "qname", None):
                candidates.append(qd.qname)
            try:
                ancount = int(getattr(dns, "ancount", 0) or 0)
            except (TypeError, ValueError):
                ancount = 0
            for i in range(min(ancount, 10)):
                try:
                    rr = dns.an[i]
                    if getattr(rr, "rrname", None):
                        candidates.append(rr.rrname)
                except Exception:
                    break
            seen = set()
            for raw in candidates:
                name = raw.decode("utf-8", "replace") if isinstance(
                    raw, bytes) else str(raw)
                name = name.strip().rstrip(".").lower()
                if not name.endswith(".local"):
                    continue
                first = name[:-len(".local")].split(".")[0]
                if not first or first.startswith("_") or first in seen:
                    continue
                seen.add(first)
                rows.append((ts, (eth_mac or "").lower(), src, first,
                             "mdns"))
        except Exception:
            pass
        return rows

    def handle(self, pkt):
        """Process one scapy packet. Never touches payload bytes."""
        ip = pkt.getlayer(IP) or pkt.getlayer(IPv6)
        if ip is None:
            return
        src, dst = ip.src, ip.dst
        ts = float(getattr(pkt, "time", time.time()))
        proto, sport, dport, is_syn = "other", 0, 0, False
        dns_row = None
        dhcp_row = None
        dhcp_gateway = None
        mdns_rows = []
        if pkt.haslayer(TCP):
            t = pkt[TCP]
            proto, sport, dport = "TCP", t.sport, t.dport
            is_syn = bool(t.flags & 0x02) and not bool(t.flags & 0x10)
        elif pkt.haslayer(UDP):
            u = pkt[UDP]
            proto, sport, dport = "UDP", u.sport, u.dport
            if u.dport == 53 and pkt.haslayer(DNS):
                dns_row = self._dns_query_row(pkt, ts, src)
        try:
            size = len(pkt)
        except Exception:
            size = 0

        eth = pkt.getlayer(Ether)
        mac = eth.src if eth is not None else None

        # TTL sighting for the OS guess (asset inventory). Bounded: busy
        # networks see thousands of IPs; keep the freshest 2048.
        try:
            ttl = getattr(ip, "ttl", None)
            if ttl is None:
                ttl = getattr(ip, "hlim", None)  # IPv6
            if ttl:
                if len(self.ttl_map) >= 2048 and src not in self.ttl_map:
                    self.ttl_map.pop(next(iter(self.ttl_map)))
                self.ttl_map[src] = (int(ttl), ts)
        except Exception:
            pass

        # DHCP hostnames (UDP 67/68) and mDNS .local names (UDP 5353).
        # Bounded like the ARP buffer: already-seen names re-record later.
        if pkt.haslayer(UDP):
            try:
                u = pkt[UDP]
                if u.dport in (67, 68) or u.sport in (67, 68):
                    dhcp_row = self._dhcp_hostname_row(pkt, ts, src, mac)
                    dhcp_gateway = self._dhcp_router_ip(pkt)
                if u.dport == 5353 and pkt.haslayer(DNS):
                    mdns_rows = self._mdns_hostname_rows(pkt, ts, src, mac)
            except Exception:
                pass

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
            if dhcp_gateway:
                self.gateway_ip = dhcp_gateway  # latest wins; DHCP is chatty
            if dhcp_row is not None and len(self.hostname_buf) < 1000:
                self.hostname_buf.append(dhcp_row)
            if mdns_rows and len(self.hostname_buf) < 1000:
                room = 1000 - len(self.hostname_buf)
                self.hostname_buf.extend(mdns_rows[:room])
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
            hostname_rows = self.hostname_buf
            self.hostname_buf = []
            ttl_rows = [(ip, ttl, ts) for ip, (ttl, ts) in self.ttl_map.items()]
            self.ttl_map = {}
            gateway_ip = self.gateway_ip
        if dns_rows:
            dbm.insert_dns_queries(dns_rows)
        if gateway_ip:
            # Default gateway seen in DHCP -- the topology map reads this.
            dbm.set_meta("dhcp_gateway_ip", gateway_ip)
        if arp_rows:
            dbm.insert_arp_observations(arp_rows)
        if hostname_rows:
            dbm.insert_hostname_observations(hostname_rows)
        if ttl_rows:
            dbm.record_ttls(ttl_rows)
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
