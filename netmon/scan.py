"""netmon/scan.py -- self vulnerability scan of our OWN LAN only.

The analyst auditing, not just watching: a weekly (or on-demand) TCP
connect scan of common ports on every discovered LAN device, mapped to a
local risk knowledge base with plain-English explanations.

Safety is the whole design:
  * every target is validated as RFC1918/loopback before a single packet
    is sent -- anything else aborts the run (refuse, don't warn);
  * bounded: <=64 devices, <=32 ports, 0.8s connect timeout, 16 workers;
  * alerts fire only for NEW or changed findings, so a quiet weekly scan
    stays quiet (quiet is a feature);
  * findings are Low/Medium and informational -- they never trigger email
    (only High/Critical do) and never block anything.

Run it: scan.run_scan() (manual) or scan.maybe_weekly_scan() (the
scheduled entry point called from run.py's monitor loop).
"""

import ipaddress
import socket
import threading
import time


# One scan at a time. The meta flag (vuln_scan_running) is visible to the
# dashboard, but the real guard is this in-process lock: check-then-set on
# a DB value is racy (two rapid /api/scan/run POSTs could both see "0"
# and launch two scans).
_SCAN_GUARD = threading.Lock()
_scan_in_flight = False


def scan_already_running():
    """True if a scan is currently in flight (atomic)."""
    with _SCAN_GUARD:
        return _scan_in_flight


def _claim_scan():
    global _scan_in_flight
    with _SCAN_GUARD:
        if _scan_in_flight:
            return False
        _scan_in_flight = True
        return True


def _release_scan():
    global _scan_in_flight
    with _SCAN_GUARD:
        _scan_in_flight = False

from . import db as dbm

# Ports worth knocking on. service = what normally lives there.
SCAN_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"),
    (53, "DNS"), (67, "DHCP server"), (80, "HTTP"), (110, "POP3"),
    (135, "Windows RPC"), (139, "NetBIOS/SMB"), (143, "IMAP"),
    (443, "HTTPS"), (445, "SMB file sharing"), (554, "RTSP camera"),
    (1433, "MS SQL Server"), (1521, "Oracle DB"), (1723, "PPTP VPN"),
    (1900, "UPnP/SSDP"), (3306, "MySQL"), (3389, "Remote Desktop"),
    (5353, "mDNS"), (5432, "PostgreSQL"), (5678, "MikroTik"),
    (5900, "VNC remote desktop"), (6379, "Redis"), (8080, "HTTP alt"),
    (8443, "HTTPS alt"), (8888, "HTTP alt"), (9000, "SonarQube/PHP"),
    (9100, "Printer (JetDirect)"), (27017, "MongoDB"),
]

# port -> (risk, plain-English explanation). Only Low/Medium: a home
# scanner reports hygiene issues, not emergencies.
RISK_KB = {
    21: ("Medium", "FTP sends logins and files with no encryption -- anyone on the network can read them."),
    22: ("Low", "SSH is the normal, encrypted way to log into a device remotely. Expected on servers and routers."),
    23: ("Medium", "Telnet sends logins in plain text -- anyone on the network can read the password. This protocol is obsolete; it should be off."),
    25: ("Low", "SMTP is the mail-sending port. Normal on a mail server, unexpected on a home device."),
    53: ("Low", "DNS answers 'what's the address of this website?' questions. Normal on routers."),
    67: ("Low", "This device hands out network addresses (DHCP) -- usually your router doing its job."),
    80: ("Low", "An unencrypted web page is served here. Common on routers, cameras, and smart-home hubs (their admin pages)."),
    110: ("Medium", "POP3 email with no encryption -- logins travel in plain text."),
    135: ("Medium", "Windows RPC: a core Windows service port. It has a long history of worms exploiting it; it should never be reachable from outside your home."),
    139: ("Medium", "NetBIOS file/printer sharing from the old Windows networking days. Fine inside the home, a risk if it ever faces the internet."),
    143: ("Medium", "IMAP email with no encryption -- logins travel in plain text."),
    443: ("Low", "An encrypted web page is served here -- the normal way admin pages should work."),
    445: ("Medium", "SMB file sharing: how Windows shares files and printers. Ransomware like WannaCry spread through this port -- keep it off the internet."),
    554: ("Medium", "RTSP streams video -- usually a security camera. Camera feeds should be password-protected."),
    1433: ("Medium", "Microsoft SQL Server database. Databases should never be reachable from the internet."),
    1521: ("Medium", "Oracle database. Databases should never be reachable from the internet."),
    1723: ("Medium", "PPTP VPN -- an old VPN type with known weaknesses. Fine inside the home; avoid exposing it."),
    1900: ("Medium", "UPnP lets devices open ports on your router automatically -- convenient, and a classic way malware punches holes in the firewall."),
    3306: ("Medium", "MySQL/MariaDB database. Databases should never be reachable from the internet."),
    3389: ("Medium", "Remote Desktop: full remote control of a Windows machine. Attackers constantly guess passwords on this port -- keep it off the internet."),
    5353: ("Low", "mDNS: how Apple/Google devices find each other on the local network ('printer._tcp.local'). Normal chatter."),
    5432: ("Medium", "PostgreSQL database. Databases should never be reachable from the internet."),
    5678: ("Medium", "MikroTik router management port. Router admin ports should never face the internet."),
    5900: ("Medium", "VNC remote desktop -- screen sharing that is often unencrypted and password-guessed from the internet."),
    6379: ("Medium", "Redis database, which famously ships with no password by default. A classic internet-exposure mistake."),
    8080: ("Low", "An alternate web port -- often a router, camera, or app admin page."),
    8443: ("Low", "An alternate encrypted web port -- often a router or app admin page."),
    8888: ("Low", "An alternate web port -- check what app is serving it."),
    9000: ("Low", "An alternate web port -- check what app is serving it."),
    9100: ("Low", "Raw printer port (JetDirect). Normal on a network printer."),
    27017: ("Medium", "MongoDB database. Databases should never be reachable from the internet."),
}

MAX_DEVICES = 64
CONNECT_TIMEOUT = 0.8
MAX_WORKERS = 16
WEEK_SECONDS = 7 * 86400


def _ok_target(ip):
    """True only for LAN/loopback addresses. Anything else is refused.

    Uses explicit RFC1918 ranges (not ipaddress.is_private: Python 3.13+
    counts documentation/test ranges as "private", and those must never
    be scanned).
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    try:
        packed = addr.packed
    except Exception:
        return False
    if len(packed) != 4:
        return False  # IPv6 LAN scanning is out of scope for this check
    a, b = packed[0], packed[1]
    return (a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


def scan_targets():
    """LAN IPs to scan: observed devices + this box's own LAN addresses,
    all validated private/loopback. Own IPs are included (auditing the
    box itself is fine); non-LAN addresses are silently dropped."""
    targets = set()
    try:
        for ip in dbm.ip_to_mac_map():
            if _ok_target(ip):
                targets.add(ip)
    except Exception:
        pass
    try:
        from .capture import get_local_ips
        for ip in get_local_ips():
            if _ok_target(ip):
                targets.add(ip)
    except Exception:
        pass
    return sorted(targets)[:MAX_DEVICES]


def scan_device(ip, ports=None, timeout=CONNECT_TIMEOUT):
    """TCP connect scan of `ports` on one IP. Returns the open port set.

    Never raises; never scans non-LAN targets (returns empty)."""
    if not _ok_target(ip):
        return set()
    ports = ports or [p for p, _ in SCAN_PORTS]
    open_ports = set()
    for port in ports[:32]:
        try:
            port = int(port)
            if not 1 <= port <= 65535:
                continue
        except (TypeError, ValueError):
            continue
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                open_ports.add(port)
        except Exception:
            pass
    return open_ports


def run_scan(ports=None, timeout=CONNECT_TIMEOUT, progress=None):
    """Scan every LAN target. Returns {ip: set(open ports)}.

    Bounded and LAN-only by construction. `progress` is an optional
    callable(done, total) for the dashboard's running indicator.
    """
    targets = scan_targets()
    if not targets:
        return {}
    results = {}
    lock = threading.Lock()
    done = [0]

    def _one(ip):
        found = scan_device(ip, ports=ports, timeout=timeout)
        with lock:
            results[ip] = found
            done[0] += 1
            if progress:
                try:
                    progress(done[0], len(targets))
                except Exception:
                    pass

    workers = min(MAX_WORKERS, len(targets))
    threads = []
    queue = list(targets)

    def _worker():
        while True:
            with lock:
                if not queue:
                    return
                ip = queue.pop(0)
            _one(ip)

    for _ in range(workers):
        t = threading.Thread(target=_worker, daemon=True)
        t.start()
        threads.append(t)
    for t in threads:
        t.join()
    return results


def _risk_for(port):
    entry = RISK_KB.get(port)
    if entry:
        return entry
    return ("Low", "An uncommon port is open here. Check what app uses it.")


def findings_from_results(results, ip2mac):
    """Build (ip, mac, port, service, risk, what) finding tuples."""
    services = dict(SCAN_PORTS)
    out = []
    for ip in sorted(results):
        mac = ip2mac.get(ip, "")
        for port in sorted(results[ip]):
            risk, what = _risk_for(port)
            out.append((ip, mac, port, services.get(port, "unknown"),
                        risk, what))
    return out


def alert_new_findings(new, changed, ip2mac, names, ts=None):
    """Alert on genuinely new (or risk-changed) open doors only.

    One alert per device listing its new doors -- quieter than one per
    port, and a repeat weekly scan with no changes stays completely
    silent. Severity is the highest risk among the doors (Low/Medium).
    """
    ts = ts if ts is not None else time.time()
    by_ip = {}
    for ip, port in list(new) + list(changed):
        by_ip.setdefault(ip, []).append(port)
    for ip in sorted(by_ip):
        label = names.get(ip2mac.get(ip, ""), "") or f"device {ip}"
        doors = []
        worst = "Low"
        for port in sorted(by_ip[ip]):
            risk, what = _risk_for(port)
            if risk == "Medium":
                worst = "Medium"
            services = dict(SCAN_PORTS)
            doors.append(f"port {port} ({services.get(port, 'unknown')})"
                         f" -- {what}")
        dbm.add_alert(
            "vuln_finding", worst,
            f"Open doors on your network: {label}",
            (f"The weekly self-check found open doors on {label} ({ip}):"
             f" {'; '.join(doors)}."),
            meaning=("An 'open door' (open port) is a way into a device"
                     " over the network -- like an unlocked window. This"
                     " scan knocked on your own devices' doors the way an"
                     " attacker would, so you see what they would see."),
            is_normal=("Many open doors are normal -- your router serves"
                       " admin pages, printers listen for print jobs. It"
                       " matters when a door is open that shouldn't be:"
                       " remote-access or database ports on devices that"
                       " don't need them."),
            what_to_do=("Look at the list above. If a door surprises you,"
                        " open that device's settings and turn the service"
                        " off, or make sure it needs a strong password."),
            ts=ts,
        )


def _scan_enabled():
    """Weekly scan on? Config `scan.weekly`, default True."""
    try:
        from . import config as cfgm
        return bool(cfgm.get(cfgm.load_cached(), "scan.weekly", True))
    except Exception:
        return True


def run_full_scan(note="scheduled"):
    """One full pass: scan, store, alert on new/changed findings.

    Returns a summary dict. Never raises -- a failed scan is a missed
    scan, not a crash (the next weekly run retries).
    """
    import time as _t
    if not _claim_scan():
        return {"ok": False, "error": "a scan is already running"}
    started = _t.time()
    try:
        dbm.set_meta("vuln_scan_running", "1")
        ip2mac = dbm.ip_to_mac_map()
        results = run_scan()
        findings = findings_from_results(results, ip2mac)
        new, resolved, changed = dbm.record_scan_findings(started, findings)
        run_id = dbm.record_scan_run(
            started, _t.time() - started, len(results), len(findings),
            note=note)
        if new or changed:
            try:
                names = dbm.device_name_map()
                alert_new_findings(new, changed, ip2mac, names, ts=started)
            except Exception:
                pass  # alerting is a bonus; the findings are stored
        dbm.set_meta("vuln_scan_last_ts", str(started))
        return {"ok": True, "run_id": run_id,
                "devices": len(results), "findings": len(findings),
                "new": len(new), "resolved": len(resolved),
                "changed": len(changed),
                "duration_s": round(_t.time() - started, 1)}
    except Exception as exc:
        try:
            dbm.set_meta("vuln_scan_error", str(exc)[:200])
        except Exception:
            pass
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        _release_scan()
        try:
            dbm.set_meta("vuln_scan_running", "0")
        except Exception:
            pass


def start_scan_async(note="manual"):
    """Start a scan in a background thread. Always launches the thread;
    the worker claims the single-scan slot atomically inside
    run_full_scan, so a second rapid call finds the first scan already
    in flight and declines."""
    threading.Thread(target=run_full_scan, kwargs={"note": note},
                     daemon=True).start()
    return True


def maybe_weekly_scan():
    """Launch the scan in the background if it's due (>7 days) and enabled.

    Called from the monitor loop; returns True when a scan was launched,
    False/None otherwise. The scan itself runs on a worker thread so a
    ~2-minute scan never stalls detection ticks -- the scan records its
    own run row and the dashboard polls /api/scan for status.
    """
    if not _scan_enabled():
        return None
    raw = dbm.get_meta("vuln_scan_last_ts")
    try:
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    if time.time() - last < WEEK_SECONDS:
        return None
    if scan_already_running():
        return None  # a scan is already going (manual or scheduled)
    start_scan_async(note="scheduled weekly scan")
    return True
