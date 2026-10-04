"""netmon/attacksurface.py -- "where am I exposed?": the attack surface review.

The view a small-business owner reads first. It ties together three
things the monitor already knows:

  * the asset inventory (batch 6): every device, hostname, maker, OS guess
  * the self vulnerability scan (batch 6): open doors per device
  * threat intel (batch 7): whether a device talked to anything malicious

...plus observed traffic (flows), which is the only honest way to say a
device is reachable from the internet: we have SEEN outside addresses
connect to it. No guesses, ever -- reachability carries a confidence
label ("Seen from outside" vs "No sign of outside access").

Design principles:
  * AI narrates, code decides: severity ranking is deterministic (see
    RANKING RULES below). The dashboard just renders the verdicts.
  * Quiet is a feature: this is an ON-DEMAND review view, not a new
    alert source. Nothing here fires alerts, sends email, or writes to
    the alerts table. Informational only.
  * No speculation beyond one hop: lateral paths come from observed
    LAN<->LAN flows, low-trust device -> high-value device, and stop
    there. Anything deeper would be a guess.

PLAYBOOK SLUGS (the playbooks batch implements /playbook/<slug> next;
until then the dashboard route renders a friendly placeholder):
    internet-exposed-door    a door the internet can reach (general case)
    internet-exposed-printer a printer reachable from the internet
    open-admin-interface     an admin page (router/camera/hub) reachable
                             from outside
    risky-service            a risky door (SMB/RDP/Telnet/database/UPnP)
                             open but not internet-visible
    malicious-contact        the device talked to a listed-malicious
                             address or site
    iot-lateral-path         a low-trust device seen talking to a
                             high-value one
Slug grammar: ^[a-z0-9-]{1,64}$ -- validated by valid_playbook_slug().
"""

import ipaddress
import re
import time

from . import db as dbm

# A week of observed traffic: long enough for port forwards to show up,
# short enough to stay relevant.
WINDOW_S = 7 * 86400
# Inbound-evidence rows kept per device (sorted by flow count, top wins).
EVIDENCE_CAP = 25
# Flow groups scanned per device when hunting for inbound evidence.
FLOW_SCAN_LIMIT = 5000
# LAN<->LAN flow groups examined for lateral paths (one query, bounded).
LAN_PAIR_LIMIT = 20000
# Max lateral paths reported (sorted: most flows first).
LATERAL_CAP = 50
# Threat-intel lookups per device (distinct IPs / DNS names).
TI_LOOKUP_CAP = 500
# New malicious-contact exposures listed per device before summarizing.
TI_EXPOSURE_CAP = 5

# Severity sort: lower = more urgent (sorts first).
_SEV_RANK = {"High": 0, "Medium": 1, "Low": 2}

# Device types that need little trust: cheap, rarely patched, often
# hijacked as a first foothold.
LOW_TRUST_TYPES = ("iot", "unknown", "tv", "printer")
# Device types holding things worth protecting.
HIGH_VALUE_TYPES = ("server", "desktop")


# ---------------------------------------------------------------------------
# Playbook slug convention (for the playbooks batch, which comes next)
# ---------------------------------------------------------------------------

# slug -> {title, blurb}: the fix-it guide each exposure links to.
# Slugs are lowercase kebab-case by convention; see module docstring.
PLAYBOOK_SLUGS = {
    "internet-exposed-door": {
        "title": "A door the internet can reach",
        "blurb": ("Something on your network answers when the internet"
                  " knocks. This guide walks through closing it: port"
                  " forwards, DMZ settings, and UPnP on your router."),
    },
    "internet-exposed-printer": {
        "title": "Your printer is visible to the internet",
        "blurb": ("Printers should never face the internet -- their admin"
                  " pages are a classic break-in point. This guide shows how"
                  " to pull it back behind your router."),
    },
    "open-admin-interface": {
        "title": "An admin page is reachable from outside",
        "blurb": ("A settings/admin page (router, camera, hub) answers"
                  " connections from the internet. This guide covers"
                  " password-protecting it or taking it off the internet."),
    },
    "risky-service": {
        "title": "A risky service is running on your network",
        "blurb": ("Something like file sharing, remote desktop, or an old"
                  " login protocol is switched on. This guide explains what"
                  " it is and how to turn it off if you don't need it."),
    },
    "malicious-contact": {
        "title": "A device talked to a known-bad address",
        "blurb": ("One of your devices contacted an address that security"
                  " researchers flag as malicious. This guide walks through"
                  " figuring out which device, what it was doing, and what"
                  " to do next."),
    },
    "iot-lateral-path": {
        "title": "A small device can reach an important one",
        "blurb": ("A low-trust gadget (smart plug, camera, TV) has been seen"
                  " talking to a computer or server on your network. This"
                  " guide explains network segmentation in plain English."),
    },
}

_SLUG_RE = re.compile(r"^[a-z0-9-]{1,64}$")


def valid_playbook_slug(slug):
    """True for well-formed playbook slugs (the dashboard 404s otherwise).

    Grammar only -- unknown-but-well-formed slugs still render the
    friendly placeholder page, so nothing 404s once the guides land.
    """
    return bool(slug) and bool(_SLUG_RE.match(str(slug)))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _is_external_ip(ip):
    """True for public-internet addresses (not LAN, loopback, multicast)."""
    if not ip:
        return False
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def _is_lan_ip(ip):
    """True for RFC1918 addresses (the LAN we review)."""
    try:
        parts = str(ip).split(".")
        if len(parts) != 4:
            return False
        a, b = int(parts[0]), int(parts[1])
    except (ValueError, TypeError):
        return False
    return (a == 10 or (a == 172 and 16 <= b <= 31)
            or (a == 192 and b == 168))


def _skip_domain(norm):
    """True for names that can never be a threat-intel hit (mirrors the
    detector's skip list so the review agrees with the alerts)."""
    if not norm or "." not in norm:
        return True
    if norm.endswith((".local", ".lan", ".home", ".internal", ".invalid",
                       ".localhost")):
        return True
    try:
        ipaddress.ip_address(norm)  # PTR-style literals aren't domains
        return True
    except ValueError:
        return False


def _risky_ports():
    """Scan ports whose knowledge-base risk is 'Medium' -- doors with a
    known weakness (telnet, SMB, RDP, databases, UPnP, ...)."""
    try:
        from . import scan as scanm
        return {p for p, (risk, _what) in scanm.RISK_KB.items()
                if risk == "Medium"}
    except Exception:
        return set()


def _service_ports():
    """Every port the self scan knocks on -- used as the 'service port'
    set for inbound evidence (see inbound_evidence)."""
    try:
        from . import scan as scanm
        return {p for p, _svc in scanm.SCAN_PORTS}
    except Exception:
        return set()


def _port_service(port):
    try:
        from . import scan as scanm
        return dict(scanm.SCAN_PORTS).get(port, "unknown")
    except Exception:
        return "unknown"


# ---------------------------------------------------------------------------
# Internet reachability -- the only claim that needs evidence
# ---------------------------------------------------------------------------

def inbound_evidence(ip, service_ports, now=None):
    """(reachable, evidence): has the internet connected TO this device?

    A flow counts as evidence only when ALL of these hold:
      * dst_ip is the device and src_ip is a public-internet address --
        it really came from outside;
      * dst_port is a SERVICE port (the self scan found it open, or it is
        one of the well-known service ports the scanner knocks on).
        This separates genuine inbound connections from return traffic:
        replies to outbound connections come back to ephemeral ports,
        never to service ports -- so an outside address hitting port
        3389 on your PC is someone knocking on Remote Desktop, not a
        reply to your web browsing.
      * it was seen inside the review window (7 days).

    Returns (False, []) when nothing qualifies -- which is honest, not
    reassuring: "no sign of outside access" means nobody came knocking
    while we watched, not "provably unreachable".
    """
    now = now if now is not None else time.time()
    service_ports = {int(p) for p in (service_ports or ())}
    evidence = []
    if not ip or not service_ports:
        return False, evidence
    try:
        rows = dbm.query(
            "SELECT src_ip, dst_port, MIN(ts), MAX(ts), COUNT(*),"
            " COALESCE(SUM(bytes),0) FROM flows"
            " WHERE dst_ip=? AND ts > ?"
            " GROUP BY src_ip, dst_port LIMIT ?",
            (ip, now - WINDOW_S, FLOW_SCAN_LIMIT))
    except Exception:
        return False, []
    for src_ip, dst_port, first, last, nflows, nbytes in rows:
        if not _is_external_ip(src_ip):
            continue
        try:
            dport = int(dst_port)
        except (TypeError, ValueError):
            continue
        if dport not in service_ports:
            continue  # return traffic to an ephemeral port, not a knock
        evidence.append({
            "ext_ip": src_ip, "port": dport,
            "service": _port_service(dport),
            "flows": nflows or 0, "bytes": nbytes or 0,
            "first_seen": first or 0, "last_seen": last or 0,
        })
    evidence.sort(key=lambda e: e["flows"], reverse=True)
    evidence = evidence[:EVIDENCE_CAP]
    return bool(evidence), evidence


# ---------------------------------------------------------------------------
# Threat-intel context per device (batch 7 data, local table only)
# ---------------------------------------------------------------------------

def ti_hits_for_device(ip, now=None):
    """Listed-malicious addresses/sites this device talked to, last 7 days.

    Local threat-intel table only -- never touches the network (no
    AbuseIPDB lookups here; the intel page does those on demand with a
    key). Returns [{value, kind, feeds, detail}] -- feeds are the raw
    feed names, the same wording the alerts use.
    """
    now = now if now is not None else time.time()
    hits = []
    seen = set()
    try:
        from . import threatintel as tim
    except Exception:
        return hits

    # (a) external IPs the device exchanged traffic with.
    try:
        rows = dbm.query(
            "SELECT DISTINCT src_ip FROM flows WHERE dst_ip=? AND ts > ?"
            " UNION SELECT DISTINCT dst_ip FROM flows"
            " WHERE src_ip=? AND ts > ?",
            (ip, now - WINDOW_S, ip, now - WINDOW_S))
    except Exception:
        rows = []
    ext_ips = sorted({r[0] for r in rows if _is_external_ip(r[0])})
    ext_ips = ext_ips[:TI_LOOKUP_CAP]
    if ext_ips:
        try:
            for addr, entries in dbm.ti_lookup("ip", ext_ips).items():
                if not entries or addr in seen:
                    continue
                seen.add(addr)
                hits.append({
                    "value": addr, "kind": "ip",
                    "feeds": sorted({e.get("feed") or "threat-intel feed"
                                     for e in entries}),
                    "detail": entries[0].get("detail") or
                              "flagged as malicious",
                })
        except Exception:
            pass

    # (b) DNS names the device looked up.
    try:
        names = dbm.query(
            "SELECT DISTINCT name FROM dns_queries"
            " WHERE src_ip=? AND ts > ?", (ip, now - WINDOW_S))
    except Exception:
        names = []
    checked = 0
    for (name,) in names:
        if checked >= TI_LOOKUP_CAP:
            break
        norm = tim.normalize_domain(name or "")
        if _skip_domain(norm):
            continue
        checked += 1
        try:
            found = tim.lookup_domain(norm)
        except Exception:
            continue
        if not found or norm in seen:
            continue
        seen.add(norm)
        hits.append({
            "value": norm, "kind": "domain",
            "feeds": sorted({h.get("feed") or "threat-intel feed"
                             for h in found}),
            "detail": found[0].get("detail") or "flagged as malicious",
        })
    return hits


# ---------------------------------------------------------------------------
# Exposure inventory per device + deterministic severity ranking
# ---------------------------------------------------------------------------

# RANKING RULES (deterministic, explainable -- code decides):
#
#   High   1. Internet-reachable AND a risky door open.
#             Anyone on the internet can walk up to a door with a known
#             weakness (telnet/SMB/RDP/database/UPnP...). Worst combo.
#   High   2. Talked to a listed-malicious address or site in the window.
#             Independent security researchers flagged that address --
#             not our guess.
#   Medium 3. Internet-reachable, but only plain (Low-risk) doors open.
#             Visible from outside; the doors themselves are ordinary.
#   Medium 4. Risky door open, NOT internet-reachable.
#             Safe today, but anyone who gets a foothold inside the
#             network (a hacked smart plug, a visitor's laptop) can
#             reach it.
#   Medium 5. Lateral path: low-trust device seen talking to a
#             high-value device. One hop, observed -- never inferred.
#   Low    6. Plain door open, LAN-only. Worth knowing, not worth
#             losing sleep over.
#
# Exposures sort by (severity rank, internet-reachable first, device
# name) so the scariest, most-exposed things read first.

def _label_for(dev):
    """Human label for a device: friendly name, hostname, or IP."""
    return dev.get("name") or dev.get("hostname") or dev.get("ip") or "a device"


def device_exposures(dev, reachable, ti_hits):
    """Ranked exposure list for one device.

    dev: {name, hostname, ip, mac, dtype, type_label, open_ports:[...]}.
    Returns [{severity, title, what_it_means, why_it_matters, playbook}].
    """
    exposures = []
    label = _label_for(dev)
    dtype = dev.get("dtype") or "unknown"
    ports = dev.get("open_ports") or []
    risky = _risky_ports()
    risky_open = [p for p in ports if _safe_port(p) in risky]
    plain_open = [p for p in ports if _safe_port(p) not in risky]
    upnp_open = any(_safe_port(p) == 1900 for p in ports)

    def _doors(plist):
        return ", ".join(
            f"port {p.get('port')} ({p.get('service') or 'unknown'})"
            for p in sorted(plist, key=lambda x: _safe_port(x)))

    # Rule 1: internet-reachable + risky door -> High.
    if reachable and risky_open:
        admin_ports = {80, 443, 8080, 8443}
        admin_open = [p for p in risky_open
                      if _safe_port(p) in admin_ports]
        if dtype == "printer":
            title = (f"Your printer's admin page is visible to the"
                     f" whole internet.")
            playbook = "internet-exposed-printer"
            meaning = (f"We watched outside addresses connect to {label}"
                       f" ({_doors(risky_open)}). Printers should never"
                       f" face the internet -- their admin pages are a"
                       f" classic break-in point.")
        elif dtype in ("router", "ap") or admin_open:
            title = (f"An admin page on {label} is visible to the"
                     f" whole internet.")
            playbook = "open-admin-interface"
            meaning = (f"We watched outside addresses connect to {label}"
                       f" ({_doors(admin_open or risky_open)}). That is the"
                       f" device's settings page answering the internet.")
        else:
            title = (f"A risky door on {label} is reachable from the"
                     f" internet.")
            playbook = "internet-exposed-door"
            meaning = (f"We watched outside addresses connect to {label}"
                       f" ({_doors(risky_open)}). These are services with"
                       f" known weaknesses -- exactly what automated"
                       f" scanners on the internet go looking for.")
        why = ("Rule 1: a risky door facing the internet is the worst"
               " combination -- anyone, anywhere, can knock on it.")
        if upnp_open:
            why += (" UPnP is also on, so gadgets on your network can ask"
                    " the router to open doors on their own; the actual"
                    " port mappings are not visible in captured traffic.")
        exposures.append({
            "severity": "High", "title": title,
            "what_it_means": meaning, "why_it_matters": why,
            "playbook": playbook})

    # Rule 3: internet-reachable, only plain doors -> Medium.
    if reachable and not risky_open and plain_open:
        if dtype == "printer":
            title = (f"Your printer is visible to the whole internet.")
            meaning = (f"We watched outside addresses connect to {label}"
                       f" ({_doors(plain_open)}). Printers should never"
                       f" face the internet -- even plain printer ports"
                       f" get abused for spam relaying and snooping.")
            playbook = "internet-exposed-printer"
        else:
            title = f"{label} can be reached from the internet."
            meaning = (f"We watched outside addresses connect to"
                       f" {label} ({_doors(plain_open)}). The doors"
                       f" themselves are ordinary -- web pages and"
                       f" the like -- but the device is visible from"
                       f" outside your home.")
            playbook = "internet-exposed-door"
        exposures.append({
            "severity": "Medium",
            "title": title,
            "what_it_means": meaning,
            "why_it_matters": ("Rule 3: visible from outside means it is"
                               " in every internet scanner's address book."
                               " Ordinary doors are fine until one has a"
                               " bug."),
            "playbook": playbook})

    # Rule 4: risky door open, LAN-only -> Medium.
    if not reachable and risky_open:
        why = ("Rule 4: not visible from outside, so today is fine -- but"
               " anyone who gets a foothold inside your network (a hacked"
               " smart plug, a visitor's laptop) can reach these doors.")
        if upnp_open:
            why += (" UPnP is also on, which is how malware punches its"
                    " own holes in the router.")
        exposures.append({
            "severity": "Medium",
            "title": (f"A risky door is open on {label}:"
                      f" {_doors(risky_open)}."),
            "what_it_means": ("These services have known weaknesses"
                              " (plain-text logins, file sharing, remote"
                              " desktop, databases). Nobody outside can"
                              " reach them right now -- but everything"
                              " inside your network can."),
            "why_it_matters": why,
            "playbook": "risky-service"})

    # Rule 6: plain doors only, LAN-only -> Low.
    if not reachable and not risky_open and plain_open:
        exposures.append({
            "severity": "Low",
            "title": f"Some doors are open on {label}: {_doors(plain_open)}.",
            "what_it_means": ("Ordinary services -- web pages, printer"
                              " ports, that kind of thing. They only"
                              " answer inside your network."),
            "why_it_matters": ("Rule 6: plain doors, LAN-only. Worth"
                               " knowing, not worth losing sleep over."),
            "playbook": "risky-service"})

    # Rule 2: talked to a listed-malicious address/site -> High.
    for hit in (ti_hits or [])[:TI_EXPOSURE_CAP]:
        kind_word = "address" if hit.get("kind") == "ip" else "site"
        exposures.append({
            "severity": "High",
            "title": (f"{label} talked to a known-bad {kind_word}:"
                      f" {hit.get('value')}."),
            "what_it_means": (f"In the last week {label} contacted"
                              f" {hit.get('value')}, which sits on"
                              f" {', '.join(hit.get('feeds') or ['a threat-intel list'])}:"
                              f" {hit.get('detail')}. Think of it as a phone"
                              f" number on a scam-call list."),
            "why_it_matters": ("Rule 2: independent security researchers"
                               " flagged that address -- not our guess."
                               " Legitimate apps do not run from addresses"
                               " on these lists."),
            "playbook": "malicious-contact"})
    extra_ti = max(0, len(ti_hits or []) - TI_EXPOSURE_CAP)
    if extra_ti:
        exposures.append({
            "severity": "High",
            "title": f"{label} talked to {extra_ti} more known-bad"
                     f" {'address' if extra_ti == 1 else 'addresses'}.",
            "what_it_means": ("See the Threat intel section for the full"
                              " list."),
            "why_it_matters": "Rule 2, continued.",
            "playbook": "malicious-contact"})

    exposures.sort(key=lambda e: _SEV_RANK.get(e["severity"], 9))
    return exposures


# ---------------------------------------------------------------------------
# Lateral-movement paths (observed, one hop, bounded)
# ---------------------------------------------------------------------------

def lateral_paths(devices_by_ip, gateway_ip, now=None):
    """One-hop paths a break-in could walk, from observed traffic.

    A path is: low-trust device (IoT/unknown/TV/printer) -> high-value
    device (server/desktop, or anything with a risky door open), with
    real LAN<->LAN flows between them in the window.

    Bounds (no exponential path explosion):
      * one GROUP BY query, capped at LAN_PAIR_LIMIT rows;
      * gateway pairs excluded -- everyone talks to the router, that is
        plumbing, not a path;
      * one hop only -- the report never claims two-hop paths;
      * LATERAL_CAP paths max, most flows first.
    """
    now = now if now is not None else time.time()
    risky = _risky_ports()
    try:
        rows = dbm.query(
            "SELECT src_ip, dst_ip, dst_port, COUNT(*),"
            " COALESCE(SUM(bytes),0), MAX(ts) FROM flows WHERE ts > ?"
            " GROUP BY src_ip, dst_ip, dst_port LIMIT ?",
            (now - WINDOW_S, LAN_PAIR_LIMIT))
    except Exception:
        return []
    # Collapse to (src, dst): ports + totals. Bounded by the query cap.
    pairs = {}
    for src, dst, dport, nflows, nbytes, last in rows:
        if not src or not dst or src == dst:
            continue
        if not (_is_lan_ip(src) and _is_lan_ip(dst)):
            continue
        if gateway_ip and (src == gateway_ip or dst == gateway_ip):
            continue
        key = (src, dst)
        cell = pairs.setdefault(
            key, {"ports": set(), "flows": 0, "bytes": 0, "last": 0})
        try:
            cell["ports"].add(int(dport))
        except (TypeError, ValueError):
            pass
        cell["flows"] += nflows or 0
        cell["bytes"] += nbytes or 0
        cell["last"] = max(cell["last"], last or 0)

    paths = []
    for (src, dst), cell in pairs.items():
        sdev = devices_by_ip.get(src) or {}
        ddev = devices_by_ip.get(dst) or {}
        if (sdev.get("dtype") or "unknown") not in LOW_TRUST_TYPES:
            continue
        dports = {_safe_port(p)
                  for p in (ddev.get("open_ports") or [])}
        high_value = ((ddev.get("dtype") or "unknown") in HIGH_VALUE_TYPES
                      or bool(dports & risky))
        if not high_value:
            continue
        slabel = _label_for({**sdev, "ip": src})
        dlabel = _label_for({**ddev, "ip": dst})
        port_words = ", ".join(
            f"port {p} ({_port_service(p)})" for p in sorted(cell["ports"]))
        paths.append({
            "from_ip": src, "from_name": slabel,
            "from_type": sdev.get("type_label") or sdev.get("dtype") or
            "unknown",
            "to_ip": dst, "to_name": dlabel,
            "to_type": ddev.get("type_label") or ddev.get("dtype") or
            "unknown",
            "ports": port_words or "unknown channels",
            "flows": cell["flows"], "mb": round(cell["bytes"] / 1e6, 2),
            "severity": "Medium",
            "title": (f"If someone got into {slabel}, they could reach"
                      f" {dlabel}."),
            "what_it_means": (f"We watched {slabel} talk to {dlabel} on"
                              f" {port_words or 'unknown channels'} in the"
                              f" last week ({cell['flows']} connections)."
                              f" {slabel} is a low-trust gadget -- the kind"
                              f" of thing that gets hijacked first."),
            "why_it_matters": ("Rule 5: one hop, observed -- not inferred."
                               " Small devices are the usual way in; this"
                               " shows exactly where 'in' leads."),
            "playbook": "iot-lateral-path",
        })
    paths.sort(key=lambda p: p["flows"], reverse=True)
    return paths[:LATERAL_CAP]


# ---------------------------------------------------------------------------
# The report
# ---------------------------------------------------------------------------

def _safe_port(p):
    """Port number from a scan-finding dict, or 0 when corrupt.

    Scan findings come from our own table (integers), but the report
    must not die on one bad row -- per-device failures stay per-device.
    """
    try:
        return int(p.get("port") or 0)
    except (TypeError, ValueError, AttributeError):
        return 0


def _load_devices(now):
    """Device dicts for the review: assets + names + best-guess types."""
    from . import assets as assetsm
    from . import topology as topom
    try:
        raw_assets = assetsm.get_assets()
    except Exception:
        raw_assets = []
    try:
        names = dbm.device_name_map()
    except Exception:
        names = {}
    try:
        gw_ip, gw_mac = topom.gateway_info()
    except Exception:
        gw_ip, gw_mac = None, None
    devices = []
    for a in raw_assets:
        mac = (a.get("mac") or "").lower()
        ip = a.get("ip") or ""
        ports = a.get("open_ports") or []
        is_gw = bool(gw_ip and ip == gw_ip) or bool(
            gw_mac and mac and mac == gw_mac.lower())
        try:
            dtype, dsource = topom.classify_device(
                mac, vendor=a.get("vendor"), hostname=a.get("hostname"),
                os_guess=a.get("os_guess"), open_ports=ports,
                is_gateway=is_gw, dns_hints=())
        except Exception:
            dtype, dsource = "unknown", "auto"
        devices.append({
            "mac": mac, "ip": ip,
            "name": names.get(mac, ""),
            "hostname": a.get("hostname") or "",
            "vendor": a.get("vendor") or "",
            "os_guess": a.get("os_guess") or "",
            "dtype": dtype, "dtype_source": dsource,
            "type_label": topom.TYPE_LABELS.get(dtype, dtype),
            "is_gateway": is_gw,
            "open_ports": [{"port": _safe_port(p),
                            "service": p.get("service") or "unknown",
                            "risk": p.get("risk") or "Low"}
                           for p in ports],
            "first_seen": a.get("first_seen") or 0,
            "last_seen": a.get("last_seen") or 0,
        })
    return devices, (gw_ip or "")


def _summary_line(counts, top_exposures):
    """The one-line read: 'N things worth a look' style."""
    n = counts.get("High", 0) + counts.get("Medium", 0)
    if not n:
        return ("All quiet on the exposure front -- no internet-reachable"
                " doors, no known-bad contacts, no risky paths. A quiet"
                " network is a healthy network.")
    bits = top_exposures[:3]
    word = "thing" if n == 1 else "things"
    head = f"{n} {word} worth a look"
    if bits:
        head += ": " + "; ".join(b["title"] for b in bits)
        if n > len(bits):
            head += f"; and {n - len(bits)} more below"
    return head + "."


def build_report(now=None):
    """Everything the Attack Surface view needs.

    Read-only: it never fires alerts, sends email, or writes the alerts
    table. Returns {ok, summary_line, counts, devices, exposures,
    lateral_paths}. `exposures` is the flattened, ranked list across all
    devices; `devices` carries per-device detail (reachability,
    evidence, open doors, threat-intel hits).
    """
    now = now if now is not None else time.time()
    try:
        devices, gw_ip = _load_devices(now)
    except Exception:
        return {"ok": False, "error": "could not load device inventory"}
    service_ports = _service_ports()
    devices_by_ip = {d["ip"]: d for d in devices if d.get("ip")}

    for dev in devices:
        ip = dev.get("ip") or ""
        scan_ports = {p["port"] for p in dev.get("open_ports") or []}
        try:
            reachable, evidence = inbound_evidence(
                ip, scan_ports | service_ports, now=now)
        except Exception:
            reachable, evidence = False, []
        try:
            hits = ti_hits_for_device(ip, now=now) if ip else []
        except Exception:
            hits = []
        try:
            exposures = device_exposures(dev, reachable, hits)
        except Exception:
            exposures = []
        dev["reachable"] = reachable
        if reachable:
            dev["reachability_label"] = "Seen from outside"
            dev["reachability_note"] = (
                "We watched outside addresses connect to this device in"
                " the last week -- that is how we know it is reachable"
                " from the internet.")
        else:
            dev["reachability_label"] = "No sign of outside access"
            dev["reachability_note"] = (
                "No outside traffic to this device in the last week. That"
                " does not prove it is unreachable -- just that nobody"
                " came knocking while we watched.")
        dev["reachability_evidence"] = [
            {**e,
             "first_seen": e["first_seen"] or 0,
             "last_seen": e["last_seen"] or 0}
            for e in evidence]
        dev["ti_hits"] = hits
        dev["exposures"] = exposures

    try:
        paths = lateral_paths(devices_by_ip, gw_ip, now=now)
    except Exception:
        paths = []

    flat = []
    for dev in devices:
        for e in dev.get("exposures") or []:
            flat.append({**e,
                         "device": _label_for(dev),
                         "device_ip": dev.get("ip") or "",
                         "device_mac": dev.get("mac") or "",
                         "reachable": dev.get("reachable")})
    flat.sort(key=lambda e: (_SEV_RANK.get(e["severity"], 9),
                             0 if e.get("reachable") else 1,
                             e.get("device") or ""))

    counts = {"High": 0, "Medium": 0, "Low": 0}
    for e in flat:
        counts[e["severity"]] = counts.get(e["severity"], 0) + 1
    counts["lateral_paths"] = len(paths)
    counts["devices"] = len(devices)
    counts["reachable_devices"] = sum(1 for d in devices if d.get("reachable"))

    return {
        "ok": True,
        "summary_line": _summary_line(counts, flat),
        "counts": counts,
        "devices": devices,
        "exposures": flat,
        "lateral_paths": paths,
    }
