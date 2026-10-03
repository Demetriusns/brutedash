"""netmon/learn.py -- learn from triage feedback (Phase 3.5, quiet-first).

Every dismissal teaches the monitor something. This module turns a
dismissed alert into a suggested "never alert me about this" pattern:

    dismiss -> extract a stable pattern -> count repeats ->
    at threshold, propose a suggestion -> human clicks Apply/Ignore

AI narrates, code decides, and the human still has the final say: nothing
here ever silences anything on its own. Applying a suggestion writes one
allowlist row, which the detector already consults before firing.

Design notes:
- Patterns are single substring tokens (the allowlist matches by
  substring), so pick the most specific stable indicator -- a domain for
  DNS-ish rules, the destination IP for port/contact rules ("port N" when
  no IP is present), a MAC for device rules. Kind-only patterns are broad
  (they match the whole rule as a wildcard) and are flagged as such.
- LAN/private IPs are never candidates -- silencing "192.168.1.1"
  would blind a whole class of local-network alerts.
- Timestamps/counts are stripped automatically: the extractor only
  looks for IPs, domains, ports, and MACs.
"""
import re

# How many dismissals of the same (rule, pattern) trigger a suggestion.
# Higher-severity alerts need more evidence before we propose silence.
SUGGEST_AFTER = {"Low": 3, "Medium": 3, "High": 5, "Critical": 5}

_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_DOMAIN_RE = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b", re.I)
_PORT_RE = re.compile(r"\bport (\d{1,5})\b", re.I)
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}:){5}[0-9a-f]{2}\b", re.I)

_DNS_KINDS = {"dns_lookup_burst", "dns_tunneling", "new_busy_domain"}
_PORT_KINDS = {"unusual_port", "port_scan"}
_DEVICE_KINDS = {"new_device", "behavior_deviation", "probation_watch"}

_LAN_PREFIXES = ("10.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.",
                 "172.21.", "172.22.", "172.23.", "172.24.", "172.25.",
                 "172.26.", "172.27.", "172.28.", "172.29.", "172.30.",
                 "172.31.", "192.168.", "127.")


def _is_lan_ip(ip):
    ip = ip or ""
    return ip.startswith(_LAN_PREFIXES)


def _valid_ip(ip):
    try:
        return all(0 <= int(p) <= 255 for p in ip.split("."))
    except ValueError:
        return False


def _candidate_ips(text):
    """External IPv4 addresses mentioned in text, order preserved."""
    out = []
    for m in _IP_RE.finditer(text or ""):
        ip = m.group(0)
        if _valid_ip(ip) and not _is_lan_ip(ip) and ip not in out:
            out.append(ip)
    return out


def extract_pattern(alert):
    """Return (pattern, broad) for a dismissed alert dict.

    `alert` carries kind/severity/title/detail. The pattern is the most
    specific stable token available; `broad` is True when the only option
    is the rule name itself (applying it would silence the whole rule).
    """
    kind = (alert.get("kind") or "").strip()
    text = f"{alert.get('title') or ''} {alert.get('detail') or ''}"
    dom = _DOMAIN_RE.search(text)
    ips = _candidate_ips(text)
    port = _PORT_RE.search(text)
    mac = _MAC_RE.search(text)

    if kind in _DNS_KINDS and dom:
        return dom.group(0).lower(), False
    if kind in _PORT_KINDS and ips:
        return ips[0], False
    if kind in _PORT_KINDS and port:
        return f"port {port.group(1)}", False
    if kind in _DEVICE_KINDS and mac:
        return mac.group(0).lower(), False
    if ips:
        return ips[0], False
    if port:
        return f"port {port.group(1)}", False
    if dom:
        return dom.group(0).lower(), False
    if mac:
        return mac.group(0).lower(), False
    return kind, True  # nothing stable found: the whole rule, flagged broad


def threshold_for(severity):
    """Dismissals needed before a suggestion appears for this severity."""
    return SUGGEST_AFTER.get((severity or "Medium").strip(), 3)


def why_text(kind, pattern, broad, dismissals, severity):
    """Plain-English reason shown next to the suggestion."""
    scope = (f"every '{kind}' alert (this would silence the whole rule)"
             if broad
             else f"'{kind}' alerts mentioning '{pattern}'")
    return (f"You've dismissed {dismissals} {severity or ''} {kind} alerts"
            f" like this one. Want to stop seeing {scope}?")
