"""netmon/threatintel.py -- "rap sheets": threat-intel enrichment.

Every external IP and every DNS name the network touches gets checked
against community blocklists kept in a LOCAL table (ti_entries in
netmon.db), so lookups are fast and work offline. Feeds refresh on a
schedule (maybe_refresh_feeds, called from run.py's monitor loop); a
failed refresh keeps the old data and never breaks anything.

Sources (documented so the operator knows where a "bad" verdict came
from):
  * URLhaus hostfile (abuse.ch, https://urlhaus.abuse.ch/downloads/hostfile/)
    -- domains distributing malware/phishing. Free for any use.
  * Emerging Threats compromised-ips
    (https://rules.emergingthreats.net/blockrules/compromised-ips.txt)
    -- IPs observed in malicious activity. Free.

Optional:
  * AbuseIPDB (abuseipdb.com) -- per-IP abuse confidence scores, country,
    ISP, ASN. Needs ABUSEIPDB_API_KEY in the environment -- never in a
    config file or in code. Without it everything else still works; the
    dashboard simply hides the score fields (no error, no nagging).

Design notes (Phase 3.5 principles):
  * AI narrates, code decides: matching is deterministic exact string
    matching on normalized domains/IPs. No model decides what's bad.
  * Quiet is a feature: feed noise lives in the table, not in the inbox.
    Alerts fire once per domain/IP per 24h, respect the allowlist, and
    only for things actually seen on the wire.
  * Stdlib only: urllib + sqlite, no new dependencies.
"""
import ipaddress
import json
import os
import re
import socket
import threading
import time
from urllib.parse import urlparse, quote
from urllib.request import Request, urlopen

from . import db as dbm


# --- feed registry --------------------------------------------------------

_FEEDS = {
    "urlhaus-domains": {
        "kind": "domain",
        "url": "https://urlhaus.abuse.ch/downloads/hostfile/",
        "label": "URLhaus malware domains (abuse.ch)",
        "detail": ("Listed by abuse.ch URLhaus -- a community feed of"
                   " domains caught distributing malware or hosting"
                   " phishing pages."),
        "parser": "_parse_hostfile",
    },
    "et-compromised-ips": {
        "kind": "ip",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "label": "Emerging Threats compromised IPs",
        "detail": ("Listed by Emerging Threats -- a community feed of IP"
                   " addresses observed in malicious activity."),
        "parser": "_parse_ip_list",
    },
}

# SSRF guard: feed downloads may only go to these hosts, full stop.
# Anything else (including redirects -- urllib follows them, so the
# final host is re-checked below) raises instead of fetching.
_FEED_HOSTS = frozenset(
    urlparse(spec["url"]).hostname for spec in _FEEDS.values())

_ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"

MAX_FEED_BYTES = 5_000_000   # unbounded downloads are a disk/memory DoS
FETCH_TIMEOUT_S = 30
FEED_REFRESH_HOURS = 12      # how often the monitor loop refreshes feeds

# AbuseIPDB free tier: 1,000 lookups/day. The dashboard cache (24h per IP)
# plus this budget keeps us far under it; page views never hammer the API.
_ABUSEIPDB_CACHE_S = 24 * 3600
_ABUSEIPDB_DAILY_CAP = 50

_RDNS_CACHE_S = 7 * 86400

_refresh_lock = threading.Lock()


# --- feed download ----------------------------------------------------------

def _fetch_url(url):
    """Download a feed URL with a hard size cap and timeout.

    Raises on any failure (bad host, too large, network error) -- callers
    keep the old feed data. The host allowlist is checked before AND
    after urllib follows redirects.
    """
    host = (urlparse(url).hostname or "").lower()
    if host not in _FEED_HOSTS:
        raise ValueError(f"refusing to fetch non-feed host: {host!r}")
    req = Request(url, headers={"User-Agent": "brutedash-threatintel/1.0"})
    chunks, total = [], 0
    with urlopen(req, timeout=FETCH_TIMEOUT_S) as resp:
        final_host = (urlparse(resp.geturl()).hostname or "").lower()
        if final_host not in _FEED_HOSTS:
            raise ValueError(
                f"feed redirected to non-feed host: {final_host!r}")
        while True:
            data = resp.read(65536)
            if not data:
                break
            total += len(data)
            if total > MAX_FEED_BYTES:
                raise ValueError("feed too large; refusing unbounded"
                                 " download")
            chunks.append(data)
    return b"".join(chunks).decode("utf-8", errors="replace")


# --- feed parsing -------------------------------------------------------------

# Strict domain shape (linear-time, no nested quantifiers -- no ReDoS).
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")


def is_plausible_domain(name):
    """True for something shaped like a real domain (for input validation)."""
    return bool(name) and bool(_DOMAIN_RE.match(normalize_domain(name)))


def _parse_hostfile(text):
    """URLhaus hostfile: '127.0.0.1 bad.example.com' lines."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        dom = parts[1].lower().rstrip(".")
        if _DOMAIN_RE.match(dom):
            out.append(dom)
    return out


def _parse_ip_list(text):
    """One IP per line (Emerging Threats compromised-ips.txt)."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        tok = line.split()[0]
        try:
            ipaddress.ip_address(tok)
        except ValueError:
            continue
        out.append(tok)
    return out


# --- feed refresh ---------------------------------------------------------------

def refresh_feeds(now=None):
    """Download every feed and swap it into the local table.

    Returns {feed_name: {"ok", "entries", "error"}}. A failed feed keeps
    its old rows; nothing here raises. The attempt timestamp is always
    recorded so a dead network backs off instead of retrying every
    monitor-loop pass (see maybe_refresh_feeds).
    """
    import sys
    now = now if now is not None else time.time()
    dbm.set_meta("ti_feeds_attempted_ts", str(now))
    results = {}
    for name, spec in _FEEDS.items():
        try:
            raw = _fetch_url(spec["url"])
            parse = globals()[spec["parser"]]
            keys = parse(raw)
            dbm.ti_replace_feed(name, spec["kind"],
                                [(k, spec["detail"]) for k in keys])
            dbm.set_meta(f"ti_feed_updated_{name}", str(now))
            results[name] = {"ok": True, "entries": len(keys), "error": None}
        except Exception as exc:
            try:
                print(f"netmon threatintel: feed {name} refresh failed:"
                      f" {exc!r}", file=sys.stderr)
            except Exception:
                pass
            results[name] = {"ok": False, "entries": 0,
                             "error": str(exc)[:200]}
    if any(r["ok"] for r in results.values()):
        dbm.set_meta("ti_feeds_refreshed_ts", str(now))
    return results


def maybe_refresh_feeds(now=None, interval_s=FEED_REFRESH_HOURS * 3600,
                        retry_s=3600):
    """Refresh feeds when the last successful refresh is older than
    interval_s. Guarded by a lock so two threads can't double-fetch.

    A failed refresh backs off for retry_s (an hour) instead of hammering
    a dead network every monitor-loop pass -- the monitor thread must
    never spend a minute per loop waiting on feed timeouts.

    Returns the refresh results dict, or None when no refresh was due.
    Never raises."""
    now = now if now is not None else time.time()
    if not _refresh_lock.acquire(blocking=False):
        return None  # another thread is already refreshing
    try:
        def _f(key):
            try:
                return float(dbm.get_meta(key) or 0)
            except (TypeError, ValueError):
                return 0
        last_ok = _f("ti_feeds_refreshed_ts")
        last_try = _f("ti_feeds_attempted_ts")
        if now - last_ok < interval_s or now - last_try < retry_s:
            return None
        return refresh_feeds(now=now)
    except Exception:
        return None
    finally:
        _refresh_lock.release()


# --- normalization + local lookups --------------------------------------------------

def normalize_domain(name):
    """Lowercase, strip trailing dot and a leading wildcard."""
    if not name:
        return ""
    name = name.strip().lower().rstrip(".")
    if name.startswith("*."):
        name = name[2:]
    return name


def parent_domains(name, max_levels=3):
    """The domain plus its parents, down to the 2-label base:

    a.b.example.com -> [a.b.example.com, b.example.com, example.com]
    """
    labels = normalize_domain(name).split(".")
    out = []
    for i in range(min(max_levels + 1, len(labels) - 1)):
        cand = ".".join(labels[i:])
        if len(cand.split(".")) >= 2:
            out.append(cand)
    return out


def lookup_domain(domain):
    """Local-table hits for a domain: exact + parent-domain walk.

    A listing for example.com covers evil.example.com (blocklists are
    usually kept at the registrable base). Returns a list of
    {key, matched, feed, detail, first_seen, last_seen} -- `matched` is
    the listing that caught it, so the UI can say exactly what matched.
    """
    name = normalize_domain(domain)
    if not name or "." not in name:
        return []
    cands = parent_domains(name)
    if not cands:
        return []
    hits = dbm.ti_lookup("domain", cands)
    out = []
    for cand in cands:
        for h in hits.get(cand, []):
            out.append({"matched": cand, **h})
    return out


def domain_listed(domain):
    """True if any local feed lists this domain (exact or parent)."""
    return bool(lookup_domain(domain))


def lookup_ip(ip, include_abuseipdb=True):
    """Local blocklist hits for an IP, plus optional AbuseIPDB enrichment.

    Returns {"listed": [...], "abuseipdb": {...}|None}. The AbuseIPDB
    part is None when no API key is configured -- graceful, never an
    error, never a nag.
    """
    try:
        ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return {"listed": [], "abuseipdb": None}
    ip = ip.strip()
    hits = dbm.ti_lookup("ip", [ip]).get(ip, [])
    abuse = _abuseipdb_check(ip) if include_abuseipdb else None
    return {"listed": hits, "abuseipdb": abuse}


# --- AbuseIPDB (optional, env key only) ---------------------------------------------

def _abuseipdb_key():
    return (os.environ.get("ABUSEIPDB_API_KEY") or "").strip()


def abuseipdb_configured():
    """True when an AbuseIPDB API key is present in the environment."""
    return bool(_abuseipdb_key())


def _abuseipdb_check(ip):
    """Enrich one IP via AbuseIPDB. Returns a dict or None.

    None when: no API key configured, daily budget spent, cached result
    fresh, or any failure. The key travels only in the request header --
    it is never logged, never stored, never returned.
    """
    key = _abuseipdb_key()
    if not key:
        return None
    cache_key = f"ti_abuseipdb_{ip}"
    cached = dbm.get_meta(cache_key)
    if cached:
        try:
            data = json.loads(cached)
            if time.time() - data.get("ts", 0) < _ABUSEIPDB_CACHE_S:
                return data.get("result")
        except Exception:
            pass
    day = time.strftime("%Y-%m-%d", time.gmtime())
    budget_key = f"ti_abuseipdb_used_{day}"
    try:
        used = int(dbm.get_meta(budget_key) or 0)
    except (TypeError, ValueError):
        used = 0
    if used >= _ABUSEIPDB_DAILY_CAP:
        return None
    try:
        url = (f"{_ABUSEIPDB_CHECK_URL}?ipAddress={quote(ip)}"
               "&maxAgeInDays=90&verbose")
        req = Request(url, headers={"Key": key,
                                    "Accept": "application/json",
                                    "User-Agent": "brutedash-threatintel/1.0"})
        with urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read(65536).decode("utf-8", "replace"))
        d = (payload or {}).get("data") or {}
        result = {
            "score": d.get("abuseConfidenceScore"),
            "country": d.get("countryName") or d.get("countryCode"),
            "isp": d.get("isp"),
            "usage": d.get("usageType"),
            "asn": d.get("asn"),
            "domain": d.get("domain"),
            "reports": d.get("totalReports"),
            "last_reported": d.get("lastReportedAt"),
        }
        dbm.set_meta(budget_key, str(used + 1))
        dbm.set_meta(cache_key,
                     json.dumps({"ts": time.time(), "result": result}))
        return result
    except Exception:
        return None


# --- reverse DNS (best-effort, cached) --------------------------------------------------

def reverse_dns(ip):
    """Best-effort PTR lookup with a 3s cap, cached 7 days in meta.

    Returns the hostname or "". Slow/broken resolvers can't stall the
    dashboard: the lookup runs on a thread that we stop waiting for.
    """
    try:
        ipaddress.ip_address((ip or "").strip())
    except ValueError:
        return ""
    ip = ip.strip()
    ck = f"ti_rdns_{ip}"
    cached = dbm.get_meta(ck)
    if cached:
        try:
            data = json.loads(cached)
            if time.time() - data.get("ts", 0) < _RDNS_CACHE_S:
                return data.get("name") or ""
        except Exception:
            pass
    box = {}

    def _go():
        try:
            box["name"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

    t = threading.Thread(target=_go, daemon=True)
    t.start()
    t.join(3.0)
    name = (box.get("name") or "").rstrip(".")
    try:
        dbm.set_meta(ck, json.dumps({"ts": time.time(), "name": name}))
    except Exception:
        pass
    return name
