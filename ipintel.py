"""ipintel.py -- best-effort IP enrichment for brutedash briefs.

Before writing a technical brief, the analyst enriches the attacker IP
(geolocation + hosting/proxy signals) so the brief carries context beyond
the raw log lines. This is the project's "tool use": gather evidence with a
tool, then reason over it.

Uses the free ip-api.com endpoint (no key needed). Results are cached in
SQLite for 24h; failures are cached for 10 minutes so an outage costs one
stall per IP per window, not one per brief. Any failure -- no network,
rate limit, reserved IP range -- returns {} and the brief is written
without enrichment. Intel never blocks the brief.
"""
import json
import os
import sqlite3
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "detections.db")
# Plain HTTP is a known, accepted-for-now constraint, not an oversight:
# the free ip-api endpoint refuses HTTPS ("SSL unavailable for this
# endpoint, order a key" -- verified live 2026-10-20), so a scheme swap
# silently kills enrichment. Moving to a keyed/HTTPS provider is staged
# as a Tier 2 proposal (warden/state/proposals/, 2026-10-20). Until
# then the response is size-capped below and treated as untrusted
# context only (the brief shape is validated in app.py).
API_URL = "http://ip-api.com/json/{ip}?fields=status,country,org,proxy,hosting,query"
CACHE_TTL = 24 * 3600  # seconds
# Robustness L8 (council review, 2026-11-01): how long a failed lookup
# is cached before it is retried. A negative row is stored with empty
# country/org -- a shape _fetch() never produces (it defaults both to
# "unknown") -- so the read path can tell it apart from a real result.
NEGATIVE_CACHE_TTL = 10 * 60  # seconds
MAX_RESPONSE_BYTES = 64 * 1024  # a legit reply is a few hundred bytes


def _db():
    # Robustness L7 (council review, 2026-11-01): timeout=30, matching
    # app.get_db() and netmon/db.py -- this module writes the same
    # detections.db and must wait out a lock, not fail at the 5s default.
    conn = sqlite3.connect(DB_PATH, timeout=30)
    # L1 (security, 2026-10-20): same file, same self-heal as app.get_db
    # -- this module also opens detections.db and must not leave a
    # fresh copy world-readable.
    try:
        if os.stat(DB_PATH).st_mode & 0o077:
            os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    conn.execute(
        "CREATE TABLE IF NOT EXISTS ip_intel ("
        "ip TEXT PRIMARY KEY, country TEXT, org TEXT, "
        "proxy INTEGER, hosting INTEGER, fetched_at REAL)"
    )
    return conn


def _fetch(ip):
    req = urllib.request.Request(API_URL.format(ip=ip),
                                 headers={"User-Agent": "brutedash/1.0"})
    with urllib.request.urlopen(req, timeout=5) as resp:
        # M3 (security, 2026-10-20): never read an unbounded body into
        # memory -- read one byte past the cap so an over-cap reply is
        # detected and dropped instead of parsed.
        raw = resp.read(MAX_RESPONSE_BYTES + 1)
    if len(raw) > MAX_RESPONSE_BYTES:
        return {}
    data = json.loads(raw.decode("utf-8"))
    if data.get("status") != "success":
        return {}
    return {"country": data.get("country") or "unknown",
            "org": data.get("org") or "unknown",
            "proxy": bool(data.get("proxy")),
            "hosting": bool(data.get("hosting"))}


def lookup_ip(ip):
    """Return enrichment dict for ip, or {} when unavailable.

    Cached in SQLite for 24h; failures are cached for
    NEGATIVE_CACHE_TTL so a down endpoint is retried at most once per
    IP per window instead of stalling every brief. Never raises, and
    the connection is closed on every path (robustness L8: the old
    bare-except return leaked the handle whenever _fetch raised).
    """
    conn = None
    try:
        conn = _db()
        row = conn.execute(
            "SELECT country, org, proxy, hosting, fetched_at "
            "FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
        if row:
            age = time.time() - row[4]
            if row[0] == "" and row[1] == "":
                # Negative marker (see NEGATIVE_CACHE_TTL): fresh
                # means "known unavailable", not a real result --
                # never return it as a positive dict.
                if age < NEGATIVE_CACHE_TTL:
                    return {}
            elif age < CACHE_TTL:
                return {"country": row[0], "org": row[1],
                        "proxy": bool(row[2]), "hosting": bool(row[3])}
        try:
            intel = _fetch(ip)
        except Exception:
            intel = {}
        if intel:
            conn.execute(
                "INSERT OR REPLACE INTO ip_intel "
                "(ip, country, org, proxy, hosting, fetched_at) "
                "VALUES (?,?,?,?,?,?)",
                (ip, intel["country"], intel["org"],
                 int(intel["proxy"]), int(intel["hosting"]), time.time()))
        else:
            conn.execute(
                "INSERT OR REPLACE INTO ip_intel "
                "(ip, country, org, proxy, hosting, fetched_at) "
                "VALUES (?,?,?,?,?,?)",
                (ip, "", "", 0, 0, time.time()))
        conn.commit()
        return intel
    except Exception:
        return {}
    finally:
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass


def describe(intel):
    """One-line human summary of an intel dict, for prompt evidence."""
    if not intel:
        return ""
    flags = []
    if intel.get("hosting"):
        flags.append("hosting provider")
    if intel.get("proxy"):
        flags.append("known proxy")
    suffix = f" ({', '.join(flags)})" if flags else ""
    return f"{intel.get('country', 'unknown')}, {intel.get('org', 'unknown')}{suffix}"


if __name__ == "__main__":
    import sys

    ip = sys.argv[1] if len(sys.argv) > 1 else "8.8.8.8"
    print(ip, "->", lookup_ip(ip))
