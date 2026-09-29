"""ipintel.py -- best-effort IP enrichment for brutedash briefs.

Before writing a technical brief, the analyst enriches the attacker IP
(geolocation + hosting/proxy signals) so the brief carries context beyond
the raw log lines. This is the project's "tool use": gather evidence with a
tool, then reason over it.

Uses the free ip-api.com endpoint (no key needed). Results are cached in
SQLite for 24h. Any failure -- no network, rate limit, reserved IP range --
returns {} and the brief is written without enrichment. Intel never blocks
the brief.
"""
import json
import os
import sqlite3
import time
import urllib.request

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "detections.db")
API_URL = "http://ip-api.com/json/{ip}?fields=status,country,org,proxy,hosting,query"
CACHE_TTL = 24 * 3600  # seconds


def _db():
    conn = sqlite3.connect(DB_PATH)
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
        data = json.loads(resp.read().decode("utf-8"))
    if data.get("status") != "success":
        return {}
    return {"country": data.get("country") or "unknown",
            "org": data.get("org") or "unknown",
            "proxy": bool(data.get("proxy")),
            "hosting": bool(data.get("hosting"))}


def lookup_ip(ip):
    """Return enrichment dict for ip, or {} when unavailable.

    Cached in SQLite for 24h; never raises.
    """
    try:
        conn = _db()
        row = conn.execute(
            "SELECT country, org, proxy, hosting, fetched_at "
            "FROM ip_intel WHERE ip = ?", (ip,)).fetchone()
        if row and time.time() - row[4] < CACHE_TTL:
            conn.close()
            return {"country": row[0], "org": row[1],
                    "proxy": bool(row[2]), "hosting": bool(row[3])}
        intel = _fetch(ip)
        if intel:
            conn.execute(
                "INSERT OR REPLACE INTO ip_intel "
                "(ip, country, org, proxy, hosting, fetched_at) "
                "VALUES (?,?,?,?,?,?)",
                (ip, intel["country"], intel["org"],
                 int(intel["proxy"]), int(intel["hosting"]), time.time()))
            conn.commit()
        conn.close()
        return intel
    except Exception:
        return {}


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
