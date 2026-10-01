"""netmon/db.py -- SQLite storage for the network monitor.

Tables:
  flows      per-flush flow records (5-tuple + packet/byte counts)
  alerts     detection findings (port scans, spikes, odd ports, ...)
  outages    connection-drop windows from the watchdog
  summaries  AI/plain-English explanations of recent activity
  dns_queries  observed outbound DNS lookups (ts, name, qtype)
  arp_observations  (ip, mac) pairs seen on the wire (ts, ip, mac)
  first_seen  first-seen timestamps keyed by (kind, key)
  device_names  user-chosen friendly names keyed by MAC
  allowlist  user-approved (kind, pattern) pairs that suppress alerts
  meta        small key/value store (heartbeats, watermarks, ...)

All writers take the module lock; SQLite runs in WAL mode so the
dashboard can read while capture threads write.
"""
import json
import os
import sqlite3
import threading

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "netmon.db")

_lock = threading.Lock()

_SCHEMA = """
CREATE TABLE IF NOT EXISTS flows(
    id INTEGER PRIMARY KEY,
    ts REAL,                 -- flush bucket time (unix epoch)
    src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER, proto TEXT,
    packets INTEGER, bytes INTEGER,
    direction TEXT           -- outbound | inbound | local
);
CREATE INDEX IF NOT EXISTS idx_flows_ts ON flows(ts);
CREATE INDEX IF NOT EXISTS idx_flows_dir ON flows(direction);

CREATE TABLE IF NOT EXISTS alerts(
    id INTEGER PRIMARY KEY,
    ts REAL,
    kind TEXT,               -- port_scan | unusual_port | traffic_spike | ...
    severity TEXT,           -- Low | Medium | High | Critical
    title TEXT,
    detail TEXT,
    meaning TEXT,            -- plain-English: what this means
    is_normal TEXT,          -- plain-English: when this is fine vs not
    what_to_do TEXT          -- plain-English: one concrete next step
);
CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);

CREATE TABLE IF NOT EXISTS outages(
    id INTEGER PRIMARY KEY,
    target TEXT,             -- e.g. "gateway (192.168.1.1)"
    start_ts REAL,
    end_ts REAL,             -- NULL while the outage is ongoing
    gap_seconds REAL         -- filled when the outage ends
);

CREATE TABLE IF NOT EXISTS summaries(
    id INTEGER PRIMARY KEY,
    ts REAL,
    window_min INTEGER,
    headline TEXT,
    whats_happening TEXT,
    stands_out TEXT,         -- JSON list of strings
    suggested_actions TEXT,  -- JSON list of strings
    origin TEXT              -- llm | rule-based
);

CREATE TABLE IF NOT EXISTS dns_queries(
    id INTEGER PRIMARY KEY,
    ts REAL,
    name TEXT,               -- queried name, trailing dot stripped
    qtype TEXT               -- DNS query type (e.g. 1 = A, 28 = AAAA)
);
CREATE INDEX IF NOT EXISTS idx_dns_ts ON dns_queries(ts);

CREATE TABLE IF NOT EXISTS arp_observations(
    id INTEGER PRIMARY KEY,
    ts REAL,
    ip TEXT,
    mac TEXT                 -- source MAC observed for this IP
);
CREATE INDEX IF NOT EXISTS idx_arp_ts ON arp_observations(ts);

CREATE TABLE IF NOT EXISTS first_seen(
    kind TEXT,
    key TEXT,
    first_ts REAL,
    PRIMARY KEY(kind, key)
);

CREATE TABLE IF NOT EXISTS device_names(
    mac TEXT PRIMARY KEY,        -- lowercased hardware address
    name TEXT NOT NULL,          -- user-chosen friendly name ("PS5")
    updated_ts REAL
);

CREATE TABLE IF NOT EXISTS allowlist(
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,          -- alert kind this entry suppresses
    pattern TEXT NOT NULL,       -- case-insensitive substring match
    note TEXT,
    created_ts REAL
);

CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT
);
"""


def _connect():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, timeout=30)
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(_SCHEMA)
    # Migrate older databases that lack the plain-English alert columns.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    for col in ("meaning", "is_normal", "what_to_do"):
        if col not in cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
    if "status" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN status TEXT DEFAULT 'new'")
    if "note" not in cols:
        conn.execute("ALTER TABLE alerts ADD COLUMN note TEXT")
    # Migrate older databases whose dns_queries lack the querier IP
    # (needed to attribute DNS anomalies per device in whole-network mode).
    dns_cols = {r[1] for r in conn.execute("PRAGMA table_info(dns_queries)")}
    if "src_ip" not in dns_cols:
        conn.execute("ALTER TABLE dns_queries ADD COLUMN src_ip TEXT")
    conn.commit()
    return conn


_conn = None


def _db():
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


def _notify_hook(alert_dict):
    """Best-effort notification fan-out after an alert is stored.

    The notify module is maintained separately; if it's missing, broken,
    or sending fails, alerting itself must never break. This hook is
    always called outside the module lock.
    """
    try:
        from . import notify
        notify.maybe_send_alert(alert_dict)
    except Exception:
        pass


def insert_flows(rows):
    """rows: list of (ts, src_ip, dst_ip, src_port, dst_port, proto,
    packets, bytes, direction)."""
    if not rows:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO flows (ts, src_ip, dst_ip, src_port, dst_port,"
            " proto, packets, bytes, direction)"
            " VALUES (?,?,?,?,?,?,?,?,?)",
            rows,
        )
        conn.commit()


def add_alert(kind, severity, title, detail, meaning="", is_normal="",
              what_to_do="", ts=None):
    """Store a detection finding.

    meaning / is_normal / what_to_do are plain-English fields written for
    non-technical readers: what this means, when it's fine vs not, and one
    concrete next step.

    After the row is committed, a best-effort notification hook fires
    (outside the lock); it can never break or delay alert storage.
    """
    import time
    ts = ts if ts is not None else time.time()
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO alerts (ts, kind, severity, title, detail,"
            " meaning, is_normal, what_to_do)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ts, kind, severity, title, detail, meaning, is_normal,
             what_to_do),
        )
        alert_id = cur.lastrowid
        conn.commit()
    _notify_hook({
        "id": alert_id, "ts": ts, "kind": kind, "severity": severity,
        "title": title, "detail": detail, "meaning": meaning,
        "is_normal": is_normal, "what_to_do": what_to_do,
        "status": "new", "note": None,
    })
    return alert_id


def insert_dns_queries(rows):
    """rows: list of (ts, src_ip, name, qtype) tuples for observed DNS lookups.

    qtype may be an int (e.g. 1) or a str; it is stored as text."""
    if not rows:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO dns_queries (ts, src_ip, name, qtype) VALUES (?,?,?,?)",
            [(ts, src_ip, name, str(qtype)) for ts, src_ip, name, qtype in rows],
        )
        conn.commit()


def insert_arp_observations(rows):
    """rows: list of (ts, ip, mac) tuples for observed IP/MAC pairs."""
    if not rows:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO arp_observations (ts, ip, mac) VALUES (?,?,?)",
            rows,
        )
        conn.commit()


def get_first_seen(kind, key):
    """First timestamp ever recorded for (kind, key), or None."""
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT first_ts FROM first_seen WHERE kind=? AND key=?",
            (kind, key),
        ).fetchone()
        return row[0] if row else None


def note_first_seen(kind, key, ts):
    """Record the first-seen timestamp for (kind, key); keeps the
    earliest value if one is already stored."""
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT OR IGNORE INTO first_seen (kind, key, first_ts)"
            " VALUES (?,?,?)",
            (kind, key, ts),
        )
        conn.commit()


def set_meta(key, value):
    """Store a small key/value fact (heartbeats, watermarks, ...)."""
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?,?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )
        conn.commit()


def get_meta(key):
    """Stored value for `key`, or None."""
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)
        ).fetchone()
        return row[0] if row else None


# --- device names ------------------------------------------------------
# Friendly names ("PS5", "Mom's iPhone") keyed by MAC so alerts and tables
# read like English instead of hardware addresses.


def set_device_name(mac, name):
    """Name (or rename) a device by MAC. An empty name clears it."""
    import time
    mac = (mac or "").strip().lower()
    name = (name or "").strip()
    if not mac:
        raise ValueError("mac is required")
    with _lock:
        conn = _db()
        if name:
            conn.execute(
                "INSERT INTO device_names (mac, name, updated_ts)"
                " VALUES (?,?,?)"
                " ON CONFLICT(mac) DO UPDATE SET name=excluded.name,"
                " updated_ts=excluded.updated_ts",
                (mac, name[:40], time.time()))
        else:
            conn.execute("DELETE FROM device_names WHERE mac=?", (mac,))
        conn.commit()


def device_name_map():
    """{mac: name} for every named device."""
    with _lock:
        conn = _db()
        return {m: n for m, n in conn.execute(
            "SELECT mac, name FROM device_names")}


def known_devices(limit=100):
    """Devices ever seen on the LAN, newest first.

    Returns [{mac, name, last_ip, last_seen, first_seen}];
    name is "" when unnamed.
    """
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT mac, MAX(ts), MIN(ts) FROM arp_observations"
            " WHERE mac IS NOT NULL AND mac != ''"
            " GROUP BY mac ORDER BY MAX(ts) DESC LIMIT ?",
            (limit,)).fetchall()
        out = []
        for mac, last_seen, first_seen in rows:
            iprow = conn.execute(
                "SELECT ip FROM arp_observations WHERE mac=?"
                " ORDER BY ts DESC LIMIT 1", (mac,)).fetchone()
            nmrow = conn.execute(
                "SELECT name FROM device_names WHERE mac=?",
                (mac,)).fetchone()
            out.append({
                "mac": mac,
                "name": nmrow[0] if nmrow else "",
                "last_ip": iprow[0] if iprow and iprow[0] else "",
                "last_seen": last_seen,
                "first_seen": first_seen,
            })
        return out


def ip_name_map():
    """{local ip: device name} using each IP's most recent MAC."""
    latest = {}
    for ip, mac, ts in query(
            "SELECT ip, mac, MAX(ts) FROM arp_observations"
            " WHERE ip IS NOT NULL AND mac IS NOT NULL AND mac != ''"
            " GROUP BY ip, mac"):
        if ip not in latest or ts > latest[ip][1]:
            latest[ip] = (mac, ts)
    names = device_name_map()
    return {ip: names[mac] for ip, (mac, _ts) in latest.items()
            if mac in names}


# --- quiet hours -------------------------------------------------------
# Email silencing windows, stored as a JSON list in meta under
# "quiet_hours". Each window: {days:[0..6 Mon..Sun], start:"HH:MM",
# end:"HH:MM", kinds:["all"] or [alert kinds]}.
def get_quiet_hours():
    """List of quiet-window dicts, or []."""
    raw = get_meta("quiet_hours")
    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def set_quiet_hours(windows):
    """Persist quiet windows (a list of dicts; validated by callers)."""
    if not isinstance(windows, list):
        raise ValueError("quiet hours must be a list")
    set_meta("quiet_hours", json.dumps(windows))

# --- allowlist ---------------------------------------------------------
# (kind, pattern) pairs the user approved: matching alerts never fire.
# Pattern is a case-insensitive substring matched against the alert's
# identifying text (e.g. a MAC, an "ip:port" key, a domain).

def add_allowlist(kind, pattern, note=""):
    """Add an allowlist entry; returns its id."""
    import time
    kind = (kind or "").strip()
    pattern = (pattern or "").strip()
    if not kind or not pattern:
        raise ValueError("kind and pattern are required")
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO allowlist (kind, pattern, note, created_ts)"
            " VALUES (?,?,?,?)",
            (kind, pattern[:200], (note or "").strip()[:200],
             time.time()))
        conn.commit()
        return cur.lastrowid


def remove_allowlist(entry_id):
    with _lock:
        conn = _db()
        conn.execute("DELETE FROM allowlist WHERE id=?", (entry_id,))
        conn.commit()


def list_allowlist():
    with _lock:
        conn = _db()
        return [
            {"id": i, "kind": k, "pattern": p, "note": n or "",
             "created_ts": t}
            for i, k, p, n, t in conn.execute(
                "SELECT id, kind, pattern, note, created_ts FROM allowlist"
                " ORDER BY kind, pattern")]


def is_allowlisted(kind, text):
    """True if any allowlist pattern for this kind appears in text
    (case-insensitive substring match)."""
    text = (text or "").lower()
    if not text:
        return False
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT pattern FROM allowlist WHERE kind=?", (kind,)).fetchall()
    return any((p or "").lower() in text for (p,) in rows if p)


def set_alert_status(alert_id, status, note=None):
    """Mark an alert 'new' | 'acknowledged' | 'dismissed', with an
    optional human note."""
    if status not in ("new", "acknowledged", "dismissed"):
        raise ValueError(f"bad alert status: {status!r}")
    with _lock:
        conn = _db()
        conn.execute(
            "UPDATE alerts SET status=?, note=? WHERE id=?",
            (status, note, alert_id),
        )
        conn.commit()


def recent_alert_kind(kind, key, within_s):
    """True if an alert of this kind mentioning `key` fired recently
    (cooldown so we don't spam the alerts table)."""
    import time
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE kind=? AND detail LIKE ?"
            " AND ts > ? LIMIT 1",
            (kind, f"%{key}%", time.time() - within_s),
        ).fetchone()
        return row is not None


def start_outage(target, ts):
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO outages (target, start_ts) VALUES (?,?)",
            (target, ts),
        )
        conn.commit()
        return cur.lastrowid


def end_outage(outage_id, end_ts):
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT start_ts FROM outages WHERE id=?", (outage_id,)
        ).fetchone()
        if row:
            conn.execute(
                "UPDATE outages SET end_ts=?, gap_seconds=? WHERE id=?",
                (end_ts, end_ts - row[0], outage_id),
            )
            conn.commit()


def ongoing_outages():
    with _lock:
        conn = _db()
        return conn.execute(
            "SELECT id, target, start_ts FROM outages WHERE end_ts IS NULL"
        ).fetchall()


def save_summary(window_min, headline, whats_happening, stands_out,
                 suggested_actions, origin, ts=None):
    import time
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO summaries (ts, window_min, headline, whats_happening,"
            " stands_out, suggested_actions, origin)"
            " VALUES (?,?,?,?,?,?,?)",
            (ts if ts is not None else time.time(), window_min, headline,
             whats_happening, json.dumps(stands_out),
             json.dumps(suggested_actions), origin),
        )
        conn.commit()


def latest_summary():
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT ts, window_min, headline, whats_happening, stands_out,"
            " suggested_actions, origin FROM summaries"
            " ORDER BY ts DESC LIMIT 1"
        ).fetchone()
    if not row:
        return None
    return {
        "ts": row[0], "window_min": row[1], "headline": row[2],
        "whats_happening": row[3],
        "stands_out": json.loads(row[4] or "[]"),
        "suggested_actions": json.loads(row[5] or "[]"),
        "origin": row[6],
    }


def query(sql, params=()):
    """Read-only helper for the dashboard/explainer."""
    with _lock:
        conn = _db()
        return conn.execute(sql, params).fetchall()

