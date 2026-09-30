"""netmon/db.py -- SQLite storage for the network monitor.

Four tables:
  flows      per-flush flow records (5-tuple + packet/byte counts)
  alerts     detection findings (port scans, spikes, odd ports, ...)
  outages    connection-drop windows from the watchdog
  summaries  AI/plain-English explanations of recent activity

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
    conn.commit()
    return conn


_conn = None


def _db():
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


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
    """
    import time
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO alerts (ts, kind, severity, title, detail,"
            " meaning, is_normal, what_to_do)"
            " VALUES (?,?,?,?,?,?,?,?)",
            (ts if ts is not None else time.time(), kind, severity,
             title, detail, meaning, is_normal, what_to_do),
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
