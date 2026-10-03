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
  device_profiles  per-MAC, per-hour behavior baselines (bytes/contacts)
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

CREATE TABLE IF NOT EXISTS device_profiles(
    mac TEXT NOT NULL,           -- lowercased hardware address
    hour INTEGER NOT NULL,       -- local hour of day, 0..23
    avg_bytes REAL NOT NULL,     -- average bytes moved in that hour
    avg_contacts REAL NOT NULL,  -- average distinct outside IPs in that hour
    days INTEGER NOT NULL,       -- distinct days behind this row
    built_ts REAL,
    PRIMARY KEY(mac, hour)
);

CREATE TABLE IF NOT EXISTS allowlist(
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,          -- alert kind this entry suppresses
    pattern TEXT NOT NULL,       -- case-insensitive substring match
    note TEXT,
    created_ts REAL
);

CREATE TABLE IF NOT EXISTS dismissal_lessons(
    kind TEXT NOT NULL,          -- alert kind that was dismissed
    pattern TEXT NOT NULL,       -- stable token learned from the dismissal
    dismissals INTEGER NOT NULL DEFAULT 0,  -- times this (kind, pattern) was dismissed
    sev TEXT,                    -- highest severity dismissed for it (Low|Medium|High|Critical)
    last_ts REAL,
    PRIMARY KEY(kind, pattern)
);

CREATE TABLE IF NOT EXISTS suggestions(
    id INTEGER PRIMARY KEY,
    kind TEXT NOT NULL,          -- alert kind the suggestion would silence
    pattern TEXT NOT NULL,       -- proposed allowlist pattern
    broad INTEGER NOT NULL DEFAULT 0,  -- 1 if the pattern is the whole rule
    why TEXT,                    -- plain-English reason for the human
    status TEXT NOT NULL DEFAULT 'pending',  -- pending | applied | ignored
    created_ts REAL,
    decided_ts REAL,
    UNIQUE(kind, pattern)
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
    # Dismissal-learning tables (Phase 3.5): older DBs get the sev column
    # and the allowlist uniqueness index below.
    lesson_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(dismissal_lessons)")}
    if "sev" not in lesson_cols:
        conn.execute("ALTER TABLE dismissal_lessons ADD COLUMN sev TEXT")
    try:
        # De-dupe any legacy rows first so the index always builds.
        conn.execute("DELETE FROM allowlist WHERE id NOT IN"
                     " (SELECT MIN(id) FROM allowlist"
                     " GROUP BY kind, pattern)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS"
                     " idx_allowlist_kind_pattern ON allowlist(kind, pattern)")
    except Exception:
        pass  # belt and suspenders: allowlist dedupe is hygiene, not load-bearing
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


# --- behavior profiles -------------------------------------------------
# Per-device "what's normal": for each MAC and each local hour of the day,
# the average bytes moved and the average number of distinct outside IPs
# contacted, learned from the last two weeks of flows. Quiet devices get a
# tiny baseline (so they never fire); deviations need a high absolute floor
# too, so a phone that usually sits idle can't page over 300 MB.
# The detector rebuilds these lazily when the build watermark is stale
# (>6h) -- "quiet is a feature", so stale by a few hours is fine.

PROFILES_LEARN_DAYS = 14  # window of flow history the profiles learn from
PROFILES_MIN_DAYS = 3     # a profile hour is trusted only with this many
PROFILE_MAX_AGE = 6 * 3600  # rebuild when the watermark is older than this


def ip_to_mac_map():
    """{local ip: mac} using each IP's most recently observed MAC."""
    with _lock:
        conn = _db()
        latest = {}
        for ip, mac, ts in conn.execute(
                "SELECT ip, mac, MAX(ts) FROM arp_observations"
                " WHERE ip IS NOT NULL AND mac IS NOT NULL AND mac != ''"
                " GROUP BY ip, mac"):
            if ip not in latest or ts > latest[ip][1]:
                latest[ip] = (mac, ts)
        return {ip: mac for ip, (mac, _ts) in latest.items()}


def build_device_profiles(now=None, days=PROFILES_LEARN_DAYS):
    """Learn per-MAC, per-hour baselines from recent flows.

    Attributes each flow to the LAN-side IP's MAC (the non-LAN side of an
    outbound flow is usually an outside address; for inbound it's the
    reverse). Counts only bytes -- direction is irrelevant for "how much
    did this device normally move at 8pm".
    """
    import ipaddress
    import time
    now = now if now is not None else time.time()
    cutoff = now - days * 86400
    ip2mac = ip_to_mac_map()

    def _lan_mac(src_ip, dst_ip):
        if src_ip in ip2mac:
            return ip2mac[src_ip], (dst_ip if dst_ip not in ip2mac else None)
        if dst_ip in ip2mac:
            return ip2mac[dst_ip], (src_ip if src_ip not in ip2mac else None)
        return None, None

    per_hour = {}  # (mac, hour, daykey) -> [bytes, {outside ips}]
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT ts, src_ip, dst_ip, bytes FROM flows WHERE ts > ?",
            (cutoff,)).fetchall()

    for ts, src_ip, dst_ip, nbytes in rows:
        mac, outside = _lan_mac(src_ip, dst_ip)
        if not mac:
            continue
        lt = time.localtime(ts)
        key = (mac, lt.tm_hour, f"{lt.tm_year}-{lt.tm_mon}-{lt.tm_mday}")
        cell = per_hour.setdefault(key, [0, set()])
        cell[0] += (nbytes or 0)
        if outside:
            try:
                if ipaddress.ip_address(outside).is_global:
                    cell[1].add(outside)
            except ValueError:
                pass

    agg = {}  # (mac, hour) -> [total_bytes, set-of-outside-ips, {daykeys}]
    for (mac, hour, daykey), (nbytes, contacts) in per_hour.items():
        cell = agg.setdefault((mac, hour), [0, set(), set()])
        cell[0] += nbytes
        cell[1] |= contacts
        cell[2].add(daykey)

    with _lock:
        conn = _db()
        conn.execute("DELETE FROM device_profiles")
        for (mac, hour), (total, contacts, daykeys) in agg.items():
            ndays = len(daykeys)
            if ndays < 1:
                continue
            conn.execute(
                "INSERT INTO device_profiles"
                " (mac, hour, avg_bytes, avg_contacts, days, built_ts)"
                " VALUES (?,?,?,?,?,?)",
                (mac, hour, total / ndays, len(contacts) / ndays, ndays,
                 now))
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('profiles_built_ts', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(now),))
        conn.commit()
    return len(agg)


def device_profiles_stale(now=None, max_age=PROFILE_MAX_AGE):
    """True when the behavior profiles need a rebuild."""
    import time
    now = now if now is not None else time.time()
    raw = get_meta("profiles_built_ts")
    try:
        built = float(raw) if raw else 0
    except (TypeError, ValueError):
        built = 0
    return (now - built) > max_age


def get_device_profile(mac, hour):
    """Baseline row for one MAC at one local hour, or None."""
    mac = (mac or "").strip().lower()
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT avg_bytes, avg_contacts, days FROM device_profiles"
            " WHERE mac=? AND hour=?", (mac, hour)).fetchone()
    if not row:
        return None
    return {"avg_bytes": row[0], "avg_contacts": row[1], "days": row[2]}


def device_profile_summaries():
    """Compact per-MAC profile for the dashboard devices table.

    Returns {mac: {hours_covered, avg_mb_per_hr, days, busy}} where busy is
    plain text like "8-9pm" for the three busiest hours.
    """
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT mac, hour, avg_bytes, days FROM device_profiles"
            " ORDER BY mac, avg_bytes DESC").fetchall()
    out = {}
    for mac, hour, avg_bytes, days in rows:
        cell = out.setdefault(
            mac, {"hours_covered": 0, "total_bytes": 0.0,
                  "days": 0, "busy": []})
        cell["hours_covered"] += 1
        cell["total_bytes"] += avg_bytes
        cell["days"] = max(cell["days"], days)
        if len(cell["busy"]) < 3:
            cell["busy"].append(hour)

    def _hour_text(h):
        if h == 0:
            return "12-1am"
        if h < 12:
            return f"{h}-{h+1}am"
        if h == 12:
            return "12-1pm"
        return f"{h-12}-{h-11}pm"

    return {mac: {
        "hours_covered": c["hours_covered"],
        "avg_mb_per_hr": round(c["total_bytes"] / max(c["hours_covered"], 1)
                               / 1e6, 1),
        "days": c["days"],
        "busy": ", ".join(_hour_text(h) for h in c["busy"]),
    } for mac, c in out.items()}


def device_first_seen(mac):
    """Earliest ARP sighting of a MAC (device join time), or None."""
    mac = (mac or "").strip().lower()
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT MIN(ts) FROM arp_observations WHERE mac=?",
            (mac,)).fetchone()
    return row[0] if row and row[0] else None
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
    """Add an allowlist entry; returns its id. Idempotent on
    (kind, pattern): a duplicate add returns the existing row's id."""
    import time
    kind = (kind or "").strip()
    pattern = (pattern or "").strip()
    if not kind or not pattern:
        raise ValueError("kind and pattern are required")
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO allowlist (kind, pattern, note, created_ts)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(kind, pattern) DO NOTHING",
            (kind, pattern[:200], (note or "").strip()[:200],
             time.time()))
        conn.commit()
        row = conn.execute(
            "SELECT id FROM allowlist WHERE kind=? AND pattern=?",
            (kind, pattern[:200])).fetchone()
        return row[0] if row else None


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
    (case-insensitive substring match). A pattern equal to the kind
    name itself is a whole-rule wildcard (used for broad suggestions)."""
    text = (text or "").lower()
    kind = (kind or "").lower()
    if not text:
        return False
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT pattern FROM allowlist WHERE kind=?", (kind,)).fetchall()
    for (p,) in rows:
        p = (p or "").lower()
        if not p:
            continue
        if p == kind:
            return True  # whole-rule wildcard
        if p in text:
            return True
    return False


# --- learning from dismissals --------------------------------------------
# Dismissing an alert teaches the monitor. Patterns extracted from
# dismissed alerts (see netmon/learn.py) are counted; at threshold a
# pending suggestion appears on the dashboard, and only the human's
# Apply click writes the allowlist row.


def learn_from_dismissal(alert_id):
    """Record one dismissal; maybe create a pending suggestion.

    Loads the alert, extracts its pattern via netmon.learn, bumps the
    (kind, pattern) counter atomically, and creates a suggestion when the
    policy says so. Returns the suggestion dict, or None. Never raises: a
    learning failure must not break dismissing, but it is logged and the
    half-open transaction is rolled back so the shared connection stays
    clean for the next caller.
    """
    import sys as _sys
    import time
    try:
        from . import learn as learnm
    except Exception:
        return None
    try:
        with _lock:
            conn = _db()
            row = conn.execute(
                "SELECT kind, severity, title, detail FROM alerts"
                " WHERE id=?", (alert_id,)).fetchone()
        if not row:
            return None
        kind, severity, title, detail = row
        kind = (kind or "").strip()
        alert = {"kind": kind, "severity": severity,
                 "title": title, "detail": detail}
        pattern, broad = learnm.extract_pattern(alert)
        pattern = (pattern or "").strip()
        if not kind or not pattern:
            return None  # nothing stable to learn from
        now = time.time()
        sev = (severity or "Medium").strip()
        # One lock, atomic single-statement upserts: safe in-process and
        # across processes (WAL), no read-modify-write in Python.
        with _lock:
            conn = _db()
            # Atomic increment; sev tracks the highest severity dismissed,
            # so the suggestion threshold uses the most demanding one seen.
            cur = conn.execute(
                "INSERT INTO dismissal_lessons (kind, pattern, dismissals,"
                " sev, last_ts) VALUES (?,?,1,?,?)"
                " ON CONFLICT(kind, pattern) DO UPDATE SET"
                " dismissals = dismissal_lessons.dismissals + 1,"
                " sev = CASE WHEN dismissal_lessons.sev IS NULL THEN excluded.sev"
                "          WHEN excluded.sev IN ('High','Critical')"
                "           AND dismissal_lessons.sev NOT IN ('High','Critical')"
                "          THEN excluded.sev"
                "          WHEN excluded.sev = 'Critical'"
                "           AND dismissal_lessons.sev != 'Critical'"
                "          THEN excluded.sev"
                "          ELSE dismissal_lessons.sev END,"
                " last_ts = excluded.last_ts"
                " RETURNING dismissals, sev",
                (kind, pattern, sev, now)).fetchone()
            dismissals, max_sev = cur[0], (cur[1] or "Medium")
            threshold = learnm.threshold_for(max_sev)
            if dismissals < threshold:
                conn.commit()
                return None
            srow = conn.execute(
                "SELECT 1 FROM suggestions WHERE kind=? AND pattern=?"
                " LIMIT 1", (kind, pattern)).fetchone()
            if srow:
                conn.commit()
                return None
            why = learnm.why_text(kind, pattern, broad, dismissals, max_sev)
            ins = conn.execute(
                "INSERT INTO suggestions (kind, pattern, broad, why,"
                " status, created_ts) VALUES (?,?,?,?,'pending',?)"
                " ON CONFLICT(kind, pattern) DO NOTHING",
                (kind, pattern, 1 if broad else 0, why, now))
            conn.commit()
            if ins.rowcount == 0:
                return None  # lost a race with another process; it exists now
            sug = conn.execute(
                "SELECT id FROM suggestions WHERE kind=? AND pattern=?",
                (kind, pattern)).fetchone()
            return {"id": sug[0] if sug else None, "kind": kind,
                    "pattern": pattern, "broad": bool(broad), "why": why,
                    "status": "pending"}
    except Exception as exc:
        try:
            _db().rollback()
        except Exception:
            pass
        print(f"netmon learn: learn_from_dismissal failed: {exc!r}",
              file=_sys.stderr)
        return None


def list_suggestions(status="pending"):
    """Suggestions awaiting (or past) a human decision, newest first."""
    with _lock:
        conn = _db()
        return [
            {"id": i, "kind": k, "pattern": p, "broad": bool(b),
             "why": w or "", "status": s, "created_ts": t}
            for i, k, p, b, w, s, t in conn.execute(
                "SELECT id, kind, pattern, broad, why, status, created_ts"
                " FROM suggestions WHERE status=? ORDER BY created_ts DESC",
                (status,))]


def decide_suggestion(sid, decision):
    """Apply or ignore a suggestion. Applying writes the allowlist row
    (the human's one click is the only thing that ever silences alerts).
    Returns True on success."""
    import time
    if decision not in ("applied", "ignored"):
        raise ValueError(f"bad decision: {decision!r}")
    with _lock:
        conn = _db()
        try:
            row = conn.execute(
                "SELECT kind, pattern, status FROM suggestions WHERE id=?",
                (sid,)).fetchone()
            if not row or row[2] != "pending":
                conn.rollback()
                return False
            kind, pattern = (row[0] or "").strip(), (row[1] or "").strip()
            if decision == "applied" and (not kind or not pattern):
                conn.rollback()
                return False  # mirrors the manual add route's validation
            conn.execute(
                "UPDATE suggestions SET status=?, decided_ts=? WHERE id=?",
                (decision, time.time(), sid))
            if decision == "applied":
                conn.execute(
                    "INSERT INTO allowlist (kind, pattern, note, created_ts)"
                    " VALUES (?,?,?,?)",
                    (kind, pattern,
                     f"Suggested after repeated dismissals; applied by owner.",
                     time.time()))
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            return False
    return True


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

