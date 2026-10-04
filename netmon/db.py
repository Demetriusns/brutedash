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
  dismissal_lessons  stable patterns learned from dismissed alerts
  suggestions  pending allowlist suggestions awaiting human approval
  incidents  cases bundling related alerts (Phase 3.5: incidents, not alerts)
  incident_alerts  which alerts belong to which incident
  assets  enriched device inventory (Phase 3.5: know the network)
  device_hostnames  DHCP/mDNS hostname observations
  device_ttl  last observed IP TTL per device IP (OS guess)
  scan_runs  self vulnerability scan runs (own LAN only)
  scan_findings  open ports found by self scans
  host_events  Windows Event Log + firewall log events (see INGEST.md)
  ingest_state  per-file read progress for log ingestion
  meta        small key/value store (heartbeats, watermarks, ...)
  ti_entries  local threat-intel blocklists (domains + IPs)

All writers take the module lock; SQLite runs in WAL mode so the
dashboard can read while capture threads write.
"""
import json
import os
import re
import sqlite3
import threading
import time
import contextlib
import uuid

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

-- Maintenance mode: one row, present only while active. While active,
-- detection keeps running but notifications (alert emails, digests,
-- the morning briefing) stay silent. until_ts NULL = until switched
-- off by hand; an expired until_ts auto-clears on read.
CREATE TABLE IF NOT EXISTS maintenance(
    id INTEGER PRIMARY KEY CHECK (id=1),
    on_ts REAL,                  -- when it was switched on
    until_ts REAL,               -- NULL = no auto end
    reason TEXT                  -- plain-English: "replacing the router"
);

-- Alert-fatigue circuit breaker: when one rule fires too often it is
-- auto-muted here. dropped firings are COUNTED (suppressed), never
-- silent: the mute notice alert + the dashboard panel show them.
CREATE TABLE IF NOT EXISTS rule_mutes(
    kind TEXT PRIMARY KEY,       -- alert kind being throttled
    muted_from REAL,              -- mute window start (unix epoch)
    muted_until REAL,             -- mute window end
    fired_count INTEGER,          -- alerts that tripped the breaker
    window_min INTEGER,           -- minutes those alerts fired inside
    suppressed INTEGER NOT NULL DEFAULT 0,  -- firings dropped since
    note TEXT
);

CREATE TABLE IF NOT EXISTS device_types(
    mac TEXT PRIMARY KEY,        -- lowercased hardware address
    dtype TEXT NOT NULL,         -- user-pinned device type (see topology.DEVICE_TYPES)
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

-- Phase 3.5: incidents, not alerts. Related alerts are bundled into one
-- case with a timeline, the way a senior analyst works.
CREATE TABLE IF NOT EXISTS incidents(
    id INTEGER PRIMARY KEY,
    created_ts REAL,
    updated_ts REAL,             -- last member alert attached
    title TEXT,                  -- e.g. "Suspicious activity involving 203.0.113.7"
    severity TEXT,               -- highest severity among member alerts
    status TEXT NOT NULL DEFAULT 'open',  -- open | escalated | closed
    device_key TEXT,             -- IP tying the case together (may be NULL)
    summary TEXT                 -- plain-English one-liner
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);
CREATE INDEX IF NOT EXISTS idx_incidents_device ON incidents(device_key);

CREATE TABLE IF NOT EXISTS incident_alerts(
    incident_id INTEGER NOT NULL,
    alert_id INTEGER PRIMARY KEY,  -- one alert belongs to at most one case
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_incident_alerts_inc ON incident_alerts(incident_id);

-- Phase 3.5 "know the network": asset inventory. Built by refresh_assets()
-- from arp_observations (MAC/IP/first/last seen), device_hostnames
-- (DHCP/mDNS names), device_ttl (OS guess), device_names (friendly name),
-- and scan_findings (open ports).
CREATE TABLE IF NOT EXISTS assets(
    mac TEXT PRIMARY KEY,      -- lowercased hardware address
    ip TEXT,                   -- most recent IP
    first_seen REAL,
    last_seen REAL,
    hostname TEXT,             -- from DHCP/mDNS, when observed
    hostname_source TEXT,      -- dhcp | mdns | ""
    os_guess TEXT,             -- TTL heuristic, may be ""
    vendor TEXT,               -- MAC OUI vendor, may be ""
    open_ports TEXT,           -- JSON list of {port, service, risk}
    updated_ts REAL
);

-- Raw hostname observations (DHCP option 12, mDNS .local names).
CREATE TABLE IF NOT EXISTS device_hostnames(
    id INTEGER PRIMARY KEY,
    ts REAL,
    mac TEXT,                  -- lowercased hardware address (may be "")
    ip TEXT,
    hostname TEXT,
    source TEXT                -- dhcp | mdns
);
CREATE INDEX IF NOT EXISTS idx_hostnames_ts ON device_hostnames(ts);

-- Last observed IP TTL per device IP (OS guess via TTL heuristics).
CREATE TABLE IF NOT EXISTS device_ttl(
    ip TEXT PRIMARY KEY,
    ttl INTEGER,
    updated_ts REAL
);

-- Phase 3.5 "know the network": self vulnerability scans of the LAN.
CREATE TABLE IF NOT EXISTS scan_runs(
    id INTEGER PRIMARY KEY,
    ts REAL,
    duration_s REAL,
    devices_scanned INTEGER,
    findings INTEGER,
    note TEXT
);

-- Open ports found by self scans. (source, ip, port) is the identity:
-- a port seen open in the latest run is 'open'; one that vanished is
-- 'resolved'. source is 'builtin' (the TCP connect scan) or 'template'
-- (a check from a YAML template in templates/) -- see netmon/scan.py.
CREATE TABLE IF NOT EXISTS scan_findings(
    id INTEGER PRIMARY KEY,
    run_ts REAL,               -- when the finding was recorded
    ip TEXT,
    mac TEXT,
    port INTEGER,
    service TEXT,
    risk TEXT,                 -- Low | Medium
    what_it_means TEXT,         -- plain-English explanation
    source TEXT NOT NULL DEFAULT 'builtin',  -- builtin | template
    status TEXT NOT NULL DEFAULT 'open',  -- open | resolved
    UNIQUE(source, ip, port)   -- current state: one row per door+source
);
CREATE INDEX IF NOT EXISTS idx_findings_status ON scan_findings(status);

-- Phase 3.5 "know the network": Windows Event Log + firewall log events
-- imported from exported logs (see INGEST.md).
CREATE TABLE IF NOT EXISTS host_events(
    id INTEGER PRIMARY KEY,
    ts REAL,
    source TEXT,               -- eventlog | firewall
    event_id TEXT,             -- e.g. "4625" or "DROP"
    computer TEXT,
    user_name TEXT,
    detail TEXT,
    matched_alert INTEGER      -- id of a correlated netmon alert, or NULL
);
CREATE INDEX IF NOT EXISTS idx_host_events_ts ON host_events(ts);

-- Ingest progress: per watched file, how far we've read (mtime for XML
-- exports which are rewritten wholesale; byte offset for append logs;
-- inode so a replaced-under-the-same-name log is re-read from the top).
CREATE TABLE IF NOT EXISTS ingest_state(
    path TEXT PRIMARY KEY,
    mtime REAL,
    offset INTEGER,
    last_run_ts REAL,
    inode INTEGER
);

CREATE TABLE IF NOT EXISTS meta(
    key TEXT PRIMARY KEY,
    value TEXT
);

-- Phase 3.5 "rap sheets": threat-intel feeds. ti_entries is the local
-- copy of community blocklists (phishing/malware domains + malicious
-- IPs); lookups hit this table first so they are fast and offline-capable.
-- Refreshed on a schedule by netmon/threatintel.py. Feed update
-- timestamps live in meta as ti_feed_updated_<feed>.
CREATE TABLE IF NOT EXISTS ti_entries(
    key TEXT NOT NULL,         -- domain (lowercased), IP string, or CVE id
    kind TEXT NOT NULL,        -- 'domain' | 'ip' | 'cve'
    feed TEXT NOT NULL,        -- which feed listed it
    detail TEXT,               -- reason/category from the feed
    first_seen REAL,           -- when we first saw it listed
    last_seen REAL,            -- when the listing was last confirmed
    PRIMARY KEY(key, kind, feed)
);
CREATE INDEX IF NOT EXISTS idx_ti_entries_kind_key ON ti_entries(kind, key);

-- External attack-surface mapping (netmon/amass.py, OWASP Amass):
-- amass_runs keeps the run history; amass_assets is the CURRENT state
-- (one row per domain/kind/value, upserted each run so diffing is a
-- set comparison against the previous state).
CREATE TABLE IF NOT EXISTS amass_runs(
    id INTEGER PRIMARY KEY,
    ts REAL,
    domain TEXT,               -- the configured root domain scanned
    duration_s REAL,
    subdomains INTEGER,
    ips INTEGER,
    note TEXT
);
CREATE TABLE IF NOT EXISTS amass_assets(
    domain TEXT NOT NULL,      -- the configured root domain
    kind TEXT NOT NULL,        -- 'subdomain' | 'ip' | 'asn'
    value TEXT NOT NULL,       -- the subdomain name, IP, or ASN
    detail TEXT,               -- small JSON blob: sources, tag, seen IPs
    first_seen REAL,           -- when we first discovered it
    last_seen REAL,            -- when the last run confirmed it
    PRIMARY KEY(domain, kind, value)
);
CREATE INDEX IF NOT EXISTS idx_amass_assets_domain ON amass_assets(domain);

-- Phase 3.5 "act, not just watch": one-click quarantine state. One row
-- per device MAC; state is 'active' (isolated right now) or 'released'
-- (isolation lifted). The ARP enforcement lives in netmon/quarantine.py;
-- this table is the durable record of what the human asked for.
CREATE TABLE IF NOT EXISTS quarantines(
    mac TEXT PRIMARY KEY,      -- lowercased hardware address
    ip TEXT,                   -- last known IP when isolated
    state TEXT NOT NULL DEFAULT 'active',  -- active | released
    created_ts REAL,
    updated_ts REAL,
    actor TEXT,                -- who clicked (e.g. "dashboard")
    note TEXT
);

-- Phase 3.5 "act, not just watch": audit log. APPEND-ONLY -- rows are
-- inserted by audit() and read by list_audit(); there is intentionally
-- no update or delete path anywhere in the codebase, so the trail of
-- who did what, when, cannot be rewritten after the fact.
CREATE TABLE IF NOT EXISTS audit_log(
    id INTEGER PRIMARY KEY,
    ts REAL,
    actor TEXT,                -- who did it (e.g. "dashboard")
    action TEXT,               -- quarantine | quarantine_refused | release
                               -- | escalate | escalate_failed | ...
    target TEXT,               -- MAC, incident id, or slug acted on
    detail TEXT                -- plain-English note, free text
);
CREATE INDEX IF NOT EXISTS idx_audit_log_ts ON audit_log(ts);
CREATE INDEX IF NOT EXISTS idx_audit_log_target ON audit_log(target);

-- Phase 3.5 "act, not just watch": escalations to the administrator.
-- One row per escalation attempt; sent_ok=0 means the email failed and
-- the case was NOT marked escalated (the state only moves on success).
CREATE TABLE IF NOT EXISTS escalations(
    id INTEGER PRIMARY KEY,
    incident_id INTEGER NOT NULL,
    ts REAL,
    actor TEXT,
    admin_email TEXT,
    subject TEXT,
    sent_ok INTEGER NOT NULL DEFAULT 0,
    FOREIGN KEY(incident_id) REFERENCES incidents(id)
);
CREATE INDEX IF NOT EXISTS idx_escalations_incident ON escalations(incident_id);

-- Phase 3.5 batch 11: Nuclei-powered self vulnerability scan. nuclei_runs
-- keeps the run history; nuclei_findings is the CURRENT state (one row
-- per ip/template/matched-URL, upserted each run so diffing is a set
-- comparison -- repeats stay quiet, first run is the silent baseline).
CREATE TABLE IF NOT EXISTS nuclei_runs(
    id INTEGER PRIMARY KEY,
    ts REAL,
    duration_s REAL,
    targets INTEGER,            -- LAN targets scanned
    findings INTEGER,           -- findings parsed from this run
    new_findings INTEGER,       -- genuinely new vs the previous state
    note TEXT
);
CREATE TABLE IF NOT EXISTS nuclei_findings(
    id INTEGER PRIMARY KEY,
    run_ts REAL,                -- when the finding was recorded
    ip TEXT,                    -- the LAN target scanned
    template_id TEXT,           -- e.g. http-missing-security-headers
    name TEXT,                  -- template name (plain words)
    severity TEXT,              -- our scale: High | Medium | Low
    matched_at TEXT,            -- the URL/endpoint that matched
    description TEXT,           -- template description (may be technical)
    cves TEXT,                  -- comma-separated CVE ids, may be ""
    status TEXT NOT NULL DEFAULT 'open',  -- open | resolved
    UNIQUE(ip, template_id, matched_at)
);
CREATE INDEX IF NOT EXISTS idx_nuclei_findings_status
    ON nuclei_findings(status);

-- Phase 3.5 batch 11: software inventory + CVE correlation (Wazuh pattern:
-- know what's installed, match it against the known-exploited list).
-- sw_inventory is the CURRENT inventory of the sensor box itself;
-- cve_matches records installed software with a KEV-listed flaw so we
-- alert exactly once per (package, CVE) -- quiet afterwards.
CREATE TABLE IF NOT EXISTS sw_inventory(
    name TEXT,                  -- package/app name as reported
    version TEXT,               -- installed version, may be ""
    source TEXT,                -- 'python' (venv) | 'os' (system packages)
    seen_ts REAL,
    PRIMARY KEY(name, source)
);
CREATE TABLE IF NOT EXISTS cve_matches(
    id INTEGER PRIMARY KEY,
    ts REAL,                    -- when the match was first seen
    package TEXT,               -- inventory name as seen
    version TEXT,               -- installed version at match time
    source TEXT,                -- 'python' | 'os'
    cve_id TEXT,                -- e.g. CVE-2024-1234
    vendor TEXT,
    product TEXT,
    vuln_name TEXT,
    description TEXT,
    due_date TEXT,              -- CISA's fix-by date, may be ""
    UNIQUE(package, cve_id)
);

-- Phase 3.5 "prove it": daily security score snapshots for the trend.
CREATE TABLE IF NOT EXISTS score_snapshots(
    day TEXT PRIMARY KEY,       -- YYYY-MM-DD, local time
    ts REAL,                    -- when the snapshot was recorded
    score INTEGER,              -- 0..100, NULL = not enough data that day
    factors TEXT                -- JSON list of the top contributing factors
);
"""


# --- reconnecting connection ------------------------------------------------
# Council review (robustness): the app ran on a single shared sqlite
# connection with no reconnect -- one dead handle (closed connection,
# disk hiccup, "unable to open database file") wedged everything until
# restart. _ReconnectingConnection proxies the raw connection and
# retries the failed operation exactly once on a fresh connection when
# the error signals a dead connection. Lock contention ("database is
# locked") is NOT retried here -- _write_with_retry owns that path.
# After an explicit close() (isolated_db teardown) it stays closed.

class _ReconnectingConnection:
    _DEAD_MARKERS = ("unable to open database file", "disk i/o error",
                     "file is not a database")

    def __init__(self, factory):
        self._factory = factory
        self._relock = threading.Lock()
        self._closed = False
        self._conn = factory()

    def _reconnect(self):
        with self._relock:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = self._factory()

    def _is_dead_error(self, exc):
        if isinstance(exc, sqlite3.ProgrammingError):
            return "closed" in str(exc).lower()
        return (isinstance(exc, sqlite3.OperationalError)
                and any(m in str(exc).lower()
                        for m in self._DEAD_MARKERS))

    def _run(self, method, *args, **kwargs):
        try:
            return getattr(self._conn, method)(*args, **kwargs)
        except Exception as exc:
            if self._closed or not self._is_dead_error(exc):
                raise
            self._reconnect()
            return getattr(self._conn, method)(*args, **kwargs)

    def execute(self, *a, **k):
        return self._run("execute", *a, **k)

    def executemany(self, *a, **k):
        return self._run("executemany", *a, **k)

    def executescript(self, *a, **k):
        return self._run("executescript", *a, **k)

    def commit(self, *a, **k):
        return self._run("commit", *a, **k)

    def rollback(self, *a, **k):
        return self._run("rollback", *a, **k)

    def close(self):
        self._closed = True
        try:
            self._conn.close()
        except Exception:
            pass

    def __getattr__(self, name):
        # cursor(), row_factory, isolation_level, ... delegate to the
        # live connection. __getattr__ only fires when normal lookup
        # fails, so _conn/_factory/_relock/_closed resolve directly.
        if name.startswith("_"):
            raise AttributeError(name)
        return getattr(self.__dict__["_conn"], name)


def _connect_raw(path=None):
    path = path or DB_PATH
    conn = sqlite3.connect(path, check_same_thread=False, timeout=30)
    # Council review: the DB holds DNS query history, flow records, and
    # device names (household browsing) -- not world-readable. Fix up both
    # fresh files and pre-existing ones whose perms predate this guard.
    try:
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, 0o600)
    except OSError:
        pass
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.executescript(_SCHEMA)
    # Migrate older databases that lack the plain-English alert columns.
    cols = {r[1] for r in conn.execute("PRAGMA table_info(alerts)")}
    for col in ("meaning", "is_normal", "what_to_do", "trace_id"):
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
    # Council review: ingest_state gains an `inode` column so a .log file
    # replaced wholesale under the same name is re-read from the top
    # instead of silently skipping its head at a stale byte offset.
    try:
        istate_cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(ingest_state)")}
        if "inode" not in istate_cols:
            conn.execute("ALTER TABLE ingest_state ADD COLUMN inode INTEGER")
    except Exception:
        pass  # ingest progress is bookkeeping; never break startup over it
    # Phase 3.5: MITRE ATT&CK tags on alerts. Backfill existing rows from
    # the static kind->technique map so old alerts read the same language.
    for col in ("mitre_id", "mitre_name", "mitre_tactic"):
        if col not in cols:
            conn.execute(f"ALTER TABLE alerts ADD COLUMN {col} TEXT")
    try:
        from . import mitre as _mitre_mod
        needs_backfill = conn.execute(
            "SELECT 1 FROM alerts WHERE mitre_id IS NULL LIMIT 1").fetchone()
        if needs_backfill:
            for kind in _mitre_mod.all_kinds():
                tag = _mitre_mod.tag_for(kind)
                conn.execute(
                    "UPDATE alerts SET mitre_id=?, mitre_name=?,"
                    " mitre_tactic=? WHERE kind=? AND mitre_id IS NULL",
                    (tag["id"], tag["name"], tag["tactic"], kind))
    except Exception:
        pass  # tags are display metadata; never break startup over them
    # Pipeline robustness (batch 14): trace ids. incident_alerts carries
    # the member alert's trace id so one detection can be followed
    # alert -> incident -> notification. Literal SQL (no f-string) so the
    # pre-push audit stays quiet.
    try:
        ia_cols = {r[1] for r in conn.execute(
            "PRAGMA table_info(incident_alerts)")}
        if "trace_id" not in ia_cols:
            conn.execute(
                "ALTER TABLE incident_alerts ADD COLUMN trace_id TEXT")
    except Exception:
        pass  # tracing is observability; never break startup over it
    # One-time backfill: rows that predate the trace_id column get one,
    # so "every alert has a trace id" holds on old databases too.
    # Guarded -- never break startup over observability.
    try:
        null_ids = conn.execute(
            "SELECT id FROM alerts WHERE trace_id IS NULL").fetchall()
        if null_ids:
            conn.executemany(
                "UPDATE alerts SET trace_id=? WHERE id=?",
                [(uuid.uuid4().hex, r[0]) for r in null_ids])
        conn.execute(
            "UPDATE incident_alerts SET trace_id="
            " (SELECT trace_id FROM alerts"
            " WHERE alerts.id=incident_alerts.alert_id)"
            " WHERE trace_id IS NULL")
    except Exception:
        pass
    try:
        # De-dupe any legacy rows first so the index always builds.
        conn.execute("DELETE FROM allowlist WHERE id NOT IN"
                     " (SELECT MIN(id) FROM allowlist"
                     " GROUP BY kind, pattern)")
        conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS"
                     " idx_allowlist_kind_pattern ON allowlist(kind, pattern)")
    except Exception:
        pass  # belt and suspenders: allowlist dedupe is hygiene, not load-bearing
    # Phase 3.5 batch 11: self-scan findings now carry their source
    # ('builtin' = the built-in TCP connect scan, 'template' = a check
    # from a YAML template in templates/). Old rows predate the column
    # and are all built-in findings.
    finding_cols = {r[1] for r in conn.execute(
        "PRAGMA table_info(scan_findings)")}
    if "source" not in finding_cols:
        conn.execute("ALTER TABLE scan_findings"
                     " ADD COLUMN source TEXT DEFAULT 'builtin'")
    # The finding identity widened to (source, ip, port) in batch 11.
    # One-time rebuild for databases created before this batch: copy
    # rows out, recreate the table with the wider key, copy back. The
    # meta flag makes it run exactly once (fresh DBs already have the
    # new schema from _SCHEMA above -- the rebuild is a harmless no-op
    # for them). All SQL here is parameterized -- PRAGMA index_info
    # takes no placeholders, so introspection was deliberately avoided.
    flag = conn.execute(
        "SELECT value FROM meta WHERE key='schema_findings_v2'"
    ).fetchone()
    if not flag or flag[0] != "1":
        rows = conn.execute(
            "SELECT id, run_ts, ip, mac, port, service, risk,"
            " what_it_means, COALESCE(source, 'builtin'), status"
            " FROM scan_findings").fetchall()
        conn.execute("DROP TABLE scan_findings")
        conn.execute(
            "CREATE TABLE scan_findings("
            " id INTEGER PRIMARY KEY, run_ts REAL, ip TEXT, mac TEXT,"
            " port INTEGER, service TEXT, risk TEXT, what_it_means TEXT,"
            " source TEXT NOT NULL DEFAULT 'builtin',"
            " status TEXT NOT NULL DEFAULT 'open',"
            " UNIQUE(source, ip, port))")
        conn.executemany(
            "INSERT INTO scan_findings (id, run_ts, ip, mac, port,"
            " service, risk, what_it_means, source, status)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)", rows)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_findings_status"
                     " ON scan_findings(status)")
        conn.execute("INSERT INTO meta (key, value)"
                     " VALUES ('schema_findings_v2', '1')"
                     " ON CONFLICT(key) DO UPDATE SET value='1'")
    # B4 cleanup: older health checks created this table in prod on every
    # tick. The probe is rolled back now; drop the leftover if present.
    try:
        conn.execute("DROP TABLE IF EXISTS _healthcheck")
    except Exception:
        pass
    conn.commit()
    return conn


def _connect(path=None):
    """Connect + full schema/migrations, wrapped in the reconnect proxy."""
    return _ReconnectingConnection(lambda: _connect_raw(path))


_conn = None

# Thread-local overrides. The pcap-analysis path runs on a dashboard
# worker thread and must not touch production state: isolated_db() gives
# that thread its own scratch connection, and notifications_paused()
# suppresses the email hook on that thread. Other threads (capture,
# monitor, dashboard) keep using the shared connection undisturbed.
_thread_state = threading.local()


def _db():
    """Shared connection, or this thread's isolated one (pcap analysis)."""
    conn = getattr(_thread_state, "conn", None)
    if conn is not None:
        return conn
    global _conn
    if _conn is None:
        _conn = _connect()
    return _conn


@contextlib.contextmanager
def isolated_db(path):
    """Redirect this thread's db access to a scratch database file.

    B2: /pcap analysis must never write production tables. The scratch
    DB gets the full schema via _connect(); on exit its connection is
    closed and discarded (the caller deletes the file).
    """
    old = getattr(_thread_state, "conn", None)
    conn = _connect(path)
    _thread_state.conn = conn
    try:
        yield conn
    finally:
        try:
            conn.close()
        except Exception:
            pass
        if old is None:
            try:
                del _thread_state.conn
            except AttributeError:
                pass
        else:
            _thread_state.conn = old


@contextlib.contextmanager
def notifications_paused():
    """Suppress the notify hook on this thread. B2: pcap-derived alerts
    must never send real emails. Other threads are unaffected."""
    old = getattr(_thread_state, "notify_paused", False)
    _thread_state.notify_paused = True
    try:
        yield
    finally:
        _thread_state.notify_paused = old


def writability_probe():
    """True if the database accepts writes, without persisting anything.

    B4: runs under the module lock on the shared connection -- a
    rolled-back savepoint proves writability with no schema changes and
    no row churn. (The old health check opened its own connection and
    created a _healthcheck table in prod on every tick.)
    """
    with _lock:
        conn = _db()
        try:
            conn.execute("SAVEPOINT netmon_health_probe")
            conn.execute("INSERT INTO meta(key, value) VALUES('_probe','1')")
            conn.execute("ROLLBACK TO SAVEPOINT netmon_health_probe")
            conn.execute("RELEASE netmon_health_probe")
            return True
        except Exception:
            try:
                conn.execute("ROLLBACK TO SAVEPOINT netmon_health_probe")
                conn.execute("RELEASE netmon_health_probe")
            except Exception:
                pass
            return False


def _notify_hook(alert_dict):
    """Best-effort notification fan-out after an alert is stored.

    The notify module is maintained separately; if it's missing, broken,
    or sending fails, alerting itself must never break. This hook is
    always called outside the module lock.

    B2: when notifications_paused() is active on this thread (pcap
    analysis), the hook is a no-op -- diagnostic alerts never email.
    """
    if getattr(_thread_state, "notify_paused", False):
        return
    try:
        from . import notify
        notify.maybe_send_alert(alert_dict)
    except Exception:
        pass


# --- bounded write retry ---------------------------------------------------
# Pipeline robustness (batch 14): SQLite "database is locked" is
# transient under WAL contention (dashboard read + capture write +
# monitor write at once). Retrying a bounded number of times with
# backoff lets the alert land instead of the write being lost -- but the
# retry is STRICTLY bounded (no infinite retry storms): after
# _DB_RETRY_MAX attempts the error propagates to the caller, and the
# monitor loop logs it and keeps going. Anything that is not a lock
# error raises immediately.

_DB_RETRY_MAX = 5
_DB_RETRY_FIRST_DELAY_S = 0.05


def _is_locked_error(exc):
    """True for sqlite3 'database is locked' / 'database is busy'."""
    return (isinstance(exc, sqlite3.OperationalError)
            and ("locked" in str(exc).lower()
                 or "busy" in str(exc).lower()))


def _write_with_retry(fn):
    """Run a DB write fn(); retry transient lock contention with backoff.

    At most _DB_RETRY_MAX attempts total. Non-lock errors raise on the
    first attempt. The final lock failure propagates -- callers (the
    alert path) let it bubble to the monitor loop's handler, which logs
    it, rather than hanging the thread forever.
    """
    import time as _t
    delay = _DB_RETRY_FIRST_DELAY_S
    for attempt in range(_DB_RETRY_MAX):
        try:
            return fn()
        except Exception as exc:
            if attempt + 1 >= _DB_RETRY_MAX or not _is_locked_error(exc):
                raise
            _t.sleep(delay)
            delay = min(delay * 2, 0.5)


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
              what_to_do="", ts=None, trace_id=None):
    """Store a detection finding.

    meaning / is_normal / what_to_do are plain-English fields written for
    non-technical readers: what this means, when it's fine vs not, and one
    concrete next step.

    trace_id: one id for this detection, minted here at rule-fire time
    (uuid4 hex) when the caller doesn't supply one. It is stored on the
    alert row, carried into the incident, handed to the notify hook, and
    shown on the dashboard as the "Follow-up ID" -- one id follows a
    single detection end to end. It is deliberately NOT included in
    emails: it is internal plumbing, not user content.

    Phase 3.5: the alert is MITRE-tagged from its kind and attached to an
    incident (a case bundling related alerts) -- both best-effort, and
    neither can ever break or delay alert storage.

    The INSERT retries transient "database is locked" contention with
    backoff (bounded -- see _write_with_retry); a lock that never clears
    propagates to the caller instead of hanging.

    After the row is committed, a best-effort notification hook fires
    (outside the lock); it can never break or delay alert storage.
    """
    import time
    ts = ts if ts is not None else time.time()
    trace_id = trace_id or uuid.uuid4().hex
    try:
        from . import mitre as _mitre_mod
        tag = _mitre_mod.tag_for(kind) or {}
    except Exception:
        tag = {}
    # Alert-fatigue circuit breaker: a rule firing too often is
    # auto-muted. Suppressed firings are counted on the mute row (never
    # silent); the trip itself records one visible "muted" alert.
    now = time.time()
    gate = _circuit_gate(kind, now)
    if gate == "suppressed":
        return None
    try:
        with _lock:
            conn = _db()

            def _do_insert():
                cur = conn.execute(
                    "INSERT INTO alerts (ts, kind, severity, title, detail,"
                    " meaning, is_normal, what_to_do, mitre_id, mitre_name,"
                    " mitre_tactic, trace_id)"
                    " VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (ts, kind, severity, title, detail, meaning, is_normal,
                     what_to_do, tag.get("id"), tag.get("name"),
                     tag.get("tactic"), trace_id),
                )
                conn.commit()
                return cur.lastrowid

            alert_id = _write_with_retry(_do_insert)
    except Exception:
        if gate == "tripped":
            # The trip didn't really happen: the alert was never stored,
            # so don't leave a mute row behind silencing future alerts
            # with no visible record of why.
            try:
                clear_rule_mute(kind)
            except Exception:
                pass
        raise
    # Incident attach runs after the insert's lock is released (_lock is a
    # plain Lock, not re-entrant) and is best-effort: grouping must never
    # break alerting. Failures are logged so a broken pipeline is visible.
    # The mute notice itself skips cases: it's operational chrome, and a
    # "suspicious activity involving your network" case would mislead.
    if kind != "rule_muted":
        try:
            attach_to_incident(alert_id, kind, severity, title, detail, ts,
                               trace_id=trace_id)
        except Exception as exc:
            import sys
            try:
                print(f"netmon db: attach_to_incident failed for alert"
                      f" {alert_id} (trace {trace_id}): {exc!r}",
                      file=sys.stderr)
            except Exception:
                pass
    if gate == "tripped":
        _fire_mute_notice(kind, now)
    _notify_hook({
        "id": alert_id, "ts": ts, "kind": kind, "severity": severity,
        "title": title, "detail": detail, "meaning": meaning,
        "is_normal": is_normal, "what_to_do": what_to_do,
        "status": "new", "note": None, "trace_id": trace_id,
    })
    return alert_id


def get_alert(alert_id):
    """One alert as a dict (including trace_id), or None. Never raises."""
    try:
        with _lock:
            conn = _db()
            r = conn.execute(
                "SELECT id, ts, kind, severity, title, detail, meaning,"
                " is_normal, what_to_do, status, note, mitre_id,"
                " mitre_name, mitre_tactic, trace_id FROM alerts"
                " WHERE id=?", (alert_id,)).fetchone()
    except Exception:
        return None
    if not r:
        return None
    return {"id": r[0], "ts": r[1], "kind": r[2], "severity": r[3],
            "title": r[4], "detail": r[5], "meaning": r[6],
            "is_normal": r[7], "what_to_do": r[8], "status": r[9],
            "note": r[10], "mitre_id": r[11], "mitre_name": r[12],
            "mitre_tactic": r[13], "trace_id": r[14]}


# --- Phase 3.5: incidents, not alerts --------------------------------------
# A senior analyst thinks in cases, not scattered alerts. Every alert is
# attached to an incident: alerts naming the same address within a 2-hour
# window join one case with a timeline. Best-effort throughout -- grouping
# must never break alert storage.

INCIDENT_WINDOW_S = 2 * 3600  # same address, this close together => one case

_SEV_RANK = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}

_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _is_lan_ip(ip):
    """True for RFC1918 / loopback / link-local addresses."""
    try:
        parts = [int(p) for p in ip.split(".")]
        if len(parts) != 4 or any(p > 255 for p in parts):
            return False
        a, b = parts[0], parts[1]
        return (a == 10 or a == 127 or (a == 172 and 16 <= b <= 31)
                or (a == 192 and b == 168) or (a == 169 and b == 254))
    except (ValueError, AttributeError):
        return False


def _extract_case_key(title, detail):
    """The address tying a case together: first external IP named in the
    alert, else the first LAN IP, else None. External IPs win because the
    interesting question is usually 'who out there is involved'."""
    ips = []
    for text in (title or "", detail or ""):
        for m in _IPV4_RE.finditer(text):
            ip = m.group(0)
            try:
                if all(int(p) <= 255 for p in ip.split(".")) and ip not in ips:
                    ips.append(ip)
            except ValueError:
                continue
    for ip in ips:
        if not _is_lan_ip(ip):
            return ip
    return ips[0] if ips else None


def attach_to_incident(alert_id, kind, severity, title, detail, ts,
                       trace_id=None):
    """Attach an alert to its incident, creating the case if needed.

    The alert's trace_id is carried onto the incident_alerts row so one
    id follows the detection from rule-fire through the case.

    Returns the incident id. Takes the module lock; callers must not hold
    it (it is a plain Lock, not re-entrant). Never raises -- callers wrap
    it in try/except as well, belt and suspenders.
    """
    import time
    ts = ts if ts is not None else time.time()
    trace_id = trace_id or uuid.uuid4().hex
    key = _extract_case_key(title, detail)
    # Friendly name for the case label ("Case: ... involving PS5
    # (192.168.1.5)"). Looked up BEFORE the lock below (_lock is not
    # re-entrant, and the map helpers take it).
    case_label = key or "your network"
    if key:
        try:
            mac = (ip_to_mac_map() or {}).get(key)
            name = (device_name_map() or {}).get(mac, "") if mac else ""
            if name:
                case_label = f"{name} ({key})"
        except Exception:
            pass
    with _lock:
        conn = _db()

        def _do_attach():
            incident_id = None
            if key:
                row = conn.execute(
                    "SELECT id, severity FROM incidents"
                    " WHERE status IN ('open','escalated') AND device_key=?"
                    " AND updated_ts > ?"
                    " ORDER BY updated_ts DESC LIMIT 1",
                    (key, ts - INCIDENT_WINDOW_S),
                ).fetchone()
                if row:
                    incident_id = row[0]
                    if _SEV_RANK.get(severity, 0) > _SEV_RANK.get(row[1], 0):
                        conn.execute(
                            "UPDATE incidents SET severity=? WHERE id=?",
                            (severity, incident_id))
            if incident_id is None:
                cur = conn.execute(
                    "INSERT INTO incidents (created_ts, updated_ts, title,"
                    " severity, status, device_key, summary)"
                    " VALUES (?,?,?,?,?,?,?)",
                    (ts, ts, f"Case: suspicious activity involving {case_label}",
                     severity, "open", key, f"Opened by: {title}"),
                )
                incident_id = cur.lastrowid
            else:
                conn.execute(
                    "UPDATE incidents SET updated_ts=? WHERE id=?",
                    (ts, incident_id))
            conn.execute(
                "INSERT OR IGNORE INTO incident_alerts"
                " (incident_id, alert_id, trace_id) VALUES (?,?,?)",
                (incident_id, alert_id, trace_id))
            conn.commit()
            return incident_id

        return _write_with_retry(_do_attach)


def list_incidents(status="open", limit=50):
    """Open cases (default), newest activity first, with alert counts."""
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT i.id, i.created_ts, i.updated_ts, i.title, i.severity,"
            " i.status, i.device_key, i.summary,"
            " COUNT(a.alert_id) FROM incidents i"
            " LEFT JOIN incident_alerts a ON a.incident_id=i.id"
            " WHERE i.status=? GROUP BY i.id"
            " ORDER BY i.updated_ts DESC LIMIT ?",
            (status, limit),
        ).fetchall()
    return [{
        "id": r[0], "created_ts": r[1], "updated_ts": r[2], "title": r[3],
        "severity": r[4], "status": r[5], "device_key": r[6],
        "summary": r[7], "alert_count": r[8],
    } for r in rows]


def get_incident(incident_id):
    """One case with its full alert timeline, oldest first. None if missing."""
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT id, created_ts, updated_ts, title, severity, status,"
            " device_key, summary FROM incidents WHERE id=?",
            (incident_id,)).fetchone()
        if not row:
            return None
        alerts = conn.execute(
            "SELECT al.id, al.ts, al.kind, al.severity, al.title, al.detail,"
            " al.meaning, al.what_to_do, al.mitre_id, al.mitre_name,"
            " al.mitre_tactic, al.status, ia.trace_id"
            " FROM incident_alerts ia JOIN alerts al ON al.id=ia.alert_id"
            " WHERE ia.incident_id=? ORDER BY al.ts ASC",
            (incident_id,)).fetchall()
    return {
        "id": row[0], "created_ts": row[1], "updated_ts": row[2],
        "title": row[3], "severity": row[4], "status": row[5],
        "device_key": row[6], "summary": row[7],
        "alerts": [{
            "id": a[0], "ts": a[1], "kind": a[2], "severity": a[3],
            "title": a[4], "detail": a[5], "meaning": a[6],
            "what_to_do": a[7], "mitre_id": a[8], "mitre_name": a[9],
            "mitre_tactic": a[10], "status": a[11],
            "trace_id": a[12] or "",
        } for a in alerts],
    }


def set_incident_status(incident_id, status):
    """Move a case through its state machine. Returns True if the case
    exists and the transition is legal.

    States: open -> escalated -> closed. Reopening goes back to open.
    Legal moves: open->escalated, open->closed, escalated->closed,
    closed->open, escalated->open. Escalating a closed case is refused
    (reopen it first) -- an escalation must always describe live work.
    """
    if status not in ("open", "escalated", "closed"):
        return False
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT status FROM incidents WHERE id=?",
            (incident_id,)).fetchone()
        if not row:
            return False
        current = row[0] or "open"
        if status == "escalated" and current != "open":
            return False  # only a live, open case can be escalated
        cur = conn.execute(
            "UPDATE incidents SET status=? WHERE id=?", (status, incident_id))
        conn.commit()
        return cur.rowcount > 0


# --- audit log: who did what, when (append-only) --------------------------
# Phase 3.5 "act, not just watch". Every quarantine, release, and
# escalation lands here. There is deliberately no update/delete path:
# the trail cannot be rewritten after the fact.


def audit(action, actor, target, detail=""):
    """Append one audit row. Never raises (a broken audit trail must not
    break the action it records); returns the row id or None."""
    import time
    try:
        with _lock:
            conn = _db()
            cur = conn.execute(
                "INSERT INTO audit_log (ts, actor, action, target, detail)"
                " VALUES (?,?,?,?,?)",
                (time.time(), actor or "", action or "", target or "",
                 detail or ""))
            conn.commit()
            return cur.lastrowid
    except Exception:
        return None


def list_audit(limit=200, target=None):
    """Newest audit rows first; optionally filtered to one target."""
    with _lock:
        conn = _db()
        if target:
            rows = conn.execute(
                "SELECT id, ts, actor, action, target, detail FROM audit_log"
                " WHERE target=? ORDER BY id DESC LIMIT ?",
                (target, limit)).fetchall()
        else:
            rows = conn.execute(
                "SELECT id, ts, actor, action, target, detail FROM audit_log"
                " ORDER BY id DESC LIMIT ?",
                (limit,)).fetchall()
    return [{"id": r[0], "ts": r[1], "actor": r[2], "action": r[3],
             "target": r[4], "detail": r[5]} for r in rows]


# --- quarantine state (the durable half of netmon/quarantine.py) ----------


def quarantine_upsert(mac, ip, actor, note=""):
    """Record that a human asked for this device to be isolated."""
    import time
    mac = (mac or "").lower()
    now = time.time()
    with _lock:
        conn = _db()
        conn.execute(
            "INSERT INTO quarantines (mac, ip, state, created_ts,"
            " updated_ts, actor, note) VALUES (?,?,?,?,?,?,?)"
            " ON CONFLICT(mac) DO UPDATE SET ip=excluded.ip,"
            " state='active', updated_ts=excluded.updated_ts,"
            " actor=excluded.actor, note=excluded.note",
            (mac, ip or "", "active", now, now, actor or "", note or ""))
        conn.commit()


def quarantine_release(mac, actor, note=""):
    """Record that a human lifted the isolation. Returns True if the
    device was actually isolated (a release of a non-isolated device
    is a no-op, not an error)."""
    import time
    mac = (mac or "").lower()
    with _lock:
        conn = _db()
        cur = conn.execute(
            "UPDATE quarantines SET state='released', updated_ts=?,"
            " actor=?, note=? WHERE mac=? AND state='active'",
            (time.time(), actor or "", note or "", mac))
        conn.commit()
        return cur.rowcount > 0


def get_quarantine(mac):
    """The quarantine row for a MAC, or None."""
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT mac, ip, state, created_ts, updated_ts, actor, note"
            " FROM quarantines WHERE mac=?", ((mac or "").lower(),)
        ).fetchone()
    if not row:
        return None
    return {"mac": row[0], "ip": row[1], "state": row[2],
            "created_ts": row[3], "updated_ts": row[4],
            "actor": row[5], "note": row[6]}


def active_quarantines():
    """Every device currently isolated: [{mac, ip, ...}]."""
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT mac, ip, created_ts, updated_ts, actor, note"
            " FROM quarantines WHERE state='active'").fetchall()
    return [{"mac": r[0], "ip": r[1], "created_ts": r[2],
             "updated_ts": r[3], "actor": r[4], "note": r[5]}
            for r in rows]


def is_quarantined(mac):
    """True when this MAC is currently isolated."""
    q = get_quarantine(mac)
    return bool(q and q["state"] == "active")


# --- escalations ----------------------------------------------------------


def record_escalation(incident_id, actor, admin_email, subject, sent_ok):
    """Log one escalation attempt. sent_ok=0 means the email failed and
    the case was NOT moved to 'escalated'. Returns the row id."""
    import time
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO escalations (incident_id, ts, actor, admin_email,"
            " subject, sent_ok) VALUES (?,?,?,?,?,?)",
            (incident_id, time.time(), actor or "", admin_email or "",
             subject or "", 1 if sent_ok else 0))
        conn.commit()
        return cur.lastrowid


def list_escalations(incident_id):
    """Escalation attempts for a case, oldest first."""
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT id, ts, actor, admin_email, subject, sent_ok"
            " FROM escalations WHERE incident_id=? ORDER BY id ASC",
            (incident_id,)).fetchall()
    return [{"id": r[0], "ts": r[1], "actor": r[2], "admin_email": r[3],
             "subject": r[4], "sent_ok": bool(r[5])} for r in rows]


def incident_what_was_tried(incident_id):
    """Plain-English list of what the human already tried on this case:
    alert triage (acknowledged/dismissed + notes), quarantine/release
    actions on the case's device, and past escalation attempts. This is
    the "what the user already tried" section of the escalation bundle,
    so the admin never re-asks what was already done."""
    case = get_incident(incident_id)
    if not case:
        return []
    import time
    tried = []
    for a in case.get("alerts") or []:
        st = (a.get("status") or "new").strip()
        if st in ("acknowledged", "dismissed"):
            note = (a.get("note") or "").strip()
            tried.append(
                f"{st.capitalize()} the alert \"{a.get('title') or a.get('kind')}\""
                + (f" with the note: {note}" if note else ""))
    device_key = (case.get("device_key") or "").strip()
    if device_key:
        # Quarantine/release audit entries touching this device's IP/MAC.
        ipmap = {}
        try:
            ipmap = ip_to_mac_map()
        except Exception:
            pass
        dev_mac = (ipmap.get(device_key) or "").lower()
        for entry in list_audit(limit=500):
            act, tgt = entry.get("action") or "", entry.get("target") or ""
            if act in ("quarantine", "release", "quarantine_refused") and (
                    tgt == device_key or (dev_mac and tgt == dev_mac)):
                when = time.strftime("%b %d %I:%M %p",
                                     time.localtime(entry.get("ts") or 0))
                verb = {"quarantine": "Isolated",
                        "release": "Released",
                        "quarantine_refused": "Tried to isolate (blocked)"}.get(
                            act, act)
                tried.append(f"{verb} the device ({tgt}) on {when}")
    for esc in list_escalations(incident_id):
        when = time.strftime("%b %d %I:%M %p",
                             time.localtime(esc.get("ts") or 0))
        if esc.get("sent_ok"):
            tried.append(f"Escalated to {esc.get('admin_email')} on {when}")
        else:
            tried.append(f"Tried to escalate on {when}, but the email"
                         f" failed to send")
    # AI-analyst tool calls (netmon/tools.py audit-logs every invocation):
    # the admin should see what the analyst already looked up or ran, so
    # it is not re-asked. Capped at the 3 most recent, phrased as analyst
    # actions (not owner actions).
    for entry in recent_tool_calls(limit=3):
        when = time.strftime("%b %d %I:%M %p",
                             time.localtime(entry.get("ts") or 0))
        tried.append(f"AI analyst ran '{entry.get('tool')}' on {when}"
                     f" ({entry.get('outcome')})")
    # De-dupe while keeping order.
    seen, out = set(), []
    for t in tried:
        if t not in seen:
            seen.add(t)
            out.append(t)
    return out


def recent_tool_calls(limit=3):
    """Most recent AI tool-server invocations from the audit log.

    Returns [{ts, actor, tool, outcome}] newest first, capped at `limit`.
    The outcome is the audit detail's short summary ("ok in 0.12s",
    "validation rejected: ...", ...). Used by incident_what_was_tried
    so the escalation bundle shows what the analyst already tried.
    Never raises.
    """
    out = []
    try:
        for entry in list_audit(limit=200):
            if (entry.get("action") or "") != "tool_call":
                continue
            detail = (entry.get("detail") or "")
            # Detail shape written by tools._audit: "params={...} -> X".
            outcome = detail.split("->", 1)[1].strip()[:120] \
                if "->" in detail else detail[:120]
            out.append({"ts": entry.get("ts"),
                        "actor": entry.get("actor") or "",
                        "tool": entry.get("target") or "",
                        "outcome": outcome or "unknown outcome"})
            if len(out) >= limit:
                break
    except Exception:
        pass
    return out


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


def set_device_type(mac, dtype):
    """Pin a device's type by MAC (the topology map's correction loop).

    An empty dtype clears the override. The value is stored as-is
    (lowercased, capped); callers validate against topology.DEVICE_TYPES.
    """
    import time
    mac = (mac or "").strip().lower()
    dtype = (dtype or "").strip().lower()
    if not mac:
        raise ValueError("mac is required")
    with _lock:
        conn = _db()
        if dtype:
            conn.execute(
                "INSERT INTO device_types (mac, dtype, updated_ts)"
                " VALUES (?,?,?)"
                " ON CONFLICT(mac) DO UPDATE SET dtype=excluded.dtype,"
                " updated_ts=excluded.updated_ts",
                (mac, dtype[:16], time.time()))
        else:
            conn.execute("DELETE FROM device_types WHERE mac=?", (mac,))
        conn.commit()


def device_type_map():
    """{mac: dtype} for every user-pinned device type."""
    with _lock:
        conn = _db()
        return {m: d for m, d in conn.execute(
            "SELECT mac, dtype FROM device_types")}


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


# --- maintenance mode ------------------------------------------------------
# "Don't alert me Saturday 2-4am -- I'm replacing the router." Detection
# keeps running (nothing is ever blind); only notifications pause:
# per-alert emails, the digest, and the morning briefing stay silent
# while the flag is active. Human-initiated actions (Escalate,
# quarantine, digest "send now") still work -- the owner asked for
# those explicitly.

def set_maintenance(on, until_ts=None, reason=""):
    """Switch maintenance mode on/off. until_ts: unix epoch or None
    (stays on until switched off). Returns the new state dict."""
    import time
    with _lock:
        conn = _db()
        if on:
            conn.execute(
                "INSERT INTO maintenance (id, on_ts, until_ts, reason)"
                " VALUES (1,?,?,?)"
                " ON CONFLICT(id) DO UPDATE SET on_ts=excluded.on_ts,"
                " until_ts=excluded.until_ts, reason=excluded.reason",
                (time.time(), until_ts,
                 (reason or "").strip()[:200] or None))
        else:
            conn.execute("DELETE FROM maintenance WHERE id=1")
        conn.commit()
    try:
        audit("maintenance", "owner", "maintenance",
              f"switched {'on' if on else 'off'}"
              + (f" until {time.strftime('%b %d %I:%M %p', time.localtime(until_ts))}"
                 if on and until_ts else "")
              + (f" ({(reason or '').strip()[:200]})" if on and reason else ""))
    except Exception:
        pass
    return get_maintenance()


def get_maintenance():
    """Maintenance state: {"active", "on_ts", "until_ts", "reason"}.

    An expired until_ts auto-clears (one row, so this is cheap). Never
    raises.
    """
    import time
    try:
        with _lock:
            conn = _db()
            row = conn.execute(
                "SELECT on_ts, until_ts, reason FROM maintenance"
                " WHERE id=1").fetchone()
            if row and row[1] is not None and row[1] <= time.time():
                conn.execute("DELETE FROM maintenance WHERE id=1")
                conn.commit()
                row = None
    except Exception:
        return {"active": False, "on_ts": None, "until_ts": None,
                "reason": ""}
    if not row:
        return {"active": False, "on_ts": None, "until_ts": None,
                "reason": ""}
    return {"active": True, "on_ts": row[0], "until_ts": row[1],
            "reason": row[2] or ""}


def maintenance_active():
    """True when maintenance mode is currently silencing notifications."""
    try:
        return bool(get_maintenance()["active"])
    except Exception:
        return False


# --- alert-fatigue circuit breaker -------------------------------------------
# One rule firing too often gets auto-muted: further firings are dropped
# at the gate (counted on the mute row, never silent) and a single
# visible "muted" alert explains what happened. Detection never stops --
# the rule still evaluates; only the alert spam is throttled. The mute
# notice itself, self-alerts, and the canary always pass through.

_CIRCUIT_EXEMPT = frozenset({"rule_muted", "self_drift", "canary_touch"})


def _circuit_config():
    """(fires, window_min, mute_min) from config.yaml `quiet`, with
    sane defaults when config is missing or broken."""
    try:
        from . import config as cfgm
        cfg = cfgm.load_cached()
        fires = int(cfgm.get(cfg, "quiet.circuit_fires", 10))
        window_min = int(cfgm.get(cfg, "quiet.circuit_window_min", 10))
        mute_min = int(cfgm.get(cfg, "quiet.circuit_mute_min", 60))
        return max(1, fires), max(1, window_min), max(1, mute_min)
    except Exception:
        return 10, 10, 60


def _circuit_gate(kind, now):
    """The gate every add_alert passes through.

    Returns "suppressed" (an active mute ate this firing -- counted),
    "tripped" (the breaker just tripped -- a mute row was created), or
    None (normal). Never raises.
    """
    if kind in _CIRCUIT_EXEMPT:
        return None
    fires, window_min, mute_min = _circuit_config()
    try:
        with _lock:
            conn = _db()
            row = conn.execute(
                "SELECT muted_until FROM rule_mutes WHERE kind=?",
                (kind,)).fetchone()
            if row and row[0] and row[0] > now:
                conn.execute(
                    "UPDATE rule_mutes SET suppressed=suppressed+1"
                    " WHERE kind=?", (kind,))
                conn.commit()
                return "suppressed"
            if row:
                # Expired mute: clear it so the rule can prove itself
                # quiet again.
                conn.execute("DELETE FROM rule_mutes WHERE kind=?",
                             (kind,))
                conn.commit()
            count = conn.execute(
                "SELECT COUNT(*) FROM alerts WHERE kind=? AND ts > ?",
                (kind, now - window_min * 60)).fetchone()[0] or 0
            if count < fires:
                return None
            conn.execute(
                "INSERT OR REPLACE INTO rule_mutes (kind, muted_from,"
                " muted_until, fired_count, window_min, suppressed, note)"
                " VALUES (?,?,?,?,?,?,?)",
                (kind, now, now + mute_min * 60, count, window_min, 0,
                 f"fired {count} times in {window_min} minutes"))
            conn.commit()
            return "tripped"
    except Exception:
        return None
    return None


def list_rule_mutes(active_only=True):
    """Mute rows for the dashboard, newest first. Never raises."""
    import time
    try:
        with _lock:
            conn = _db()
            rows = conn.execute(
                "SELECT kind, muted_from, muted_until, fired_count,"
                " window_min, suppressed, note FROM rule_mutes"
                " ORDER BY muted_from DESC").fetchall()
    except Exception:
        return []
    now = time.time()
    out = []
    for kind, mfrom, muntil, fired, wmin, supp, note in rows:
        active = bool(muntil and muntil > now)
        if active_only and not active:
            continue
        out.append({"kind": kind, "muted_from": mfrom,
                    "muted_until": muntil, "fired_count": fired or 0,
                    "window_min": wmin or 0, "suppressed": supp or 0,
                    "note": note or "", "active": active})
    return out


def clear_rule_mute(kind):
    """Owner override: lift a mute early. Returns True when one existed."""
    with _lock:
        conn = _db()
        cur = conn.execute("DELETE FROM rule_mutes WHERE kind=?",
                           ((kind or "").strip(),))
        conn.commit()
        return cur.rowcount > 0


def _fire_mute_notice(kind, now):
    """The one visible entry when the circuit breaker trips: a Medium
    alert reading "muted for X because it fired Y times". Never a
    silent drop. Best-effort; never raises.

    The notice itself is gate-exempt (no recursion) and skips incident
    attach (handled by the caller). It is Medium, so it never pages --
    the dashboard and the Detection rules panel carry it.
    """
    try:
        mute = next((m for m in list_rule_mutes(active_only=True)
                     if m["kind"] == kind), None)
        if not mute:
            return
        fired, wmin = mute["fired_count"], mute["window_min"]
        span = mute["muted_until"] - (mute["muted_from"] or now)
        mute_min = max(1, round(span / 60))
        add_alert(
            "rule_muted", "Medium",
            f"'{kind}' kept firing -- quieting it down for a while",
            (f"The '{kind}' rule fired {fired} times in the last {wmin}"
             f" minutes, so it is muted for {mute_min} minutes. Detection"
             f" keeps running; further firings are counted but won't"
             f" page you."),
            meaning=("One of the detection rules got very chatty -- like a"
                     " car alarm going off every few minutes. The monitor"
                     " turned its volume down for a while instead of"
                     " bothering you each time."),
            is_normal=("Normal when something genuinely repeats -- a busy"
                       " backup, a chatty device. Worth a look if you don't"
                       " recognize the pattern."),
            what_to_do=("Check the Detection rules panel to see what kept"
                        " firing. If it's normal, dismiss one of the alerts"
                        " and the monitor will learn to stay quiet about it."),
            ts=now)
    except Exception:
        pass

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
    # Council review: escape LIKE wildcards in `key` (MAC-derived or
    # domain keys can contain % or _) so they can't over-suppress
    # unrelated alerts' cooldowns. Backslash is the ESCAPE character.
    like_key = (key.replace("\\", "\\\\")
                   .replace("%", "\\%")
                   .replace("_", "\\_"))
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT 1 FROM alerts WHERE kind=? AND detail LIKE ? ESCAPE '\\'"
            " AND ts > ? LIMIT 1",
            (kind, f"%{like_key}%", time.time() - within_s),
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


# --- asset inventory -----------------------------------------------------
# "Know the network": every LAN device, enriched. refresh_assets() (see
# netmon/assets.py) folds arp_observations, device_hostnames, device_ttl,
# device_names and scan_findings into the assets table; the dashboard
# reads get_assets().


def insert_hostname_observations(rows):
    """rows: list of (ts, mac, ip, hostname, source).

    mac is lowercased by callers when known; hostname is sanitized here
    (LAN-derived strings must never reach the UI raw -- defense in depth
    alongside the dashboard's esc())."""
    if not rows:
        return
    clean = []
    for ts, mac, ip, hostname, source in rows:
        name = re.sub(r"[^A-Za-z0-9_.\- ]", "", str(hostname or "")).strip()
        if not name:
            continue
        clean.append((ts, (mac or "").strip().lower() or "",
                      (ip or "").strip(),
                      name[:64],
                      (source or "").strip().lower()[:16]))
    if not clean:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO device_hostnames (ts, mac, ip, hostname, source)"
            " VALUES (?,?,?,?,?)",
            clean,
        )
        conn.commit()


def device_hostname_map():
    """{mac: (hostname, source)} -- latest non-empty name per MAC."""
    latest = {}
    for ts, mac, hostname, source in query(
            "SELECT ts, mac, hostname, source FROM device_hostnames"
            " WHERE mac != '' ORDER BY ts"):
        if mac not in latest or ts >= latest[mac][0]:
            latest[mac] = (ts, hostname, source)
    return {mac: (hn, src) for mac, (_ts, hn, src) in latest.items()}


def record_ttls(rows):
    """rows: list of (ip, ttl, ts). Keeps the latest TTL per IP."""
    if not rows:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO device_ttl (ip, ttl, updated_ts) VALUES (?,?,?)"
            " ON CONFLICT(ip) DO UPDATE SET ttl=excluded.ttl,"
            " updated_ts=excluded.updated_ts",
            [(ip, int(ttl), ts) for ip, ttl, ts in rows
             if ip and ttl is not None],
        )
        conn.commit()


def device_ttl_map():
    """{ip: ttl} -- last observed TTL per device IP."""
    with _lock:
        conn = _db()
        return {ip: ttl for ip, ttl in conn.execute(
            "SELECT ip, ttl FROM device_ttl")}


def refresh_assets(rows):
    """Replace the assets table with `rows`: list of dicts with keys
    mac, ip, first_seen, last_seen, hostname, hostname_source, os_guess,
    vendor, open_ports (list of dicts), updated_ts."""
    import time as _t
    with _lock:
        conn = _db()
        conn.execute("DELETE FROM assets")
        conn.executemany(
            "INSERT INTO assets (mac, ip, first_seen, last_seen, hostname,"
            " hostname_source, os_guess, vendor, open_ports, updated_ts)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            [(
                r.get("mac", ""), r.get("ip", ""), r.get("first_seen"),
                r.get("last_seen"), r.get("hostname", ""),
                r.get("hostname_source", ""), r.get("os_guess", ""),
                r.get("vendor", ""),
                json.dumps(r.get("open_ports") or []),
                r.get("updated_ts") or _t.time(),
            ) for r in rows],
        )
        conn.execute(
            "INSERT INTO meta (key, value) VALUES ('assets_synced_ts', ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (str(_t.time()),))
        conn.commit()


def get_assets():
    """Enriched device inventory, newest activity first."""
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT mac, ip, first_seen, last_seen, hostname,"
            " hostname_source, os_guess, vendor, open_ports, updated_ts"
            " FROM assets ORDER BY last_seen DESC").fetchall()
    out = []
    for r in rows:
        try:
            ports = json.loads(r[8] or "[]")
            if not isinstance(ports, list):
                ports = []
        except Exception:
            ports = []
        out.append({
            "mac": r[0], "ip": r[1], "first_seen": r[2], "last_seen": r[3],
            "hostname": r[4] or "", "hostname_source": r[5] or "",
            "os_guess": r[6] or "", "vendor": r[7] or "",
            "open_ports": ports, "updated_ts": r[9],
        })
    return out


def assets_stale(max_age_s=3600):
    """True when the assets table needs a refresh."""
    import time as _t
    raw = get_meta("assets_synced_ts")
    try:
        synced = float(raw) if raw else 0
    except (TypeError, ValueError):
        synced = 0
    return (_t.time() - synced) > max_age_s


# --- self vulnerability scans --------------------------------------------
# Weekly, on-demand TCP connect scans of our OWN LAN only (see
# netmon/scan.py). Findings are stored; alerts fire only for NEW or
# changed findings so a weekly scan stays quiet.


def record_scan_run(ts, duration_s, devices_scanned, findings, note=""):
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO scan_runs (ts, duration_s, devices_scanned,"
            " findings, note) VALUES (?,?,?,?,?)",
            (ts, duration_s, devices_scanned, findings, (note or "")[:200]))
        conn.commit()
        return cur.lastrowid


def record_scan_findings(run_ts, findings, source="builtin"):
    """Store this run's open findings; mark vanished ones resolved.

    Current-state table (one row per ip/port; the scan_runs table keeps
    the run history). findings: list of (ip, mac, port, service, risk,
    what_it_means). source: 'builtin' (the TCP connect scan) or
    'template' (a YAML-template check) -- new/changed/resolved are
    computed per source so the two check families never cross-talk.
    Returns (new_findings, resolved_findings, changed_findings) as
    (ip, port) key lists -- the scan module alerts only on genuinely
    new/changed doors.
    """
    source = (source or "builtin")[:16]
    with _lock:
        conn = _db()
        prev_risk = {}
        for ip, port, risk in conn.execute(
                "SELECT ip, port, risk FROM scan_findings"
                " WHERE status='open' AND source=?", (source,)):
            prev_risk[(ip, int(port))] = risk
        new, changed, current = [], [], {}
        for ip, mac, port, _svc, risk, _what in findings:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            key = (ip, port)
            current[key] = True
            if key not in prev_risk:
                new.append(key)
            elif prev_risk[key] != risk:
                changed.append(key)
        resolved = [k for k in prev_risk if k not in current]
        for ip, port in resolved:
            conn.execute(
                "UPDATE scan_findings SET status='resolved'"
                " WHERE ip=? AND port=? AND status='open' AND source=?",
                (ip, port, source))
        for ip, mac, port, service, risk, what in findings:
            try:
                port = int(port)
            except (TypeError, ValueError):
                continue
            conn.execute(
                "INSERT INTO scan_findings (run_ts, ip, mac, port, service,"
                " risk, what_it_means, source, status)"
                " VALUES (?,?,?,?,?,?,?,?,'open')"
                " ON CONFLICT(source, ip, port) DO UPDATE SET"
                " run_ts=excluded.run_ts,"
                " mac=excluded.mac, service=excluded.service,"
                " risk=excluded.risk, what_it_means=excluded.what_it_means,"
                " status='open'",
                (run_ts, ip, mac, port, service, risk, what, source))
        conn.commit()
        return new, resolved, changed


def latest_scan_run():
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT ts, duration_s, devices_scanned, findings, note"
            " FROM scan_runs ORDER BY ts DESC LIMIT 1").fetchone()
    if not row:
        return None
    return {"ts": row[0], "duration_s": row[1], "devices_scanned": row[2],
            "findings": row[3], "note": row[4] or ""}


def list_scan_findings(status="open", limit=200):
    with _lock:
        conn = _db()
        return [
            {"id": i, "run_ts": rt, "ip": ip, "mac": m or "",
             "port": p, "service": s or "", "risk": rk or "",
             "what_it_means": w or "", "source": src or "builtin",
             "status": st}
            for i, rt, ip, m, p, s, rk, w, src, st in conn.execute(
                "SELECT id, run_ts, ip, mac, port, service, risk,"
                " what_it_means, source, status FROM scan_findings"
                " WHERE status=? ORDER BY ip, port LIMIT ?",
                (status, limit))]


# --- external attack-surface mapping (OWASP Amass) -------------------------
# Run history + current asset state per configured domain (see
# netmon/amass.py). Diffing compares the new run against the stored
# state; the first run for a domain is the silent baseline.


def record_amass_run(ts, domain, duration_s, subdomains, ips, note=""):
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO amass_runs (ts, domain, duration_s, subdomains,"
            " ips, note) VALUES (?,?,?,?,?,?)",
            (ts, (domain or "")[:253], duration_s, subdomains, ips,
             (note or "")[:200]))
        conn.commit()
        return cur.lastrowid


def record_amass_assets(domain, rows, ts):
    """Upsert the current asset state for a domain.

    rows: list of (kind, value, detail). Returns the current
    {(kind, value)} set for diffing.
    """
    domain = (domain or "")[:253]
    clean = []
    for kind, value, detail in rows or []:
        kind = (kind or "")[:16]
        value = (value or "")[:253]
        if not kind or not value:
            continue
        clean.append((kind, value, (detail or "")[:500]))
    with _lock:
        conn = _db()
        for kind, value, detail in clean:
            conn.execute(
                "INSERT INTO amass_assets (domain, kind, value, detail,"
                " first_seen, last_seen) VALUES (?,?,?,?,?,?)"
                " ON CONFLICT(domain, kind, value) DO UPDATE SET"
                " detail=excluded.detail, last_seen=excluded.last_seen",
                (domain, kind, value, detail, ts, ts))
        conn.commit()
    return {(k, v) for k, v, _ in clean}


def amass_asset_set(domain):
    """Current {(kind, value)} asset set for a domain (for diffing)."""
    with _lock:
        conn = _db()
        return {(k, v) for k, v in conn.execute(
            "SELECT kind, value FROM amass_assets WHERE domain=?",
            ((domain or "")[:253],))}


def latest_amass_run(domain):
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT ts, duration_s, subdomains, ips, note FROM amass_runs"
            " WHERE domain=? ORDER BY ts DESC LIMIT 1",
            ((domain or "")[:253],)).fetchone()
    if not row:
        return None
    return {"ts": row[0], "duration_s": row[1], "subdomains": row[2],
            "ips": row[3], "note": row[4] or ""}


def list_amass_assets(domain, limit=500):
    """Current assets for a domain: [{kind, value, detail, first_seen}]."""
    try:
        limit = max(1, min(2000, int(limit)))
    except (TypeError, ValueError):
        limit = 500
    with _lock:
        conn = _db()
        return [
            {"kind": k, "value": v, "detail": d or "",
             "first_seen": fs or 0}
            for k, v, d, fs in conn.execute(
                "SELECT kind, value, detail, first_seen FROM amass_assets"
                " WHERE domain=? ORDER BY kind, value LIMIT ?",
                ((domain or "")[:253], limit))]


# --- Nuclei-powered self vulnerability scan --------------------------------
# Run history + current finding state for the scheduled Nuclei scans of
# our OWN LAN (see netmon/nuclei.py). Diffing compares each run against
# the stored state; the first run is the silent baseline.


def record_nuclei_run(ts, duration_s, targets, findings, new_findings,
                      note=""):
    with _lock:
        conn = _db()
        cur = conn.execute(
            "INSERT INTO nuclei_runs (ts, duration_s, targets, findings,"
            " new_findings, note) VALUES (?,?,?,?,?,?)",
            (ts, duration_s, targets, findings, new_findings,
             (note or "")[:200]))
        conn.commit()
        return cur.lastrowid


def record_nuclei_findings(run_ts, findings):
    """Upsert this run's findings; resolve ones that vanished.

    findings: list of dicts with ip, template_id, name, severity,
    matched_at, description, cves. Identity is
    (ip, template_id, matched_at). Returns (new, resolved, changed) as
    (ip, template_id, matched_at) key lists.
    """
    with _lock:
        conn = _db()
        prev = {}
        for ip, tid, ma, sev in conn.execute(
                "SELECT ip, template_id, matched_at, severity"
                " FROM nuclei_findings WHERE status='open'"):
            prev[(ip, tid, ma)] = sev
        new, changed, current = [], [], {}
        for f in findings or []:
            key = (f.get("ip") or "", f.get("template_id") or "",
                   f.get("matched_at") or "")
            if not key[0] or not key[1]:
                continue
            current[key] = True
            if key not in prev:
                new.append(key)
            elif prev[key] != (f.get("severity") or ""):
                changed.append(key)
        resolved = [k for k in prev if k not in current]
        for ip, tid, ma in resolved:
            conn.execute(
                "UPDATE nuclei_findings SET status='resolved'"
                " WHERE ip=? AND template_id=? AND matched_at=?"
                " AND status='open'", (ip, tid, ma))
        for f in findings or []:
            ip, tid = (f.get("ip") or ""), (f.get("template_id") or "")
            if not ip or not tid:
                continue
            conn.execute(
                "INSERT INTO nuclei_findings (run_ts, ip, template_id, name,"
                " severity, matched_at, description, cves, status)"
                " VALUES (?,?,?,?,?,?,?,?, 'open')"
                " ON CONFLICT(ip, template_id, matched_at) DO UPDATE SET"
                " run_ts=excluded.run_ts, name=excluded.name,"
                " severity=excluded.severity,"
                " description=excluded.description, cves=excluded.cves,"
                " status='open'",
                (run_ts, ip, tid, (f.get("name") or "")[:200],
                 (f.get("severity") or "")[:16],
                 (f.get("matched_at") or "")[:500],
                 (f.get("description") or "")[:1000],
                 (f.get("cves") or "")[:500]))
        conn.commit()
        return new, resolved, changed


def latest_nuclei_run():
    with _lock:
        conn = _db()
        row = conn.execute(
            "SELECT ts, duration_s, targets, findings, new_findings, note"
            " FROM nuclei_runs ORDER BY ts DESC LIMIT 1").fetchone()
    if not row:
        return None
    return {"ts": row[0], "duration_s": row[1], "targets": row[2],
            "findings": row[3], "new_findings": row[4], "note": row[5] or ""}


def list_nuclei_findings(status="open", limit=200, min_severity=None):
    """Current Nuclei findings. min_severity filters to that level and
    above on our scale (Low < Medium < High)."""
    rank = {"Low": 1, "Medium": 2, "High": 3}
    floor = rank.get((min_severity or "Low").capitalize(), 1)
    try:
        limit = max(1, min(2000, int(limit)))
    except (TypeError, ValueError):
        limit = 200
    with _lock:
        conn = _db()
        out = []
        for row in conn.execute(
                "SELECT id, run_ts, ip, template_id, name, severity,"
                " matched_at, description, cves FROM nuclei_findings"
                " WHERE status=? ORDER BY ip, template_id LIMIT ?",
                (status, limit)):
            sev = row[5] or "Low"
            if rank.get(sev, 0) < floor:
                continue
            out.append({
                "id": row[0], "run_ts": row[1], "ip": row[2],
                "template_id": row[3], "name": row[4] or "",
                "severity": sev, "matched_at": row[6] or "",
                "description": row[7] or "", "cves": row[8] or ""})
    return out


def nuclei_open_counts_by_ip():
    """{ip: count} of open Nuclei findings, for the attack-surface view."""
    with _lock:
        conn = _db()
        return {ip: n for ip, n in conn.execute(
            "SELECT ip, COUNT(*) FROM nuclei_findings"
            " WHERE status='open' AND severity IN ('Medium','High')"
            " GROUP BY ip")}


# --- software inventory + CVE correlation ------------------------------------
# The sensor box's own installed software, matched against CISA's
# known-exploited-vulnerabilities list kept in ti_entries (kind='cve',
# see netmon/swaudit.py + netmon/threatintel.py). Quiet by design: a
# match alerts once, then stays silent until it is gone.


def record_sw_inventory(rows, ts):
    """Replace the current inventory snapshot.

    rows: iterable of (name, version, source). Returns the row count.
    """
    clean = []
    for name, version, source in rows or []:
        name = (name or "").strip()[:200]
        source = (source or "").strip()[:16]
        if not name or not source:
            continue
        clean.append((name, (version or "").strip()[:64], source, ts))
    with _lock:
        conn = _db()
        conn.execute("DELETE FROM sw_inventory")
        conn.executemany(
            "INSERT INTO sw_inventory (name, version, source, seen_ts)"
            " VALUES (?,?,?,?)"
            " ON CONFLICT(name, source) DO UPDATE SET"
            " version=excluded.version, seen_ts=excluded.seen_ts",
            clean)
        conn.commit()
    return len(clean)


def list_sw_inventory(limit=2000):
    try:
        limit = max(1, min(5000, int(limit)))
    except (TypeError, ValueError):
        limit = 2000
    with _lock:
        conn = _db()
        return [{"name": n, "version": v or "", "source": s or ""}
                for n, v, s in conn.execute(
                    "SELECT name, version, source FROM sw_inventory"
                    " ORDER BY source, name LIMIT ?", (limit,))]


def list_kev_entries():
    """The local CISA KEV list: [{cve_id, vendor, product, vuln_name,
    description, due_date}]. Read from the ti_entries feed rows."""
    import json as _json
    out = []
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT key, detail FROM ti_entries WHERE kind='cve'").fetchall()
    for cve_id, detail in rows:
        try:
            d = _json.loads(detail or "{}")
        except Exception:
            d = {}
        out.append({
            "cve_id": cve_id or "",
            "vendor": d.get("v", "") or "",
            "product": d.get("p", "") or "",
            "vuln_name": d.get("n", "") or "",
            "description": d.get("d", "") or "",
            "due_date": d.get("due", "") or "",
        })
    return out


def record_cve_matches(ts, matches):
    """Store matches; return only the genuinely NEW (package, cve_id)
    pairs so alerting fires once per match.

    matches: iterable of dicts with package, version, source, cve_id,
    vendor, product, vuln_name, description, due_date.
    """
    with _lock:
        conn = _db()
        known = {(p, c) for p, c in conn.execute(
            "SELECT package, cve_id FROM cve_matches")}
        new = []
        for m in matches or []:
            pkg, cve = (m.get("package") or "")[:200], \
                       (m.get("cve_id") or "")[:32]
            if not pkg or not cve or (pkg, cve) in known:
                continue
            known.add((pkg, cve))
            new.append(m)
            conn.execute(
                "INSERT INTO cve_matches (ts, package, version, source,"
                " cve_id, vendor, product, vuln_name, description, due_date)"
                " VALUES (?,?,?,?,?,?,?,?,?,?)"
                " ON CONFLICT(package, cve_id) DO NOTHING",
                (ts, pkg, (m.get("version") or "")[:64],
                 (m.get("source") or "")[:16], cve,
                 (m.get("vendor") or "")[:120],
                 (m.get("product") or "")[:200],
                 (m.get("vuln_name") or "")[:200],
                 (m.get("description") or "")[:1000],
                 (m.get("due_date") or "")[:16]))
        # Drop matches that no longer apply (package updated/removed or
        # the CVE left the KEV list): quiet cleanup, no alerts.
        current = {( (m.get("package") or "")[:200],
                     (m.get("cve_id") or "")[:32]) for m in matches or []}
        for pkg, cve in list(known):
            if (pkg, cve) not in current:
                conn.execute("DELETE FROM cve_matches"
                             " WHERE package=? AND cve_id=?", (pkg, cve))
        conn.commit()
    return new


def list_cve_matches(limit=200):
    try:
        limit = max(1, min(2000, int(limit)))
    except (TypeError, ValueError):
        limit = 200
    with _lock:
        conn = _db()
        return [
            {"package": p, "version": v or "", "source": s or "",
             "cve_id": c, "vendor": vd or "", "product": pr or "",
             "vuln_name": n or "", "description": d or "",
             "due_date": dd or "", "first_seen": ts or 0}
            for p, v, s, c, vd, pr, n, d, dd, ts in conn.execute(
                "SELECT package, version, source, cve_id, vendor, product,"
                " vuln_name, description, due_date, ts FROM cve_matches"
                " ORDER BY ts DESC LIMIT ?", (limit,))]


# --- host events (Windows Event Log + firewall log ingestion) -------------
# Parsed from exported logs watched by netmon/ingest.py (see INGEST.md).
# Degrades gracefully: an empty table just means no logs were provided.


def insert_host_events(rows):
    """rows: list of (ts, source, event_id, computer, user_name, detail)."""
    if not rows:
        return
    with _lock:
        conn = _db()
        conn.executemany(
            "INSERT INTO host_events (ts, source, event_id, computer,"
            " user_name, detail) VALUES (?,?,?,?,?,?)",
            [(ts, (source or "")[:16], str(event_id or "")[:16],
              (computer or "")[:128], (user_name or "")[:128],
              (detail or "")[:2000])
             for ts, source, event_id, computer, user_name, detail in rows],
        )
        conn.commit()


def host_events_since(ts, limit=200):
    with _lock:
        conn = _db()
        return [
            {"id": i, "ts": t, "source": s, "event_id": e,
             "computer": c or "", "user_name": u or "",
             "detail": d or "", "matched_alert": m}
            for i, t, s, e, c, u, d, m in conn.execute(
                "SELECT id, ts, source, event_id, computer, user_name,"
                " detail, matched_alert FROM host_events WHERE ts > ?"
                " ORDER BY ts DESC LIMIT ?", (ts, limit))]


def mark_host_event_matched(event_id, alert_id):
    with _lock:
        conn = _db()
        conn.execute("UPDATE host_events SET matched_alert=? WHERE id=?",
                     (alert_id, event_id))
        conn.commit()


def ingest_state_get(path):
    with _lock:
        conn = _db()
        try:
            row = conn.execute(
                "SELECT mtime, offset, last_run_ts, inode FROM ingest_state"
                " WHERE path=?", (path,)).fetchone()
        except Exception:
            # Pre-migration database: the inode column may not exist yet.
            row = conn.execute(
                "SELECT mtime, offset, last_run_ts FROM ingest_state"
                " WHERE path=?", (path,)).fetchone()
            if not row:
                return None
            return {"mtime": row[0], "offset": row[1],
                    "last_run_ts": row[2], "inode": None}
    if not row:
        return None
    return {"mtime": row[0], "offset": row[1], "last_run_ts": row[2],
            "inode": row[3]}


def ingest_state_set(path, mtime, offset, inode=None):
    import time as _t
    with _lock:
        conn = _db()
        try:
            conn.execute(
                "INSERT INTO ingest_state (path, mtime, offset, last_run_ts,"
                " inode) VALUES (?,?,?,?,?)"
                " ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime,"
                " offset=excluded.offset, last_run_ts=excluded.last_run_ts,"
                " inode=excluded.inode",
                (path, mtime, offset, _t.time(), inode))
        except Exception:
            # Pre-migration database: fall back to the old column set.
            conn.execute(
                "INSERT INTO ingest_state (path, mtime, offset, last_run_ts)"
                " VALUES (?,?,?,?)"
                " ON CONFLICT(path) DO UPDATE SET mtime=excluded.mtime,"
                " offset=excluded.offset, last_run_ts=excluded.last_run_ts",
                (path, mtime, offset, _t.time()))
        conn.commit()


# --- sensor-box self-health baselines ---------------------------------------
# netmon/selfcheck.py stores one JSON blob per check here. First run
# learns the baseline (no alert); later runs compare and alert on drift.


def selfcheck_baseline_get(check_name):
    raw = get_meta(f"selfcheck_base_{check_name}")
    if not raw:
        return None
    try:
        return json.loads(raw)
    except Exception:
        return None


def selfcheck_baseline_set(check_name, value):
    set_meta(f"selfcheck_base_{check_name}", json.dumps(value))


# --- internet uptime log ---------------------------------------------------
# The outages table already records every watchdog drop (Phase 3). This
# productizes it: weekly stats for the dashboard's uptime view.


def outage_stats(days=7):
    """Downtime summary for the last `days` days.

    Returns {count, total_s, longest_s, uptime_pct, ongoing_s} where
    ongoing_s is the length of a currently-open outage (0 if none).
    """
    import time as _t
    now = _t.time()
    cutoff = now - days * 86400
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT start_ts, gap_seconds FROM outages"
            " WHERE start_ts > ? AND end_ts IS NOT NULL", (cutoff,)).fetchall()
        ongoing = conn.execute(
            "SELECT start_ts FROM outages WHERE end_ts IS NULL"
            " ORDER BY start_ts DESC LIMIT 1").fetchone()
    gaps = [(max(0.0, s - cutoff), g or 0.0) for s, g in rows]
    # Only count the portion of each outage inside the window.
    total = 0.0
    longest = 0.0
    for start, gap in gaps:
        end = start + gap
        inside = max(0.0, min(end, now - cutoff) - max(start, 0.0))
        total += inside
        longest = max(longest, inside)
    ongoing_s = (now - ongoing[0]) if ongoing else 0.0
    window = now - cutoff
    uptime_pct = max(0.0, min(100.0, 100.0 * (window - total) / window))
    return {"count": len(rows), "total_s": total, "longest_s": longest,
            "uptime_pct": uptime_pct, "ongoing_s": ongoing_s}


def list_outages(limit=30):
    """Recent outage log, newest first: target, start, end, duration."""
    with _lock:
        conn = _db()
        return [
            {"id": i, "target": t or "", "start_ts": s,
             "end_ts": e, "gap_seconds": g}
            for i, t, s, e, g in conn.execute(
                "SELECT id, target, start_ts, end_ts, gap_seconds"
                " FROM outages ORDER BY start_ts DESC LIMIT ?", (limit,))]


# --- threat intel ("rap sheets") -------------------------------------------
# Local copy of community blocklists (netmon/threatintel.py). Lookups
# hit ti_entries first: fast, offline-capable, no per-lookup API calls.
# Feed refreshes swap one feed's rows atomically, preserving first_seen
# for keys that were already listed.


def ti_replace_feed(feed, kind, entries):
    """Atomically replace one feed's rows.

    entries: iterable of (key, detail). Keys already listed keep their
    original first_seen; last_seen becomes now for every fresh row.
    """
    import time as _t
    now = _t.time()
    feed = (feed or "").strip()[:64]
    kind = (kind or "").strip()[:16]
    clean = []
    for key, detail in entries or []:
        key = (str(key or "").strip().lower()
               if kind == "domain" else str(key or "").strip())
        if not key:
            continue
        clean.append((key, (detail or "")[:300]))
    with _lock:
        conn = _db()
        old = {r[0]: r[1] for r in conn.execute(
            "SELECT key, first_seen FROM ti_entries"
            " WHERE feed=? AND kind=?", (feed, kind))}
        conn.execute("DELETE FROM ti_entries WHERE feed=? AND kind=?",
                     (feed, kind))
        conn.executemany(
            "INSERT INTO ti_entries (key, kind, feed, detail, first_seen,"
            " last_seen) VALUES (?,?,?,?,?,?)",
            [(k, kind, feed, d, old.get(k, now), now) for k, d in clean])
        conn.execute(
            "INSERT INTO meta (key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (f"ti_feed_updated_{feed}", str(now)))
        conn.commit()
    return len(clean)


def ti_lookup(kind, keys):
    """Local feed hits for a batch of keys.

    Returns {key: [{feed, detail, first_seen, last_seen}]}; keys with no
    hits map to []. Chunked so arbitrarily long key lists stay within
    SQLite's variable limit.
    """
    keys = [k for k in dict.fromkeys(keys or []) if k]
    out = {k: [] for k in keys}
    if not keys:
        return out
    with _lock:
        conn = _db()
        for i in range(0, len(keys), 500):
            chunk = keys[i:i + 500]
            rows = conn.execute(
                "SELECT key, feed, detail, first_seen, last_seen"
                " FROM ti_entries WHERE kind=? AND key IN (%s)"
                % ",".join("?" * len(chunk)),
                (kind, *chunk)).fetchall()
            for key, feed, detail, first_seen, last_seen in rows:
                out.setdefault(key, []).append({
                    "feed": feed or "", "detail": detail or "",
                    "first_seen": first_seen, "last_seen": last_seen})
    return out


def ti_feed_status():
    """Per-feed status for the dashboard: [{feed, kind, entries,
    last_updated}] with the feed's human label looked up from
    threatintel's registry when available.

    Pipeline robustness (batch 14): each feed also carries "stale" --
    True when the feed never loaded or its last successful refresh is
    older than twice the refresh interval. A failed refresh keeps the
    old rows (see refresh_feeds); "stale" tells the dashboard to say so
    instead of silently serving old data. See also ti_feed_health() for
    the global attempt state.
    """
    labels = {}
    try:
        from . import threatintel as tim
        labels = {n: s.get("label", n) for n, s in tim._FEEDS.items()}
    except Exception:
        pass
    now = time.time()
    try:
        _interval_h = float(tim.FEED_REFRESH_HOURS)
    except Exception:
        _interval_h = 12.0
    stale_after_s = 2 * _interval_h * 3600
    with _lock:
        conn = _db()
        rows = conn.execute(
            "SELECT feed, kind, COUNT(*) FROM ti_entries"
            " GROUP BY feed, kind").fetchall()
        updates = {r[0]: r[1] for r in conn.execute(
            "SELECT key, value FROM meta WHERE key LIKE 'ti_feed_updated\\_%'"
            " ESCAPE '\\'")}
    out = []
    for feed, kind, count in rows:
        raw = updates.get(f"ti_feed_updated_{feed}")
        try:
            updated = float(raw) if raw else 0
        except (TypeError, ValueError):
            updated = 0
        stale = (not updated) or (now - updated > stale_after_s)
        out.append({"feed": feed, "label": labels.get(feed, feed),
                    "kind": kind, "entries": count,
                    "last_updated": updated or None,
                    "stale": stale})
    return sorted(out, key=lambda r: r["feed"])


def ti_feed_health():
    """Global feed-refresh health: was the last attempt a failure?

    Returns {"last_attempt_ts", "last_success_ts", "failed_recently"}.
    failed_recently is True when an attempt happened after the last
    success -- i.e. the network is down (or the feeds are) and the
    dashboard is serving cached lists. Never raises.
    """
    def _f(key):
        try:
            return float(get_meta(key) or 0)
        except (TypeError, ValueError):
            return 0
        except Exception:
            return 0
    try:
        attempted = _f("ti_feeds_attempted_ts")
        succeeded = _f("ti_feeds_refreshed_ts")
        return {"last_attempt_ts": attempted or None,
                "last_success_ts": succeeded or None,
                "failed_recently": bool(attempted and attempted > succeeded)}
    except Exception:
        return {"last_attempt_ts": None, "last_success_ts": None,
                "failed_recently": False}


def ti_entry_count():
    """Total rows in the local threat-intel tables."""
    with _lock:
        conn = _db()
        return conn.execute(
            "SELECT COUNT(*) FROM ti_entries").fetchone()[0]


def query(sql, params=()):
    """Read-only helper for the dashboard/explainer."""
    with _lock:
        conn = _db()
        return conn.execute(sql, params).fetchall()

