"""netmon/retention.py -- data retention policy for Project Orion.

SQLite grows forever otherwise. Each data type keeps a rolling window,
configured in config.yaml under ``retention`` (defaults: flows 30d,
alerts 1y, summaries 90d, score snapshots 1y). A scheduled
prune job (daily, from the monitor loop) deletes expired rows; the
dashboard's Settings panel shows the policy and the last prune run, and
owners can trigger a prune on demand.

SAFETY RULES (deliberate, documented):
  * Alerts attached to OPEN or ESCALATED cases are NEVER pruned -- only
    history that is no longer actionable goes. (Every alert lands in a
    case, even a keyless one; closing the case makes its old alerts
    prunable.) The case rows themselves are kept (they are small; they
    are the record).
  * Deletes run in bounded batches (prune_batch rows per DELETE, default
    5000) so the database never locks for minutes on a big prune.
  * Ongoing outages (end_ts NULL) are never pruned, whatever their age.
  * Scan findings, threat-intel feeds, the asset inventory, device
    names/types, the allowlist, and the audit trail are NOT pruned here:
    findings describe current exposure (small), feeds are replaced
    wholesale on refresh, the rest is configuration -- and the audit log
    is append-only by design (batch 9: the trail cannot be rewritten
    after the fact), so retention never touches it.
  * The forensic rewind buffer has its own hard bounds (rewind_minutes /
    rewind_max_mb, enforced by netmon/rewind.py) and is not pruned here.

Every prune logs one stderr line naming what was deleted. Quiet is a
feature: pruning never alerts, never emails.

Stdlib only. Nothing here raises out of its public helpers.
"""
import json
import sys
import time

from . import db as dbm
from . import config as cfgm

# All prune SQL is literal: table and column names are baked into these
# module constants, never interpolated from variables. Parameters always
# travel as ? placeholders. (The release gate's B-SQL audit trusts
# literals at the use site; more importantly, there is no code path by
# which an identifier could come from anything but this module.)
_PRUNE_SQL = {
    "flows": "DELETE FROM flows WHERE ts < ? LIMIT ?",
    "dns_queries": "DELETE FROM dns_queries WHERE ts < ? LIMIT ?",
    "arp_observations": "DELETE FROM arp_observations WHERE ts < ? LIMIT ?",
    "summaries": "DELETE FROM summaries WHERE ts < ? LIMIT ?",
    "outages": ("DELETE FROM outages WHERE start_ts < ?"
                " AND end_ts IS NOT NULL LIMIT ?"),
    "score_snapshots": "DELETE FROM score_snapshots WHERE ts < ? LIMIT ?",
}
# Alerts attached to OPEN or ESCALATED cases are never pruned -- only
# history that is no longer actionable goes. The same expired batch is
# selected twice (mappings, then alerts) with an identical ORDER BY id
# LIMIT subquery, so both DELETEs cover exactly the same rows; new alerts
# always carry ts=now > cutoff and can never slip into the batch.
_ALERT_EXPIRED = (
    "SELECT id FROM alerts WHERE ts < ?"
    " AND NOT EXISTS (SELECT 1 FROM incident_alerts ia"
    " JOIN incidents i ON i.id = ia.incident_id"
    " WHERE ia.alert_id = alerts.id"
    " AND i.status IN ('open','escalated'))"
    " ORDER BY id LIMIT ?")
_PRUNE_ALERT_MAPPINGS = (
    "DELETE FROM incident_alerts WHERE alert_id IN (" + _ALERT_EXPIRED + ")")
_PRUNE_ALERTS = (
    "DELETE FROM alerts WHERE id IN (" + _ALERT_EXPIRED + ")")

# (table, config_key) for every pruned data type, in prune order.
_TABLES = [
    ("flows", "flows_days"),
    ("dns_queries", "observations_days"),
    ("arp_observations", "observations_days"),
    ("summaries", "summaries_days"),
    ("outages", "outages_days"),
    ("score_snapshots", "score_snapshots_days"),
    # alerts last: its mapping rows are deleted in the same pass so no
    # orphan references survive.
    ("alerts", "alerts_days"),
]
# NOTE: audit_log is deliberately absent -- it is append-only by design
# (see the module docstring); retention never deletes from it.

_LAST_RUN_KEY = "retention_last_run_ts"
_LAST_COUNTS_KEY = "retention_last_counts"


def _log(msg):
    try:
        print(f"netmon retention: {msg}", file=sys.stderr)
    except Exception:
        pass


def policy(cfg=None):
    """{config_key: days} for every pruned data type. Never raises."""
    cfg = cfg if cfg is not None else cfgm.load_cached()
    out = {}
    try:
        for _table, key in _TABLES:
            try:
                out[key] = int(cfgm.get(cfg, f"retention.{key}", 0) or 0)
            except (TypeError, ValueError):
                out[key] = 0
    except Exception:
        pass
    return out


def _prune_table(table, cutoff, batch):
    """Delete expired rows from one table in bounded batches.

    Returns the total rows deleted. For alerts, the case-mapping rows
    are deleted for the same expired batch first (same transaction), so
    no orphan references survive -- while alerts on open/escalated cases
    are never touched.
    """
    total = 0
    try:
        with dbm._lock:
            conn = dbm._db()
            if table == "alerts":
                while True:
                    conn.execute(_PRUNE_ALERT_MAPPINGS, (cutoff, batch))
                    cur = conn.execute(_PRUNE_ALERTS, (cutoff, batch))
                    n = cur.rowcount or 0
                    conn.commit()
                    total += n
                    if n < batch:
                        break
            else:
                sql = _PRUNE_SQL[table]
                while True:
                    cur = conn.execute(sql, (cutoff, batch))
                    n = cur.rowcount or 0
                    conn.commit()
                    total += n
                    if n < batch:
                        break
    except Exception as exc:
        _log(f"prune of {table} failed partway ({exc!r});"
             f" {total} rows deleted before the failure")
    return total


def prune_once(now=None, batch=None, cfg=None):
    """Run one full prune pass. Returns {table: rows_deleted}.

    Bounded batches keep every DELETE short; a failure in one table is
    logged and the pass continues with the next. Never raises.
    """
    now = now if now is not None else time.time()
    cfg = cfg if cfg is not None else cfgm.load_cached()
    try:
        batch = int(batch if batch is not None
                    else cfgm.get(cfg, "retention.prune_batch", 5000))
    except (TypeError, ValueError):
        batch = 5000
    batch = max(100, min(batch, 100000))
    pol = policy(cfg)
    counts = {}
    for table, key in _TABLES:
        days = pol.get(key, 0)
        if not days or days <= 0:
            continue  # 0/negative disables pruning for this type
        cutoff = now - days * 86400
        counts[table] = _prune_table(table, cutoff, batch)
    kept = ", ".join(f"{t}: {n}" for t, n in counts.items() if n) or "none"
    _log(f"prune pass deleted -- {kept}")
    try:
        dbm.set_meta(_LAST_RUN_KEY, str(now))
        dbm.set_meta(_LAST_COUNTS_KEY, json.dumps(counts))
    except Exception:
        pass
    return counts


def last_prune():
    """(run_ts|None, {table: rows}|None) for the most recent prune pass."""
    try:
        raw_ts = dbm.get_meta(_LAST_RUN_KEY)
        raw_counts = dbm.get_meta(_LAST_COUNTS_KEY)
        ts = float(raw_ts) if raw_ts else None
    except (TypeError, ValueError):
        return None, None
    except Exception:
        return None, None
    try:
        counts = json.loads(raw_counts) if raw_counts else None
    except Exception:
        counts = None
    return ts, counts


def maybe_prune(now=None, cfg=None):
    """Run prune_once() when the scheduled interval has elapsed.

    Called from the monitor loop via pipeline.safe_step -- best-effort,
    never breaks the loop. Returns the counts dict, or None when the
    prune is disabled or not yet due. Never raises.
    """
    now = now if now is not None else time.time()
    try:
        cfg = cfg if cfg is not None else cfgm.load_cached()
        if not cfgm.get(cfg, "retention.prune_enabled", True):
            return None
        try:
            interval_h = float(cfgm.get(cfg, "retention.prune_interval_hours",
                                        24))
        except (TypeError, ValueError):
            interval_h = 24
        if interval_h <= 0:
            return None
        last_ts, _ = last_prune()
        if last_ts and now - last_ts < interval_h * 3600:
            return None
        return prune_once(now=now, cfg=cfg)
    except Exception as exc:
        _log(f"scheduled prune failed: {exc!r}")
        return None
