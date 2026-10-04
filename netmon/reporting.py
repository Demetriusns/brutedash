"""netmon/reporting.py -- "prove it": score card, morning briefing, reports.

Three jobs, all deterministic (code decides, the LLM never does):

1. SECURITY SCORE CARD (0-100): one grade for the network with a
   plain-English "here's why". The formula is documented below and in
   code comments; every deduction is capped so one bad week can't nuke
   the score. Empty database -> a neutral "not enough data yet", never
   0-as-punishment.

   THE FORMULA (all inputs from the last 7 days unless noted):
     start at 100
     - alerts (not dismissed): Critical -15, High -8, Medium -3, Low -1
       each; alert deductions capped at -40 total
     - open cases: open -5 each, escalated ("awaiting admin") -3 each;
       capped at -15 total
     - attack-surface exposures (the current review, read-only): High -6,
       Medium -3, Low -1 each; capped at -15 total
     - open vulnerability findings (self door-check + Nuclei, Medium+):
       -4 each; capped at -12 total
     - sensor health: -10 if no flow data in the last 30 minutes (the
       monitor is flying blind); otherwise 0
     floor 0, ceiling 100.

   Score snapshots are recorded daily (score_snapshots table) so the
   dashboard can draw the trend.

2. DAILY MORNING BRIEFING: one email per day (never per alert) covering
   the last 24h -- new alerts by severity, cases opened/still open,
   score + change, quiet wins ("you dismissed X, so it's quieter now"),
   top exposures, dashboard link. Honors quiet hours (deferred, not
   dropped). Reuses notify.py's SMTP path and its CR/LF cleaning.

3. COMPLIANCE REPORTS: weekly/monthly summaries with the fields an
   auditor asks for -- incidents by category with MITRE tags, response
   actions taken (quarantines, releases, escalations, dismissals with
   reasons), alert volume trends, score history. Exported as clean
   print-friendly HTML and as CSV, both downloadable from the
   dashboard's Reports section. Incident briefs and the weekly summary
   also export as text-layout PDFs (see pdfgen.py).

Voice rule: casual, plain-spoken, non-technical. No medical/doctor
language anywhere in here.
"""
import csv
import html
import io
import json
import time
from datetime import datetime

from . import config as cfgm
from . import db as dbm

SEV_WEIGHTS = {"Critical": 15, "High": 8, "Medium": 3, "Low": 1}
ALERT_POINTS_CAP = 40
INCIDENT_POINTS_CAP = 15
EXPOSURE_WEIGHTS = {"High": 6, "Medium": 3, "Low": 1}
EXPOSURE_POINTS_CAP = 15
VULN_POINTS_EACH = 4
VULN_POINTS_CAP = 12
STALE_MINUTES = 30
STALE_POINTS = 10
SCORE_WINDOW = 7 * 24 * 3600

_FACTOR_LINKS = {
    "alerts": "#alerts",
    "incidents": "#cases",
    "exposures": "#surface",
    "vulns": "#scan",
    "health": "#overview",
}

# Email sender indirection for tests: None = really send via notify._send.
_SEND_FUNC = None


# --- security score card ----------------------------------------------------

def _alert_points(since):
    """(points, factors) for 7d non-dismissed alerts."""
    try:
        rows = dbm.query(
            "SELECT severity, COUNT(*) FROM alerts WHERE ts > ?"
            " AND (status IS NULL OR status != 'dismissed')"
            " GROUP BY severity", (since,))
    except Exception:
        rows = []
    points = 0
    factors = []
    for sev, count in rows:
        sev = (sev or "").strip()
        weight = SEV_WEIGHTS.get(sev)
        if not weight or not count:
            continue
        lost = weight * count
        points += lost
        word = {"Critical": "critical", "High": "high-urgency",
                "Medium": "medium", "Low": "low-key"}.get(sev, sev.lower())
        factors.append({
            "kind": "alerts", "severity": sev, "count": count,
            "points": lost,
            "label": (f"{count} {word} alert{'s' if count != 1 else ''}"
                      f" in the last 7 days"),
            "link": _FACTOR_LINKS["alerts"],
        })
    if points > ALERT_POINTS_CAP:
        scale = ALERT_POINTS_CAP / points
        points = ALERT_POINTS_CAP
        for f in factors:
            f["points"] = int(round(f["points"] * scale))
    return points, factors


def _incident_points():
    """(points, factors) for currently open/escalated cases."""
    try:
        rows = dbm.query(
            "SELECT status, COUNT(*) FROM incidents WHERE status IN"
            " ('open', 'escalated') GROUP BY status")
    except Exception:
        rows = []
    weights = {"open": 5, "escalated": 3}
    words = {"open": "open case", "escalated": "case waiting on the admin"}
    points = 0
    factors = []
    for status, count in rows:
        weight = weights.get(status or "", 0)
        if not weight or not count:
            continue
        lost = weight * count
        points += lost
        word = words[status]
        factors.append({
            "kind": "incidents", "severity": "", "count": count,
            "points": lost,
            "label": (f"{count} {word}{'s' if count != 1 else ''}"),
            "link": _FACTOR_LINKS["incidents"],
        })
    if points > INCIDENT_POINTS_CAP:
        scale = INCIDENT_POINTS_CAP / points
        points = INCIDENT_POINTS_CAP
        for f in factors:
            f["points"] = int(round(f["points"] * scale))
    return points, factors


def _exposure_points(now):
    """(points, factors) from the current attack-surface review.

    Read-only: building the review never fires alerts or writes the
    alerts table (verified in attacksurface's own tests)."""
    try:
        from . import attacksurface as asm
        report = asm.build_report(now=now)
    except Exception:
        return 0, []
    if not report.get("ok"):
        return 0, []
    counts = report.get("counts") or {}
    points = 0
    factors = []
    for sev in ("High", "Medium", "Low"):
        count = int(counts.get(sev) or 0)
        if not count:
            continue
        lost = EXPOSURE_WEIGHTS[sev] * count
        points += lost
        word = {"High": "serious", "Medium": "worth-a-look",
                "Low": "minor"}.get(sev)
        factors.append({
            "kind": "exposures", "severity": sev, "count": count,
            "points": lost,
            "label": (f"{count} {word} exposure{'s' if count != 1 else ''}"
                      f" on your devices"),
            "link": _FACTOR_LINKS["exposures"],
        })
    if points > EXPOSURE_POINTS_CAP:
        scale = EXPOSURE_POINTS_CAP / points
        points = EXPOSURE_POINTS_CAP
        for f in factors:
            f["points"] = int(round(f["points"] * scale))
    return points, factors


def _vuln_points():
    """(points, factors) for open door-check + Nuclei findings (Medium+)."""
    total = 0
    try:
        rows = dbm.query(
            "SELECT COUNT(*) FROM scan_findings WHERE status='open'"
            " AND risk IN ('Medium', 'High')")
        total += rows[0][0] if rows else 0
    except Exception:
        pass
    try:
        rows = dbm.query(
            "SELECT COUNT(*) FROM nuclei_findings WHERE status='open'"
            " AND severity IN ('Medium', 'High')")
        total += rows[0][0] if rows else 0
    except Exception:
        pass
    points = min(total * VULN_POINTS_EACH, VULN_POINTS_CAP)
    factors = []
    if total:
        factors.append({
            "kind": "vulns", "severity": "", "count": total,
            "points": points,
            "label": (f"{total} open vulnerability finding"
                      f"{'s' if total != 1 else ''} from the door checks"),
            "link": _FACTOR_LINKS["vulns"],
        })
    return points, factors


def _health_points(now):
    """(points, factors): -10 when the monitor is flying blind (no flow
    data in the last STALE_MINUTES)."""
    try:
        rows = dbm.query("SELECT MAX(ts) FROM flows")
        latest = rows[0][0] if rows else None
    except Exception:
        latest = None
    if latest is None:
        return 0, []  # no flows at all: the neutral check handles that
    if now - float(latest) > STALE_MINUTES * 60:
        return STALE_POINTS, [{
            "kind": "health", "severity": "", "count": 1,
            "points": STALE_POINTS,
            "label": "no fresh data -- the monitor may have stopped",
            "link": _FACTOR_LINKS["health"],
        }]
    return 0, []


def _has_any_data():
    """True when the monitor has seen anything at all (flows, alerts,
    assets, or scan runs). Used for the neutral default."""
    for sql in ("SELECT 1 FROM flows LIMIT 1",
                "SELECT 1 FROM alerts LIMIT 1",
                "SELECT 1 FROM assets LIMIT 1",
                "SELECT 1 FROM scan_runs LIMIT 1"):
        try:
            if dbm.query(sql):
                return True
        except Exception:
            pass
    return False


def compute_score(now=None):
    """Compute the 0-100 security score. Deterministic: same database
    state -> same score, every time. Never the LLM.

    Returns {"score": int|None, "neutral": bool, "factors": [...],
    "as_of": ts}. A fresh/empty database returns score None with
    neutral=True -- "not enough data yet", never 0-as-punishment."""
    now = now if now is not None else time.time()
    if not _has_any_data():
        return {"score": None, "neutral": True, "factors": [],
                "as_of": now}
    since = now - SCORE_WINDOW
    total_lost = 0
    factors = []
    for points, new_factors in (
            _alert_points(since),
            _incident_points(),
            _exposure_points(now),
            _vuln_points(),
            _health_points(now)):
        total_lost += points
        factors.extend(new_factors)
    score = max(0, min(100, 100 - total_lost))
    factors.sort(key=lambda f: (-f["points"], f["kind"]))
    return {"score": score, "neutral": False, "factors": factors,
            "as_of": now}

# --- score history + "here's why" -------------------------------------------


def record_score_snapshot(now=None):
    """Record today's score for the trend. Idempotent per local day.
    Returns the computed score dict."""
    now = now if now is not None else time.time()
    data = compute_score(now=now)
    day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
    try:
        with dbm._lock:
            conn = dbm._db()
            conn.execute(
                "INSERT OR REPLACE INTO score_snapshots(day, ts, score,"
                " factors) VALUES (?, ?, ?, ?)",
                (day, now, data["score"],
                 json.dumps(data["factors"])))
            conn.commit()
    except Exception:
        pass
    return data


def maybe_daily_score(now=None):
    """Record today's snapshot if missing. Returns True when recorded."""
    now = now if now is not None else time.time()
    day = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
    try:
        rows = dbm.query("SELECT 1 FROM score_snapshots WHERE day=?",
                         (day,))
        if rows:
            return False
    except Exception:
        return False
    record_score_snapshot(now=now)
    return True


def score_history(days=14):
    """Newest-first list of {"day", "score"} for the trend view."""
    try:
        rows = dbm.query(
            "SELECT day, score FROM score_snapshots ORDER BY day DESC"
            " LIMIT ?", (int(days),))
    except Exception:
        rows = []
    return [{"day": r[0], "score": r[1]} for r in rows]


def explain_score(data):
    """Deterministic casual paragraph: the score + why + what would
    raise it. Built from the top contributing factors -- never the LLM,
    never medical/doctor language."""
    if data.get("neutral") or data.get("score") is None:
        return ("Not enough data yet -- give the monitor a day or two of"
                " watching your network and it will start grading.")
    score = data["score"]
    factors = data.get("factors") or []
    if not factors:
        return (f"Your network scored {score} out of 100. Nothing pulled"
                " points off -- no alerts worth worrying about, no open"
                " cases, no exposed doors found. A quiet network is a"
                " healthy network.")
    top = factors[:2]
    reasons = "; ".join(f["label"] for f in top)
    text = (f"Your network scored {score} out of 100. Here's what pulled"
            f" it down: {reasons}.")
    # One concrete "do this" from the biggest factor.
    kind = top[0]["kind"]
    if kind == "alerts":
        text += (" To bring it up: work through the alerts list --"
                 " acknowledging or dismissing what you recognize clears"
                 " the points those alerts cost.")
    elif kind == "incidents":
        text += (" To bring it up: close out the open cases once you've"
                 " looked them over.")
    elif kind == "exposures":
        text += (" To bring it up: shut the exposed doors you don't need"
                 " -- the Attack surface section shows each one and how"
                 " to fix it.")
    elif kind == "vulns":
        text += (" To bring it up: fix or accept the open findings from"
                 " the door checks.")
    elif kind == "health":
        text += (" To bring it up: make sure the monitor is still running"
                 " -- fresh data is what the score is built on.")
    return text


# --- daily morning briefing -------------------------------------------------
# One email per day, never per alert. Scheduled by run.py's monitor loop;
# also sendable on demand from the dashboard.

BRIEFING_WINDOW = 24 * 3600


def _briefing_enabled():
    try:
        return bool(cfgm.get(cfgm.load_cached(), "reporting.briefing_enabled",
                             True))
    except Exception:
        return True


def _briefing_hour():
    try:
        v = cfgm.get(cfgm.load_cached(), "reporting.briefing_hour", 7)
        return max(0, min(23, int(v)))
    except (TypeError, ValueError):
        return 7


def dashboard_link():
    """Dashboard URL for emails: host:port from config."""
    try:
        cfg = cfgm.load_cached()
        port = str(cfgm.get(cfg, "dashboard.port", 5001) or 5001)
    except Exception:
        port = "5001"
    try:
        cfg = cfgm.load_cached()
        bind = str(cfgm.get(cfg, "dashboard.host", "127.0.0.1")
                   or "127.0.0.1")
    except Exception:
        bind = "127.0.0.1"
    if bind in ("127.0.0.1", "localhost", "::1"):
        return f"http://localhost:{port}/"
    return f"http://{bind}:{port}/"


def _fmt_when(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%I:%M %p")
    except (TypeError, ValueError):
        return ""


def build_briefing(now=None):
    """Assemble the morning briefing for the last 24h.

    Returns {"subject", "body"}. Pure function of the database -- no
    sending, no side effects. Never raises."""
    now = now if now is not None else time.time()
    since = now - BRIEFING_WINDOW
    try:
        return _build_briefing(now, since)
    except Exception:
        return {"subject": "Your network this morning",
                "body": ("Your network monitor has updates -- open the"
                         " dashboard to see them.\n\n"
                         f"{dashboard_link()}")}


def _build_briefing(now, since):
    sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    alerts = []
    try:
        rows = dbm.query(
            "SELECT severity, title, detail, ts FROM alerts"
            " WHERE ts > ? AND ts <= ?"
            " AND (status IS NULL OR status != 'dismissed')"
            " ORDER BY ts DESC LIMIT 200", (since, now))
        for sev, title, detail, ts in rows:
            alerts.append({"severity": (sev or "Low").strip() or "Low",
                           "title": (title or "").strip(),
                           "detail": (detail or "").strip(),
                           "ts": ts})
        alerts.sort(key=lambda a: (sev_rank.get(a["severity"], 4), -a["ts"]))
    except Exception:
        alerts = []

    by_sev = {}
    for a in alerts:
        by_sev.setdefault(a["severity"], []).append(a)

    opened = []
    try:
        for i in dbm.list_incidents(status="open", limit=200):
            if (i.get("created_ts") or 0) > since:
                opened.append(i)
    except Exception:
        opened = []
    open_count = escalated_count = 0
    try:
        for i in dbm.list_incidents(status="open", limit=500):
            open_count += 1
        for i in dbm.list_incidents(status="escalated", limit=500):
            escalated_count += 1
    except Exception:
        pass

    # Quiet wins: dismissed in the window + learning suggestions decided.
    dismissed = 0
    try:
        rows = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE status='dismissed'"
            " AND ts > ?", (since,))
        dismissed = rows[0][0] if rows else 0
    except Exception:
        pass
    applied = 0
    try:
        rows = dbm.query(
            "SELECT COUNT(*) FROM suggestions WHERE status='applied'"
            " AND decided_ts > ?", (since,))
        applied = rows[0][0] if rows else 0
    except Exception:
        pass

    # Score + change vs yesterday's snapshot.
    score_data = compute_score(now=now)
    score = score_data["score"]
    delta = None
    try:
        hist = score_history(days=3)
        prev = [h for h in hist
                if h["day"] != datetime.fromtimestamp(now).strftime(
                    "%Y-%m-%d") and h["score"] is not None]
        if score is not None and prev:
            delta = score - prev[0]["score"]
    except Exception:
        pass

    # Top exposures from the attack-surface review (read-only).
    exposures = []
    try:
        from . import attacksurface as asm
        rep = asm.build_report(now=now)
        if rep.get("ok"):
            exposures = (rep.get("exposures") or [])[:3]
    except Exception:
        exposures = []

    day_label = datetime.fromtimestamp(now).strftime("%A, %b %d")
    quiet = not alerts and not opened
    if quiet:
        subject = f"Quiet night on your network -- {day_label}"
    else:
        n = len(alerts)
        subject = (f"Your network this morning -- {day_label}"
                   f" ({n} alert{'s' if n != 1 else ''})")

    lines = [f"Good morning -- here's what your network did in the last"
             f" 24 hours ({day_label}).", ""]
    if quiet:
        lines.append("Nothing needed your eyes overnight. "
                     "A quiet network is a healthy network.")
        lines.append("")
    # Score first: the grade, then the detail.
    if score is None:
        lines.append("YOUR SCORE: not enough data yet -- the monitor is"
                     " still learning your network.")
    else:
        bit = f"YOUR SCORE: {score} out of 100"
        if delta:
            bit += f" ({'up' if delta > 0 else 'down'} {abs(delta)} from" \
                   " yesterday)"
        lines.append(bit)
    lines.append("")

    if alerts:
        sev_bits = []
        for sev in ("Critical", "High", "Medium", "Low"):
            c = len(by_sev.get(sev, []))
            if c:
                sev_bits.append(f"{c} {sev.lower()}")
        lines.append(f"ALERTS: {len(alerts)} worth a look"
                     f" ({', '.join(sev_bits)})")
        for a in alerts[:10]:
            when = _fmt_when(a["ts"])
            line = f"- [{a['severity']}] {a['title']}"
            if when:
                line += f" ({when})"
            lines.append(line)
            if a["detail"]:
                lines.append(f"  {a['detail'][:160]}")
        if len(alerts) > 10:
            lines.append(f"  ...and {len(alerts) - 10} more on the"
                         " dashboard.")
        lines.append("")

    lines.append("CASES:")
    if opened:
        for i in opened[:5]:
            lines.append(f"- Opened: {i.get('title') or 'case'}"
                         f" [{i.get('severity') or ''}]")
        if len(opened) > 5:
            lines.append(f"  ...and {len(opened) - 5} more.")
    else:
        lines.append("- No new cases overnight.")
    lines.append(f"- {open_count} open right now"
                 + (f", {escalated_count} waiting on the admin"
                    if escalated_count else "") + ".")
    lines.append("")

    if dismissed or applied:
        lines.append("QUIET WINS:")
        if dismissed:
            lines.append(f"- You dismissed {dismissed} alert"
                         f"{'s' if dismissed != 1 else ''} -- the monitor"
                         " learns from those, so it stays quieter.")
        if applied:
            lines.append(f"- {applied} \"never alert me about this\" rule"
                         f"{'s' if applied != 1 else ''} applied from your"
                         " dismissals.")
        lines.append("")

    if exposures:
        lines.append("EXPOSED DOORS WORTH A LOOK:")
        for e in exposures:
            label = e.get("device") or ""
            title = (e.get("title") or "").strip()
            lines.append(f"- [{e.get('severity') or ''}] {title}"
                         + (f" -- {label}" if label else ""))
        lines.append("")

    lines.append(f"Open your dashboard: {dashboard_link()}")
    return {"subject": subject, "body": "\n".join(lines)}


def send_briefing(now=None):
    """Send the morning briefing email. Returns (True, "") on send,
    (False, reason) otherwise. Never raises. Reuses notify.py's SMTP
    path; the recipient is the same NETMON_ALERT_TO as other mail."""
    try:
        from . import notify as notifm
        cfg = notifm._smtp_config()
        if not cfg["host"] or not cfg["to"]:
            return False, "email isn't configured"
        brief = build_briefing(now=now)
        subject = notifm._clean(brief["subject"])
        body = notifm._clean(brief["body"])
        sender = _SEND_FUNC or (lambda s, b: notifm._send(cfg, s, b))
        sender(subject, body)
        return True, ""
    except Exception as exc:
        return False, str(exc) or "send failed"


def maybe_daily_briefing(now=None):
    """Send the briefing once per day at/after briefing_hour.

    Returns a status string: "disabled", "not_configured",
    "not_yet" (before the hour), "deferred_quiet" (quiet hours --
    retried on the next monitor tick, not dropped), "already_sent",
    "sent", or "failed". Never raises."""
    now = now if now is not None else time.time()
    try:
        if not _briefing_enabled():
            return "disabled"
        try:
            from . import notify as notifm
            cfg = notifm._smtp_config()
            if not cfg["host"] or not cfg["to"]:
                return "not_configured"
        except Exception:
            return "not_configured"
        today = datetime.fromtimestamp(now).strftime("%Y-%m-%d")
        last = dbm.get_meta("last_briefing_day")
        if last == today:
            return "already_sent"
        if datetime.fromtimestamp(now).hour < _briefing_hour():
            return "not_yet"
        try:
            if notifm.in_quiet_hours("briefing", now):
                return "deferred_quiet"
        except Exception:
            pass
        ok, _reason = send_briefing(now=now)
        if ok:
            dbm.set_meta("last_briefing_day", today)
            return "sent"
        return "failed"
    except Exception:
        return "failed"

# --- compliance-ready reports ------------------------------------------------
# Weekly/monthly summaries with the fields an auditor asks for: incidents
# by category with MITRE tags, response actions taken, alert volume
# trends, score history. HTML is clean and print-friendly; CSV carries
# the same data in flat sections an auditor can open in a spreadsheet.

PERIOD_DAYS = {"weekly": 7, "monthly": 30}


def _site_name():
    try:
        return str(cfgm.get(cfgm.load_cached(), "general.site_name",
                            "Home network") or "Home network")
    except Exception:
        return "Home network"


def compliance_report_data(period="weekly", now=None):
    """Gather everything the compliance report needs. Pure function of
    the database (no sending). Never raises."""
    now = now if now is not None else time.time()
    days = PERIOD_DAYS.get(period, 7)
    since = now - days * 24 * 3600
    data = {
        "period": period,
        "days": days,
        "site": _site_name(),
        "since": since,
        "now": now,
        "incidents": [],
        "actions": [],
        "volume": [],
        "scores": [],
    }
    try:
        data.update(_compliance_body(days, since, now))
    except Exception:
        pass
    return data


def _compliance_body(days, since, now):
    incidents = []
    try:
        rows = dbm.query(
            "SELECT id, created_ts, updated_ts, title, severity, status,"
            " device_key FROM incidents WHERE created_ts > ?"
            " ORDER BY created_ts DESC", (since,))
        for iid, cts, uts, title, sev, status, dkey in rows:
            case = dbm.get_incident(iid) or {}
            members = case.get("alerts") or []
            kinds = {}
            mitre = {}
            for a in members:
                k = a.get("kind") or "unknown"
                kinds[k] = kinds.get(k, 0) + 1
                mid = a.get("mitre_id")
                if mid:
                    mitre[mid] = (a.get("mitre_name") or "")
            category = (max(kinds, key=kinds.get) if kinds else "unknown")
            incidents.append({
                "id": iid, "title": title or "", "severity": sev or "",
                "status": status or "", "device": dkey or "",
                "created": cts, "alerts": len(members),
                "category": category,
                "mitre": sorted(mitre.items()),
            })
    except Exception:
        incidents = []

    actions = []
    try:
        for mac, ip, state, cts, uts, actor, note in dbm.query(
                "SELECT mac, ip, state, created_ts, updated_ts, actor, note"
                " FROM quarantines WHERE created_ts > ?"
                " ORDER BY created_ts DESC", (since,)):
            actions.append({
                "ts": cts, "action": "quarantine",
                "target": mac or "", "actor": actor or "",
                "detail": f"device {ip or mac or ''} isolated"
                          + (f" ({note})" if note else ""),
            })
            if state == "released" and uts and uts > since:
                actions.append({
                    "ts": uts, "action": "quarantine_released",
                    "target": mac or "", "actor": actor or "",
                    "detail": f"device {ip or mac or ''} released",
                })
    except Exception:
        pass
    try:
        for iid, ts, actor, sent_ok in dbm.query(
                "SELECT incident_id, ts, actor, sent_ok FROM escalations"
                " WHERE ts > ? ORDER BY ts DESC", (since,)):
            actions.append({
                "ts": ts,
                "action": "escalated" if sent_ok else "escalation_failed",
                "target": f"case {iid}", "actor": actor or "",
                "detail": "sent to the administrator"
                          if sent_ok else "email failed; case stayed open",
            })
    except Exception:
        pass
    try:
        for aid, kind, sev, title, note, ts in dbm.query(
                "SELECT id, kind, severity, title, note, ts FROM alerts"
                " WHERE status='dismissed' AND ts > ?"
                " ORDER BY ts DESC", (since,)):
            detail = f"[{sev or ''}] {title or ''}".strip()
            if note:
                detail += f" -- reason: {note}"
            actions.append({
                "ts": ts, "action": "dismissed", "target": f"alert {aid}",
                "actor": "", "detail": detail,
            })
    except Exception:
        pass
    try:
        for aid, kind, sev, title, ts in dbm.query(
                "SELECT id, kind, severity, title, ts FROM alerts"
                " WHERE status='acknowledged' AND ts > ?"
                " ORDER BY ts DESC", (since,)):
            actions.append({
                "ts": ts, "action": "acknowledged",
                "target": f"alert {aid}", "actor": "",
                "detail": f"[{sev or ''}] {title or ''}".strip(),
            })
    except Exception:
        pass
    actions.sort(key=lambda a: -(a["ts"] or 0))

    volume = []
    try:
        rows = dbm.query(
            "SELECT date(ts, 'unixepoch', 'localtime'), severity,"
            " COUNT(*) FROM alerts WHERE ts > ?"
            " GROUP BY 1, 2 ORDER BY 1", (since,))
        by_day = {}
        for day, sev, count in rows:
            d = by_day.setdefault(day or "", {"Critical": 0, "High": 0,
                                              "Medium": 0, "Low": 0})
            if sev in d:
                d[sev] = count
        volume = [{"day": day, **counts}
                  for day, counts in sorted(by_day.items())]
    except Exception:
        volume = []

    scores = [h for h in score_history(days=days + 1)
              if (h.get("score") is not None)]
    return {"incidents": incidents, "actions": actions, "volume": volume,
            "scores": scores}


def _fmt_dt(ts):
    try:
        return datetime.fromtimestamp(float(ts)).strftime("%Y-%m-%d %H:%M")
    except (TypeError, ValueError):
        return ""


def compliance_html(data):
    """Clean print-friendly HTML of the compliance report. Never raises;
    every dynamic value is html-escaped."""
    try:
        return _compliance_html(data)
    except Exception:
        return ("<html><body><p>The compliance report could not be"
                " built.</p></body></html>")


def _compliance_html(data):
    e = html.escape
    period = e(str(data.get("period", "weekly")))
    days = int(data.get("days", 7) or 7)
    site = e(str(data.get("site", "")))
    since = _fmt_dt(data.get("since"))
    now_s = _fmt_dt(data.get("now"))
    parts = [f"""<html><head><title>brutedash compliance report ({period})</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
body{{font-family:monospace;max-width:900px;margin:2em auto;padding:0 1em;color:#111}}
h1{{font-size:1.4em}} h2{{font-size:1.1em;border-bottom:1px solid #ccc;padding-bottom:.3em}}
table{{border-collapse:collapse;width:100%;margin:1em 0;font-size:.85em}}
th,td{{border:1px solid #ccc;padding:.4em;text-align:left}}
th{{background:#f0f0f0}}
.note{{color:#555;font-size:.85em}}
@media print{{body{{margin:0}}}}
</style></head><body>
<h1>brutedash compliance report -- {period}</h1>
<p class="note">{site} &middot; last {days} days ({since} to {now_s}) &middot;
generated {now_s}</p>"""]

    parts.append("<h2>Incidents by category (with MITRE ATT&amp;CK tags)</h2>")
    inc = data.get("incidents") or []
    if not inc:
        parts.append("<p class='note'>No incidents in this period.</p>")
    else:
        parts.append("<table><tr><th>Case</th><th>Category</th><th>Urgency</th>"
                     "<th>Status</th><th>Alerts</th><th>MITRE</th>"
                     "<th>Opened</th></tr>")
        for i in inc:
            mitre_bits = [f"{e(mid)} {e(name)}".strip()
                          for mid, name in (i.get("mitre") or [])]
            mitre = ", ".join(mitre_bits) if mitre_bits else "--"
            parts.append(
                f"<tr><td>{e(str(i.get('title')))}</td>"
                f"<td>{e(str(i.get('category')))}</td>"
                f"<td>{e(str(i.get('severity')))}</td>"
                f"<td>{e(str(i.get('status')))}</td>"
                f"<td>{int(i.get('alerts') or 0)}</td>"
                f"<td>{mitre}</td>"
                f"<td>{e(_fmt_dt(i.get('created')))}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Response actions taken</h2>")
    acts = data.get("actions") or []
    if not acts:
        parts.append("<p class='note'>No response actions in this"
                     " period.</p>")
    else:
        parts.append("<table><tr><th>When</th><th>Action</th><th>Target</th>"
                     "<th>Detail</th></tr>")
        for a in acts:
            parts.append(
                f"<tr><td>{e(_fmt_dt(a.get('ts')))}</td>"
                f"<td>{e(str(a.get('action')))}</td>"
                f"<td>{e(str(a.get('target')))}</td>"
                f"<td>{e(str(a.get('detail')))}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Alert volume by day</h2>")
    vol = data.get("volume") or []
    if not vol:
        parts.append("<p class='note'>No alerts in this period.</p>")
    else:
        parts.append("<table><tr><th>Day</th><th>Critical</th><th>High</th>"
                     "<th>Medium</th><th>Low</th><th>Total</th></tr>")
        for v in vol:
            tot = sum(int(v.get(s) or 0)
                      for s in ("Critical", "High", "Medium", "Low"))
            parts.append(
                f"<tr><td>{e(str(v.get('day')))}</td>"
                f"<td>{int(v.get('Critical') or 0)}</td>"
                f"<td>{int(v.get('High') or 0)}</td>"
                f"<td>{int(v.get('Medium') or 0)}</td>"
                f"<td>{int(v.get('Low') or 0)}</td><td>{tot}</td></tr>")
        parts.append("</table>")

    parts.append("<h2>Security score history</h2>")
    scores = data.get("scores") or []
    if not scores:
        parts.append("<p class='note'>No score snapshots in this"
                     " period.</p>")
    else:
        parts.append("<table><tr><th>Day</th><th>Score</th></tr>")
        for s in scores:
            parts.append(f"<tr><td>{e(str(s.get('day')))}</td>"
                         f"<td>{int(s.get('score'))}</td></tr>")
        parts.append("</table>")

    parts.append("<p class='note'>Generated by brutedash -- your network,"
                 " explained.</p></body></html>")
    return "".join(parts)


def compliance_csv(data):
    """Flat CSV of the same compliance data, in labeled sections an
    auditor can open in a spreadsheet. Never raises."""
    try:
        return _compliance_csv(data)
    except Exception:
        return "error,compliance report could not be built\n"


def _compliance_csv(data):
    buf = io.StringIO()
    w = csv.writer(buf)
    days = int(data.get("days", 7) or 7)
    w.writerow(["# brutedash compliance report"])
    w.writerow(["# period", data.get("period", "weekly")])
    w.writerow(["# site", data.get("site", "")])
    w.writerow(["# window_days", days])
    w.writerow(["# generated",
                datetime.fromtimestamp(
                    data.get("now") or time.time()).isoformat()])
    w.writerow([])
    w.writerow(["# incidents"])
    w.writerow(["id", "title", "category", "severity", "status",
                "device", "alerts", "mitre_ids", "opened"])
    for i in data.get("incidents") or []:
        w.writerow([i.get("id"), i.get("title"), i.get("category"),
                    i.get("severity"), i.get("status"), i.get("device"),
                    i.get("alerts"),
                    ";".join(mid for mid, _ in (i.get("mitre") or [])),
                    _fmt_dt(i.get("created"))])
    w.writerow([])
    w.writerow(["# response actions"])
    w.writerow(["when", "action", "target", "actor", "detail"])
    for a in data.get("actions") or []:
        w.writerow([_fmt_dt(a.get("ts")), a.get("action"),
                    a.get("target"), a.get("actor"), a.get("detail")])
    w.writerow([])
    w.writerow(["# alert volume by day"])
    w.writerow(["day", "critical", "high", "medium", "low", "total"])
    for v in data.get("volume") or []:
        tot = sum(int(v.get(s) or 0)
                  for s in ("Critical", "High", "Medium", "Low"))
        w.writerow([v.get("day"), v.get("Critical"), v.get("High"),
                    v.get("Medium"), v.get("Low"), tot])
    w.writerow([])
    w.writerow(["# score history"])
    w.writerow(["day", "score"])
    for s in data.get("scores") or []:
        w.writerow([s.get("day"), s.get("score")])
    return buf.getvalue()

# --- PDF exports (via pdfgen.py: stdlib-only, text layout) -------------------


def incident_pdf_bytes(incident_id):
    """One-click incident brief as a PDF. Returns bytes, or None when the
    case doesn't exist. Never raises."""
    try:
        from . import pdfgen
        case = dbm.get_incident(int(incident_id))
    except Exception:
        return None
    if not case:
        return None
    try:
        return _incident_pdf(case)
    except Exception:
        return None


def _incident_pdf(case):
    from . import pdfgen
    sev = case.get("severity") or ""
    status = case.get("status") or ""
    doc = pdfgen.PdfDoc(
        title=f"Incident brief: {case.get('title') or 'case'}",
        subtitle=(f"Urgency: {sev} -- Status: {status} -- "
                  f"{_fmt_dt(case.get('created_ts'))}"))
    if case.get("summary"):
        doc.body(case["summary"])
    doc.spacer()
    doc.subheading("Timeline")
    rows = []
    for a in case.get("alerts") or []:
        mitre = a.get("mitre_id") or ""
        if a.get("mitre_name"):
            mitre += f" {a['mitre_name']}"
        rows.append([_fmt_dt(a.get("ts")), a.get("severity") or "",
                     (a.get("title") or "")[:60], mitre.strip()])
    doc.table(["When", "Urgency", "What happened", "Technique"],
              rows, widths=[110, 70, 180, 108])
    doc.spacer()
    doc.subheading("What to do")
    seen = set()
    for a in case.get("alerts") or []:
        step = (a.get("what_to_do") or "").strip()
        if step and step not in seen:
            seen.add(step)
            doc.bullet(step)
    if not seen:
        doc.body("Keep an eye on it; if it keeps happening, look into it.")
    return doc.build()


def weekly_pdf_bytes(now=None):
    """The weekly summary as a PDF. Returns bytes. Never raises."""
    try:
        from . import pdfgen
        from . import weekly as weekm
        report = weekm.generate_weekly_report(now=now)
        return _weekly_pdf(report)
    except Exception:
        return None


def _weekly_pdf(report):
    from . import pdfgen
    totals = report.get("totals") or {}
    doc = pdfgen.PdfDoc(
        title="Your network this week",
        subtitle=f"{_site_name()} -- {report.get('period') or ''}")
    doc.body(report.get("headline") or "")
    doc.spacer()
    doc.subheading("The numbers")
    mb = totals.get("mb") or 0
    if mb >= 1024:
        moved = f"{mb / 1024:.1f} GB"
    else:
        moved = f"{mb:.1f} MB"
    doc.bullet(f"Data moved: {moved} "
               f"({totals.get('packets') or 0} packets)")
    sev = report.get("alerts_by_severity") or {}
    sev_bit = ", ".join(
        f"{sev.get(s, 0)} {s.lower()}"
        for s in ("Critical", "High", "Medium", "Low")
        if sev.get(s, 0)) or "no alerts at all"
    doc.bullet(f"Alerts: {sev_bit}")
    doc.bullet(report.get("outages") or "")
    doc.bullet(report.get("firsts") or "")
    if report.get("busiest_day"):
        doc.bullet(f"Busiest day: {report['busiest_day']}")
    notable = report.get("notable_alerts") or []
    if notable:
        doc.spacer()
        doc.subheading("Worth knowing about")
        for n in notable[:8]:
            doc.bullet(str(n))
    talkers = report.get("top_talkers") or []
    if talkers:
        doc.spacer()
        doc.subheading("Biggest conversations")
        for t in talkers[:8]:
            doc.bullet(str(t))
    scores = [h for h in score_history(days=8) if h.get("score") is not None]
    if scores:
        doc.spacer()
        doc.subheading("Security score this week")
        doc.table(["Day", "Score"],
                  [[s["day"], str(s["score"])] for s in
                   sorted(scores, key=lambda h: h["day"])],
                  widths=[234, 234])
    return doc.build()
