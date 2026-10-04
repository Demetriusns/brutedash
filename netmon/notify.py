"""netmon/notify.py -- email notifications for important alerts.

A hook in db.add_alert lazily calls ``notify.maybe_send_alert(alert_dict)``
inside try/except; this module must simply exist and expose that function.
The alert dict carries: kind, severity, title, detail, meaning, is_normal,
what_to_do, ts.

Config comes from the environment (see docstring of _smtp_config):
  NETMON_SMTP_HOST, NETMON_SMTP_PORT (default 587),
  NETMON_SMTP_USER, NETMON_SMTP_PASS,
  NETMON_ALERT_TO (recipient), NETMON_SMTP_FROM (optional, default USER).

Only High/Critical alerts send mail, at most one email per alert kind
per hour. Quiet hours (set on the dashboard) silence email without
dropping the alerts themselves. When one alert kind fires 5+ times in an
hour, a single "still happening" escalation replaces the stream.
Nothing here ever raises: any failure means False.
"""
import os
import queue
import re
import smtplib
import sys
import threading
import time
from datetime import datetime
from email.message import EmailMessage

COOLDOWN_SECONDS = 3600  # one email per alert kind per hour

CIRCUIT_WINDOW = 3600    # look back one hour ...
CIRCUIT_THRESHOLD = 5    # ... 5+ alerts of one kind -> escalate, then hush

_SENDABLE = {"High", "Critical"}

# In-memory fallback cooldown, keyed by alert kind -> last sent epoch.
# Used only when the db meta helpers (added by a teammate) are missing.
_mem_cooldown = {}

# Consecutive email-send failures, counted on the worker thread. When
# SMTP is configured but sends keep failing, one self-alert fires (see
# _send_failed) -- an email about broken email would be absurd, and a
# silent failure means missed High/Critical pages.
_fail_streak = 0
NOTIFY_FAIL_STREAK_ALERT = 5


# --- async delivery ---------------------------------------------------------
# B1: SMTP used to run synchronously inside db.add_alert, i.e. on the
# detection thread -- one slow mail server stalled detection up to 30s
# per alert. Delivery now goes through a single daemon worker thread;
# maybe_send_alert only enqueues and always returns fast.

_job_queue = queue.Queue()
_worker_lock = threading.Lock()
_worker_started = False


def _ensure_worker():
    global _worker_started
    with _worker_lock:
        if not _worker_started:
            threading.Thread(target=_worker_loop, name="notify-worker",
                             daemon=True).start()
            _worker_started = True


def _worker_loop():
    while True:
        try:
            job = _job_queue.get()
        except Exception:
            continue
        try:
            kind, payload = job
            if kind == "alert":
                _maybe_send_alert(payload)
            elif kind == "digest":
                _send_digest()
        except Exception as exc:
            try:
                print(f"netmon notify: worker job failed: {exc}",
                      file=sys.stderr)
            except Exception:
                pass
        finally:
            _job_queue.task_done()


def _clean(text):
    """Strip CR/LF from LAN-derived strings before they reach email
    headers or bodies. L3: a crafted newline in an alert title made
    EmailMessage raise, which silently dropped that alert's email."""
    return re.sub(r"[\r\n]+", " ", str(text or "")).strip()


def _meta_get(key):
    try:
        from . import db as dbm
        get_meta = getattr(dbm, "get_meta", None)
        if get_meta is None:
            return None
        return get_meta(key)
    except Exception:
        return None


def _meta_set(key, value):
    try:
        from . import db as dbm
        set_meta = getattr(dbm, "set_meta", None)
        if set_meta is None:
            return False
        set_meta(key, value)
        return True
    except Exception:
        return False


def _cooldown_allows(kind):
    """True if we may email for this kind now (one per hour).

    Returns False when a mail for this kind went out less than
    COOLDOWN_SECONDS ago. Cooldown is recorded via the db meta helpers
    when available, otherwise in a module-level dict. The "last sent"
    stamp is only written by record_cooldown(), i.e. after a send
    actually succeeded, so failures never consume the quota.
    """
    now = time.time()
    key = f"email_cooldown_{kind}"
    last = _meta_get(key)
    if last is None:
        last = _mem_cooldown.get(key)
    if last is not None:
        try:
            if now - float(last) < COOLDOWN_SECONDS:
                return False
        except (TypeError, ValueError):
            pass
    return True


def record_cooldown(kind):
    """Mark that an email for this alert kind was just sent."""
    key = f"email_cooldown_{kind}"
    if not _meta_set(key, str(time.time())):
        _mem_cooldown[key] = time.time()


def build_email(alert):
    """Plain-English (subject, body) for an alert dict. Never raises."""
    try:
        title = _clean(alert.get("title")) or "Something needs your attention"
        detail = _clean(alert.get("detail"))
        meaning = (alert.get("meaning") or "").strip() or \
            "We're still learning about this one."
        is_normal = (alert.get("is_normal") or "").strip() or \
            "Not sure yet -- treat it as worth a quick check."
        what_to_do = (alert.get("what_to_do") or "").strip() or \
            "Keep an eye on it; if it keeps happening, look into it."
        ts = alert.get("ts") or time.time()
        try:
            when = datetime.fromtimestamp(float(ts)).strftime(
                "%b %d, %Y at %I:%M %p")
        except (TypeError, ValueError):
            when = "just now"

        subject = f"[netmon] Needs attention: {title}"
        lines = [
            "Hi -- your home network monitor spotted something worth a look.",
            "",
            f"What happened: {title}" + (f" -- {detail}" if detail else ""),
            "",
            f"What it means: {meaning}",
            "",
            f"Is this normal? {is_normal}",
            "",
            f"What to do: {what_to_do}",
            "",
            f"Spotted: {when}.",
        ]
        return subject, "\n".join(lines)
    except Exception:
        return "[netmon] Needs attention", \
            "Your network monitor saw something unusual."


def _smtp_config():
    port = (os.environ.get("NETMON_SMTP_PORT") or "587").strip()
    try:
        port = int(port)
    except ValueError:
        port = 587
    user = (os.environ.get("NETMON_SMTP_USER") or "").strip()
    return {
        "host": (os.environ.get("NETMON_SMTP_HOST") or "").strip(),
        "port": port,
        "user": user,
        "password": os.environ.get("NETMON_SMTP_PASS") or "",
        "to": (os.environ.get("NETMON_ALERT_TO") or "").strip(),
        "from": (os.environ.get("NETMON_SMTP_FROM") or "").strip() or user,
    }


def _send(config, subject, body):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config["from"]
    msg["To"] = config["to"]
    msg.set_content(body)
    with smtplib.SMTP(config["host"], config["port"], timeout=30) as smtp:
        smtp.starttls()
        if config["user"]:
            smtp.login(config["user"], config["password"])
        smtp.send_message(msg)


def maybe_send_alert(alert):
    """Queue an alert email for High/Critical alerts.

    Returns True when the alert was accepted for delivery -- NOT when the
    email was sent (delivery is async). Returns False (never raises) for
    anything that isn't a queueable alert.

    Never blocks the caller: the detection thread must not stall on SMTP.
    Severity/config/quiet-hours/cooldown filtering happens on the worker.
    """
    try:
        if not isinstance(alert, dict):
            return False
        if (alert.get("severity") or "").strip() not in _SENDABLE:
            return False
        _ensure_worker()
        _job_queue.put(("alert", dict(alert)))
        return True
    except Exception as exc:  # never raise; one stderr line at most
        try:
            print(f"netmon notify: failed to queue alert email: {exc}",
                  file=sys.stderr)
        except Exception:
            pass
        return False


def _maybe_send_alert(alert):
    if not isinstance(alert, dict):
        return False
    if (alert.get("severity") or "").strip() not in _SENDABLE:
        return False
    cfg = _smtp_config()
    if not cfg["host"] or not cfg["to"]:
        return False  # not configured: silent no-op
    kind = (alert.get("kind") or "general").strip() or "general"
    if in_quiet_hours(kind):
        return False  # silenced by the user's quiet hours; alert kept
    if not _cooldown_allows(kind):
        return False
    trip = _circuit_state(kind)
    if trip is True:
        return False  # already escalated this hour: stay quiet
    if trip == "escalate":
        subject, body = build_escalation_email(alert, kind)
    else:
        subject, body = build_email(alert)
    try:
        _send(cfg, subject, body)
    except Exception as exc:
        _send_failed(exc)
        return False
    record_cooldown(kind)
    _send_ok()
    return True


def _send_failed(exc):
    """Record one failed email send.

    Logs one stderr line (a fallback transition logs; it doesn't page),
    counts the consecutive-failure streak, and -- when SMTP is configured
    but sends keep failing -- fires ONE Medium self-alert so the owner
    learns their pages aren't going out. Never raises.

    This only runs after _send was attempted, i.e. SMTP is configured;
    unconfigured mail stays a silent no-op. The self-alert is Medium, so
    it never re-enters the email queue itself (no loop: only
    High/Critical queue mail).
    """
    global _fail_streak
    try:
        print(f"netmon notify: email send failed: {exc!r}", file=sys.stderr)
    except Exception:
        pass
    _fail_streak += 1
    if _fail_streak < NOTIFY_FAIL_STREAK_ALERT:
        return
    try:
        if _meta_get("notify_down_alerted"):
            return  # already alerted for this episode; stay quiet
        from . import db as dbm
        dbm.add_alert(
            "self_drift", "Medium",
            "Alert emails aren't going out",
            f"{_fail_streak} email sends in a row failed.",
            meaning=("brutedash emails you about High and Critical"
                     " findings. Right now those emails are failing to"
                     " send, so anything urgent would only show on the"
                     " dashboard."),
            is_normal=("Not normal -- email worked before, or was never"
                       " tested. The most common cause is a wrong SMTP"
                       " password or a changed mail setting."),
            what_to_do=("Check your email settings (SMTP host, user, and"
                        " password in the environment) and your internet"
                        " connection, then use the dashboard's digest"
                        " button to send a test email."))
        _meta_set("notify_down_alerted", str(time.time()))
    except Exception as exc2:
        try:
            print(f"netmon notify: down-alert failed: {exc2!r}",
                  file=sys.stderr)
        except Exception:
            pass


def _send_ok():
    """A send succeeded: reset the failure streak, clear any down-alert
    flag (recovery), and stamp the notify watermark. Never raises."""
    global _fail_streak
    _fail_streak = 0
    try:
        if _meta_get("notify_down_alerted"):
            _meta_set("notify_down_alerted", "")
    except Exception:
        pass
    try:
        from . import pipeline as pipelinem
        pipelinem.mark("notify")
    except Exception:
        pass


# --- quiet hours ---------------------------------------------------------
# Windows come from db.get_quiet_hours(): each is {days:[0..6 Mon..Sun],
# start:"HH:MM", end:"HH:MM", kinds:["all"] or [alert kinds]}. Overnight
# windows (end <= start) wrap past midnight.

def _parse_hhmm(s):
    try:
        h, m = str(s).split(":")
        h, m = int(h), int(m)
        if 0 <= h < 24 and 0 <= m < 60:
            return h * 60 + m
    except Exception:
        pass
    return None


def in_quiet_hours(kind, now=None):
    """True if `now` falls inside a user quiet window for this alert kind."""
    now = now if now is not None else time.time()
    try:
        from . import db as dbm
        windows = dbm.get_quiet_hours()
    except Exception:
        return False
    if not windows:
        return False
    lt = datetime.fromtimestamp(now)
    day = lt.weekday()  # 0 = Monday
    mins = lt.hour * 60 + lt.minute
    kind = (kind or "").strip()
    for w in windows:
        if not isinstance(w, dict):
            continue
        days = w.get("days")
        if days and day not in days:
            continue
        start = _parse_hhmm(w.get("start") or "")
        end = _parse_hhmm(w.get("end") or "")
        if start is None or end is None:
            continue
        kinds = w.get("kinds") or ["all"]
        if "all" not in kinds and kind not in kinds:
            continue
        if start < end:
            inside = start <= mins < end
        else:  # wraps midnight
            inside = mins >= start or mins < end
        if inside:
            return True
    return False


# --- fatigue circuit breaker ----------------------------------------------
# When one alert kind fires CIRCUIT_THRESHOLD+ times in CIRCUIT_WINDOW,
# email one "still happening" escalation and then go quiet for the hour
# instead of sending (or worse, wanting to send) a stream of mails.

def _circuit_state(kind):
    """None = normal; "escalate" = tripped, send one summary mail;
    True = already escalated this hour, stay quiet."""
    now = time.time()
    try:
        from . import db as dbm
        rows = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE kind=? AND ts > ?",
            (kind, now - CIRCUIT_WINDOW))
        count = rows[0][0] if rows else 0
    except Exception:
        return None
    if count < CIRCUIT_THRESHOLD:
        return None
    key = f"circuit_escalated_{kind}"
    last = _meta_get(key)
    try:
        escalated = last is not None and \
            now - float(last) < CIRCUIT_WINDOW
    except (TypeError, ValueError):
        escalated = False
    if escalated:
        return True
    _meta_set(key, str(now))
    return "escalate"


def build_escalation_email(alert, kind):
    """One rolled-up email for a chatty alert kind. Never raises."""
    try:
        from . import db as dbm
        rows = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE kind=? AND ts > ?",
            (kind, time.time() - CIRCUIT_WINDOW))
        count = rows[0][0] if rows else 0
    except Exception:
        count = 0
    title = _clean(alert.get("title")) or "Something on your network"
    detail = _clean(alert.get("detail"))
    subject = f"[netmon] Still happening: {title} (x{count} in the last hour)"
    lines = [
        "Hi -- this keeps firing, so I'm rolling it into one email"
        " instead of sending you a stream of them.",
        "",
        f"What: {title} -- fired {count} times in the last hour.",
    ]
    if detail:
        lines += ["", f"Latest detail: {detail}"]
    lines += [
        "",
        "If you recognize this as normal, dismiss one of these alerts on"
        " the dashboard -- the monitor learns from your dismissals and"
        " will quiet down.",
    ]
    return subject, "\n".join(lines)


# --- daily digest ----------------------------------------------------------
# One rolled-up email of recent Medium+ alerts, for people who don't want
# per-alert mail at all. Scheduled by run.py; also sendable on demand
# from the dashboard.

def build_digest(rows):
    """rows: (kind, severity, title, detail, ts). Returns (subject, body).
    Never raises."""
    try:
        return _build_digest(rows)
    except Exception:
        return "[netmon] Network digest", \
            "Your network monitor has updates -- open the dashboard."


def _build_digest(rows):
    groups = {}
    order = []
    for kind, severity, title, detail, ts in rows:
        g = groups.get(kind)
        if g is None:
            g = groups[kind] = {"severity": severity or "",
                                "title": _clean(title),
                                "count": 0, "latest": None}
            order.append(kind)
        g["count"] += 1
        if g["latest"] is None:
            g["latest"] = (_clean(detail), ts)
    n = len(rows)
    subject = (f"[netmon] Digest: {n} alert{'s' if n != 1 else ''}"
               f" across {len(groups)} kind{'s' if len(groups) != 1 else ''}")
    lines = ["Hi -- here's what your network monitor noticed recently.", ""]
    for kind in order:
        g = groups[kind]
        head = f"- [{g['severity']}] {g['title']}"
        if g["count"] > 1:
            head += f" (x{g['count']})"
        lines.append(head)
        detail, ts = g["latest"]
        if detail:
            lines.append(f"  Latest: {detail}")
        try:
            when = datetime.fromtimestamp(float(ts)).strftime(
                "%b %d at %I:%M %p")
            lines.append(f"  When: {when}")
        except (TypeError, ValueError):
            pass
    lines += ["",
              "Open your dashboard to acknowledge or dismiss these --",
              " the monitor learns from what you dismiss."]
    return subject, "\n".join(lines)


def send_digest():
    """Email one digest of recent Medium+ alerts. True on send.

    Never raises. Advances the digest watermark only after a successful
    send, so a failure retries on the next run."""
    try:
        return _send_digest()
    except Exception as exc:  # never raise; one stderr line at most
        try:
            print(f"netmon notify: failed to send digest: {exc}",
                  file=sys.stderr)
        except Exception:
            pass
        return False


def send_digest_async():
    """Queue a digest email for the worker thread. Returns True when
    queued. Use this on the monitor thread (run.py) -- the dashboard's
    "send now" button keeps the synchronous send_digest() so it can
    report the outcome to the user."""
    try:
        _ensure_worker()
        _job_queue.put(("digest", None))
        return True
    except Exception:
        return False


def _send_digest():
    cfg = _smtp_config()
    if not cfg["host"] or not cfg["to"]:
        return False  # not configured: silent no-op
    try:
        from . import db as dbm
    except Exception:
        return False
    last = _meta_get("last_digest_ts")
    try:
        since = float(last) if last else time.time() - 24 * 3600
    except (TypeError, ValueError):
        since = time.time() - 24 * 3600
    rows = dbm.query(
        "SELECT kind, severity, title, detail, ts FROM alerts"
        " WHERE ts > ? AND severity IN ('High','Critical','Medium')"
        " AND (status IS NULL OR status != 'dismissed')"
        " ORDER BY ts DESC",
        (since,))
    if not rows:
        return False
    subject, body = build_digest(rows)
    try:
        _send(cfg, subject, body)
    except Exception as exc:
        _send_failed(exc)
        return False
    _send_ok()
    _meta_set("last_digest_ts", str(time.time()))
    return True
