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
per hour. Nothing here ever raises: any failure means False.
"""
import os
import smtplib
import sys
import time
from datetime import datetime
from email.message import EmailMessage

COOLDOWN_SECONDS = 3600  # one email per alert kind per hour

_SENDABLE = {"High", "Critical"}

# In-memory fallback cooldown, keyed by alert kind -> last sent epoch.
# Used only when the db meta helpers (added by a teammate) are missing.
_mem_cooldown = {}


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
        title = (alert.get("title") or "Something needs your attention").strip()
        detail = (alert.get("detail") or "").strip()
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
    """Email the user about a High/Critical alert. Returns True on send.

    Returns False (never raises) when the alert isn't High/Critical,
    email isn't configured, the per-kind hourly cooldown is active,
    or sending fails for any reason.
    """
    try:
        return _maybe_send_alert(alert)
    except Exception as exc:  # never raise; one stderr line at most
        try:
            print(f"netmon notify: failed to send alert email: {exc}",
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
    if not _cooldown_allows(kind):
        return False
    subject, body = build_email(alert)
    try:
        _send(cfg, subject, body)
    except Exception:
        return False
    record_cooldown(kind)
    return True
