"""netmon/escalate.py -- "Escalate to administrator".

His feature call, and the product's core differentiator: the AI handles
the triage, the owner handles the routine with guidance, and the hard 5%
goes to the expert. The Escalate button on a case packages the FULL
incident bundle -- timeline, MITRE tags, evidence, the plain-English
brief, recommended actions, and what the owner already tried -- and
emails it to the configured administrator contact.

The admin contact comes from config.yaml `response.admin_email`
(DEFAULT EMPTY -- never hardcode personal data in the repo; it can also
arrive via BRUTEDASH_RESPONSE_ADMIN_EMAIL). When it's not configured the
escalation refuses with setup instructions instead of failing silently.

State machine: the case moves open -> escalated ONLY when the email was
actually sent (sent_ok=1). A failed send leaves the case open and logs
the attempt -- "awaiting admin" must never be a lie.

Email safety: the admin address is validated against a strict regex
(header injection), and the subject/body go through notify._clean
(CR/LF stripping), the same treatment as alert emails.
"""

import re
import time

from . import config as cfgm
from . import db as dbm

# Strict enough to stop header injection, loose enough for real
# addresses. The local part is capped so a pathological config value
# can't smuggle a novel's worth of text into a header.
EMAIL_RE = re.compile(
    r"^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,253}\.[A-Za-z]{2,}$")

SETUP_HINT = (
    "No admin email is configured yet. Set response.admin_email in"
    " config.yaml (or the BRUTEDASH_RESPONSE_ADMIN_EMAIL environment"
    " variable) to your administrator's address, restart the dashboard,"
    " then escalate again.")

# Email sender indirection. None = really send via notify._send with the
# SMTP env config. Tests and the smoke boot replace this with a recorder.
_SEND_EMAIL = None


def admin_email():
    """The configured administrator contact, or '' when unset."""
    try:
        return (cfgm.get(cfgm.load_cached(), "response.admin_email", "")
                or "").strip()
    except Exception:
        return ""


def valid_admin_email(addr):
    """True for a plausibly real, header-safe email address."""
    if not addr or not isinstance(addr, str):
        return False
    if "\r" in addr or "\n" in addr:
        return False
    return bool(EMAIL_RE.match(addr.strip()))


def _fmt_ts(ts):
    try:
        return time.strftime("%b %d, %Y %I:%M %p", time.localtime(float(ts)))
    except (TypeError, ValueError):
        return "unknown time"


def build_escalation_bundle(incident_id):
    """The full incident bundle, as a plain dict.

    Sections: case (title/summary/severity/device/window), timeline
    (every alert with its plain-English fields + MITRE tag), what_tried
    (what the owner already did -- dismissals, quarantine attempts,
    past escalations), recommended_actions (deduped next steps from the
    alerts), past_escalations. Returns None when the case doesn't exist.
    """
    case = dbm.get_incident(incident_id)
    if not case:
        return None
    try:
        from . import mitre as mitrem
    except Exception:
        mitrem = None
    timeline = []
    for a in case.get("alerts") or []:
        tag = None
        if mitrem:
            try:
                tag = mitrem.tag_for(a.get("kind"))
            except Exception:
                tag = None
        timeline.append({
            "when": _fmt_ts(a.get("ts")),
            "severity": a.get("severity") or "",
            "kind": a.get("kind") or "",
            "title": a.get("title") or "",
            "detail": a.get("detail") or "",
            "meaning": a.get("meaning") or "",
            "what_to_do": a.get("what_to_do") or "",
            "mitre": (f"{tag['id']} {tag['name']}"
                      if tag else ""),
        })
    recommended = []
    for a in case.get("alerts") or []:
        step = (a.get("what_to_do") or "").strip()
        if step and step not in recommended:
            recommended.append(step)
    return {
        "case_id": case.get("id"),
        "title": case.get("title") or "",
        "summary": case.get("summary") or "",
        "severity": case.get("severity") or "",
        "status": case.get("status") or "",
        "device": case.get("device_key") or "",
        "opened": _fmt_ts(case.get("created_ts")),
        "last_activity": _fmt_ts(case.get("updated_ts")),
        "alert_count": len(timeline),
        "timeline": timeline,
        "what_tried": dbm.incident_what_was_tried(incident_id),
        "recommended_actions": recommended,
        "past_escalations": [
            {"when": _fmt_ts(e.get("ts")),
             "to": e.get("admin_email") or "",
             "sent": bool(e.get("sent_ok"))}
            for e in dbm.list_escalations(incident_id)
        ],
    }


def build_escalation_email(bundle):
    """(subject, body) for the bundle. Plain English, header-safe."""
    from . import notify as notifm
    clean = notifm._clean
    title = clean(bundle.get("title")) or "a network case"
    subject = f"[netmon] Escalated case: {title}"
    L = []
    L.append("Hi -- this case needs an expert's eyes. Everything below is"
             " what the monitor found and what the owner already tried.")
    L.append("")
    L.append(f"Case: {bundle.get('title')}")
    L.append(f"Urgency: {bundle.get('severity')}")
    if bundle.get("device"):
        L.append(f"Device involved: {bundle.get('device')}")
    L.append(f"Opened: {bundle.get('opened')}")
    L.append(f"Last activity: {bundle.get('last_activity')}")
    if bundle.get("summary"):
        L.append(f"Summary: {clean(bundle.get('summary'))}")
    L.append("")
    L.append(f"Timeline ({bundle.get('alert_count')} alerts, oldest first):")
    for t in bundle.get("timeline") or []:
        L.append(f"  - [{t['severity']}] {clean(t['title'])}"
                 f" ({t['when']})")
        if t.get("detail"):
            L.append(f"    Detail: {clean(t['detail'])}")
        if t.get("meaning"):
            L.append(f"    What it means: {clean(t['meaning'])}")
        if t.get("mitre"):
            L.append(f"    Technique: {clean(t['mitre'])}")
    tried = bundle.get("what_tried") or []
    L.append("")
    L.append("What the owner already tried:")
    if tried:
        for item in tried:
            L.append(f"  - {clean(item)}")
    else:
        L.append("  - Nothing yet -- this case went straight to you.")
    rec = bundle.get("recommended_actions") or []
    if rec:
        L.append("")
        L.append("Recommended next steps (from the monitor's guides):")
        for i, step in enumerate(rec, 1):
            L.append(f"  {i}. {clean(step)}")
    past = [e for e in (bundle.get("past_escalations") or []) if e.get("sent")]
    if past:
        L.append("")
        L.append("Previously escalated: " +
                 ", ".join(f"{e['to']} on {e['when']}" for e in past))
    L.append("")
    L.append("-- sent by brutedash (Project Orion), the network monitor")
    return subject, "\n".join(L)


def _really_send(subject, body, to_addr):
    """Send via the configured SMTP env (same as alert emails), but TO
    the administrator -- not the NETMON_ALERT_TO recipient."""
    from . import notify as notifm
    cfg = notifm._smtp_config()
    if not cfg["host"]:
        raise RuntimeError("email isn't configured (NETMON_SMTP_HOST is"
                           " empty)")
    cfg = dict(cfg, to=to_addr)
    notifm._send(cfg, subject, body)


def send_escalation(incident_id, actor="dashboard"):
    """Escalate a case to the administrator.

    Returns (True, message) when the email went out and the case moved
    to 'escalated'; (False, plain-English reason) otherwise. A failed
    send never moves the case -- 'awaiting admin' is only ever true.
    """
    actor = actor or "dashboard"
    case = dbm.get_incident(incident_id)
    if not case:
        return False, "That case doesn't exist."
    if (case.get("status") or "") != "open":
        return False, ("Only open cases can be escalated -- this one is"
                       f" '{case.get('status')}'. Reopen it first if it"
                       " needs admin attention again.")
    email = admin_email()
    if not email:
        return False, SETUP_HINT
    if not valid_admin_email(email):
        return False, (f"The configured admin email ({email}) doesn't look"
                       " like a real address. Fix response.admin_email in"
                       " config.yaml and try again.")
    bundle = build_escalation_bundle(incident_id)
    if not bundle:
        return False, "Couldn't load the case details."
    subject, body = build_escalation_email(bundle)
    sender = _SEND_EMAIL or (lambda s, b: _really_send(s, b, email))
    try:
        sender(subject, body)
    except Exception as exc:
        dbm.record_escalation(incident_id, actor, email, subject, False)
        dbm.audit("escalate_failed", actor, str(incident_id),
                  f"email to {email} failed: {exc}")
        return False, (f"The email didn't go through ({exc}). The case is"
                       " still open -- nothing was lost. Check the email"
                       " settings and try again.")
    dbm.record_escalation(incident_id, actor, email, subject, True)
    dbm.set_incident_status(incident_id, "escalated")
    dbm.audit("escalate", actor, str(incident_id),
              f"escalated case {incident_id} to {email}")
    return True, (f"Sent to {email}. The case is now marked 'awaiting"
                  " admin' -- you'll see it under the Escalated filter.")
