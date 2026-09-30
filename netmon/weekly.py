"""netmon/weekly.py -- a warm weekly rollup of the network, in plain English.

Three pieces, kept separate so each can be tested alone:

  generate_weekly_report(now=None) -> dict
      Rolls up the last 7 days from SQLite: totals, top talkers,
      alerts by severity, outages, first-seen devices, busiest day.
  format_plaintext(report) -> str
      Turns that dict into an email-style report a non-technical
      owner can read -- no jargon.
  maybe_polish(report_text) -> str
      Asks the teammate's ai_assist module to polish the wording
      when it exists; otherwise returns the text unchanged.
  email_report(text) -> bool
      Sends the report by email when SMTP is configured. Never raises.

The report degrades gracefully: an empty database still produces a
readable "quiet week" report instead of an error.
"""
import os
import smtplib
import time
from datetime import datetime
from email.message import EmailMessage

from . import db as dbm
from .explainer import _port_words

WEEK_SECONDS = 7 * 24 * 3600


def _fmt_size(mb):
    """Human size from megabytes: 1234.5 MB -> '1.2 GB'."""
    if mb >= 1024:
        return f"{mb/1024:.1f} GB"
    if mb >= 1:
        return f"{mb:.1f} MB"
    return f"{mb*1024:.0f} KB"


def _day_label(ts):
    return datetime.fromtimestamp(ts).strftime("%A, %b %d")


def generate_weekly_report(now=None):
    """Roll up the last 7 days of SQLite data into a plain dict."""
    now = now or time.time()
    since = now - WEEK_SECONDS

    tot = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0),"
        " COUNT(*) FROM flows WHERE ts > ?", (since,))[0]
    total_mb = (tot[0] or 0) / 1e6
    total_packets = tot[1] or 0
    nflows = tot[2] or 0

    # Top 5 external talkers, with their main port described in plain words.
    top_talkers = []
    talkers = dbm.query(
        "SELECT dst_ip, SUM(bytes), SUM(packets) FROM flows"
        " WHERE ts > ? AND direction='outbound' GROUP BY dst_ip"
        " ORDER BY SUM(bytes) DESC LIMIT 5", (since,))
    for ip, b, p in talkers:
        main = dbm.query(
            "SELECT dst_port, proto, SUM(bytes) FROM flows"
            " WHERE ts > ? AND direction='outbound' AND dst_ip=?"
            " GROUP BY dst_port, proto ORDER BY SUM(bytes) DESC LIMIT 1",
            (since, ip))
        if main:
            port, proto, pb = main[0]
            desc = _port_words(port)
            top_talkers.append(
                f"{ip} -- {_fmt_size(b/1e6)} across {p or 0} packets."
                f" Mainly port {port} ({proto or 'unknown'}): {desc}.")
        else:
            top_talkers.append(
                f"{ip} -- {_fmt_size(b/1e6)} across {p or 0} packets.")

    # Alerts by severity, plus the High/Critical ones spelled out.
    sev_rows = dbm.query(
        "SELECT severity, COUNT(*) FROM alerts WHERE ts > ?"
        " GROUP BY severity", (since,))
    alerts_by_severity = {sev: n for sev, n in sev_rows}

    notable_alerts = []
    for sev, title, meaning, what_to_do in dbm.query(
            "SELECT severity, title, meaning, what_to_do FROM alerts"
            " WHERE ts > ? AND severity IN ('High','Critical')"
            " ORDER BY ts DESC", (since,)):
        line = f"{sev} -- {title}"
        if meaning:
            line += f". {meaning}"
        if what_to_do:
            line += f" Next step: {what_to_do}"
        notable_alerts.append(line)

    # Outages: ended ones inside the window, plus anything still down.
    ended = dbm.query(
        "SELECT COUNT(*), COALESCE(SUM(gap_seconds),0) FROM outages"
        " WHERE start_ts > ? AND end_ts IS NOT NULL", (since,))[0]
    ongoing = dbm.query(
        "SELECT target, start_ts FROM outages WHERE end_ts IS NULL")
    n_out, down_seconds = ended[0] or 0, ended[1] or 0
    if n_out or ongoing:
        bits = []
        if n_out:
            bits.append(
                f"{n_out} outage{'s' if n_out != 1 else ''} totalling"
                f" {down_seconds/60:.0f} minute{'s' if down_seconds/60 != 1 else ''}")
        for target, start_ts in ongoing:
            bits.append(
                f"one still going right now ({target},"
                f" down since {_day_label(start_ts)})")
        outages = "Connection drops: " + "; ".join(bits) + "."
    else:
        outages = ("No connection drops at all this week -- the internet"
                   " stayed up the whole time.")

    # New devices / addresses, if the first_seen table exists.
    try:
        n_new = dbm.query(
            "SELECT COUNT(*) FROM first_seen WHERE first_ts > ?",
            (since,))[0][0] or 0
        if n_new:
            firsts = (f"{n_new} new device{'s' if n_new != 1 else ''} or"
                      f" address{'es' if n_new != 1 else ''} appeared on"
                      f" the network for the first time.")
        else:
            firsts = "No new devices or addresses appeared this week."
    except Exception:
        firsts = ("New-device tracking isn't turned on yet, so there's no"
                  " count of first-seen devices for this week.")

    # Busiest day of the week.
    busy = dbm.query(
        "SELECT date(ts, 'unixepoch', 'localtime'), SUM(bytes) FROM flows"
        " WHERE ts > ? GROUP BY 1 ORDER BY SUM(bytes) DESC LIMIT 1",
        (since,))
    if busy and busy[0][1]:
        busiest = datetime.strptime(busy[0][0], "%Y-%m-%d").strftime("%A, %b %d")
        busiest_day = (f"{busiest}"
                       f" ({_fmt_size(busy[0][1]/1e6)} moved)")
    else:
        busiest_day = None

    issues = len(notable_alerts) + n_out + len(ongoing)
    if issues:
        headline = (f"An eventful week: {len(notable_alerts)} high-priority"
                    f" alert{'s' if len(notable_alerts) != 1 else ''} and"
                    f" {n_out + len(ongoing)} connection drop{'s' if n_out + len(ongoing) != 1 else ''}")
    elif total_packets:
        headline = (f"A calm week: {_fmt_size(total_mb)} moved, no outages,"
                    " nothing alarming")
    else:
        headline = "A very quiet week -- almost no traffic was recorded"

    period = (f"{datetime.fromtimestamp(since).strftime('%b %d')}"
              f" - {datetime.fromtimestamp(now).strftime('%b %d, %Y')}")

    return {
        "headline": headline,
        "period": period,
        "totals": {"mb": round(total_mb, 1), "packets": total_packets,
                   "flows": nflows},
        "top_talkers": top_talkers,
        "alerts_by_severity": alerts_by_severity,
        "notable_alerts": notable_alerts,
        "outages": outages,
        "firsts": firsts,
        "busiest_day": busiest_day,
    }


def format_plaintext(report):
    """Warm, plain-English email-style rendering of the weekly dict."""
    t = report["totals"]
    L = ["Your network this week",
         f"({report['period']})",
         "",
         report["headline"] + ".",
         "",
         "How much went through",
         "---------------------",
         (f"This week your network moved about {_fmt_size(t['mb'])}"
          f" across {t['packets']:,} packets"
          f" ({t['flows']:,} separate connections)."),
         "",
         "Where it went",
         "-------------"]
    if report["busiest_day"]:
        L.insert(8, f"Your busiest day was {report['busiest_day']}.")
    else:
        L.insert(8, "There wasn't enough traffic to pick a busiest day.")
    if report["top_talkers"]:
        n = len(report["top_talkers"])
        L.append("The outside address"
                 f"{'es' if n != 1 else ''} you talked to most:")
        for i, talker in enumerate(report["top_talkers"], 1):
            L.append(f"  {i}. {talker}")
    else:
        L.append("No outside connections were recorded this week.")

    L += ["",
          "Anything to look at",
          "-------------------"]
    sev = report["alerts_by_severity"]
    if sev:
        parts = ", ".join(f"{n} {s.lower()} alert{'s' if n != 1 else ''}"
                          for s, n in sorted(sev.items()))
        L.append(f"The monitor raised {parts} this week.")
    else:
        L.append("The monitor didn't raise any alerts this week.")
    if report["notable_alerts"]:
        L.append("Worth a look:")
        for a in report["notable_alerts"]:
            L.append(f"  - {a}")
    elif sev:
        L.append("Nothing in the bunch looks serious --"
                 " they were all low or medium priority.")

    L += ["",
          "Connection",
          "----------",
          report["outages"],
          "",
          "New on the network",
          "------------------",
          report["firsts"],
          "",
          "That's the week in a nutshell. If anything above worries you,"
          " ask me about it and I'll dig in.",
          "-- netmon"]
    return "\n".join(L)


def maybe_polish(report_text):
    """Let the teammate's ai_assist module polish the wording, if present.

    ai_assist.polish_weekly returns None when no API key is configured,
    so the plain report is always a fine fallback. Never raises."""
    try:
        from . import ai_assist
        polished = ai_assist.polish_weekly(report_text)
        return polished or report_text
    except Exception:
        return report_text


def _send_via_notify(text):
    """Use the teammate's notify module if it exposes a generic send."""
    from . import notify
    for name in ("send", "send_email", "send_mail", "send_alert_email"):
        fn = getattr(notify, name, None)
        if callable(fn):
            try:
                fn("Your network this week", text)
                return True
            except TypeError:
                try:
                    fn(text)
                    return True
                except Exception:
                    return False
            except Exception:
                return False
    return None  # no usable generic send function


def email_report(text):
    """Email the weekly report. True if sent, False if skipped.

    Reuses the teammate's notify module when it exposes a generic send
    function; otherwise sends directly via SMTP using
    NETMON_SMTP_HOST/PORT/USER/PASS and NETMON_ALERT_TO. Silent False
    whenever email isn't configured. Never raises."""
    try:
        try:
            sent = _send_via_notify(text)
            if sent:
                return True
        except (ImportError, AttributeError):
            pass

        host = os.environ.get("NETMON_SMTP_HOST")
        to = os.environ.get("NETMON_ALERT_TO")
        if not host or not to:
            return False
        port = int(os.environ.get("NETMON_SMTP_PORT", "587"))
        user = os.environ.get("NETMON_SMTP_USER")
        password = os.environ.get("NETMON_SMTP_PASS")

        msg = EmailMessage()
        msg["Subject"] = "Your network this week"
        msg["From"] = user or "netmon@localhost"
        msg["To"] = to
        msg.set_content(text)

        with smtplib.SMTP(host, port, timeout=20) as s:
            s.starttls()
            if user and password:
                s.login(user, password)
            s.send_message(msg)
        return True
    except Exception:
        return False
