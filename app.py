"""brutedash -- mini SOC analyst: parses auth logs, writes technical briefs.

Pipeline: parse -> detect -> persist -> brief
  parse:    paste an auth log into the form on /
  detect:   detector.detect_brute_force()
  persist:  findings saved to detections.db (SQLite)
  brief:    per-IP button -> LLM-written technical brief, or rule-based fallback

Run:  python app.py   (then open http://127.0.0.1:5000)
"""
import os
import json
import ipaddress
import math
import sqlite3
import tempfile
import threading
import time
from datetime import datetime, timedelta

from flask import Flask, request, render_template_string

from detector import detect_brute_force
from ipintel import lookup_ip, describe as describe_intel
from netmon import config as cfgm

app = Flask(__name__)
# Council review (security, 2026-10-11): cap request bodies -- the / POST
# handler writes the pasted log to a tempfile and appends every finding to
# SQLite, so an unbounded body is a memory/disk DoS on the public demo.
# Flask aborts oversized bodies with 413 before we ever touch them.
# (Mirrors the dashboard's M4 cap; the mini-app needs far less.)
app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


# Content-Security-Policy (2026-10-17, mirrors the dashboard's CSP batch):
# this app has no scripts and no external resources at all -- templates
# are inline <style> plus same-origin forms -- so scripts are refused
# outright and the rest is locked to 'self'.
DEMO_CSP = (
    "default-src 'self'; "
    "script-src 'none'; "
    "style-src 'self' 'unsafe-inline'; "
    "font-src 'self'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "object-src 'none'; "
    "base-uri 'self'; "
    "form-action 'self'; "
    "frame-ancestors 'none'"
)


@app.after_request
def _security_headers(resp):
    # Browser security headers on EVERY response (2026-10-15, mirrors
    # the dashboard): stop MIME sniffing, refuse framing outright (the
    # public demo is never embedded anywhere by design), and leak no
    # referrer. This app sets no session cookie, so there is no cookie
    # hardening to mirror.
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = DEMO_CSP
    return resp


BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "detections.db")


# ---------------------------------------------------------------- persistence
def get_db():
    conn = sqlite3.connect(DB_PATH)
    # L1 (security, 2026-10-20): detections.db holds scan history (which
    # IPs were investigated, when) -- not world-readable. Same self-heal
    # as netmon/db.py: covers fresh files and pre-existing ones whose
    # permissions predate this guard.
    try:
        if os.stat(DB_PATH).st_mode & 0o077:
            os.chmod(DB_PATH, 0o600)
    except OSError:
        pass
    conn.execute(
        "CREATE TABLE IF NOT EXISTS detections ("
        "id INTEGER PRIMARY KEY, ip TEXT, count INTEGER, "
        "severity TEXT, scanned_at TEXT)"
    )
    return conn


def known_ips():
    conn = get_db()
    rows = conn.execute("SELECT DISTINCT ip FROM detections").fetchall()
    conn.close()
    return {r[0] for r in rows}


def save_detections(findings):
    conn = get_db()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    for f in findings:
        conn.execute(
            "INSERT INTO detections (ip, count, severity, scanned_at)"
            " VALUES (?,?,?,?)",
            (f["ip"], f["count"], f["severity"], now),
        )
    # M2 retention (security, 2026-10-20): the demo table used to grow
    # without bound. scanned_at is "%Y-%m-%d %H:%M:%S" text, so the
    # 30-day cutoff compares correctly as a string.
    cutoff = (datetime.now() - timedelta(days=30)).strftime(
        "%Y-%m-%d %H:%M:%S")
    conn.execute("DELETE FROM detections WHERE scanned_at < ?", (cutoff,))
    conn.commit()
    conn.close()
    return now


# ---------------------------------------------------------------------- briefs
# Every brief -- LLM-written or rule-based -- is a dict matching this shape.
# Structured data in, validated data out: the UI renders from the dict, so a
# malformed LLM response can never corrupt the page.
BRIEF_PROMPT = """You are a SOC analyst writing a technical brief.
Evidence: {evidence}
Return ONLY a JSON object with exactly these keys:
{
  "severity": "one of: Low, Medium, High, Critical",
  "observed_pattern": "1-2 sentences grounded ONLY in the evidence",
  "recommended_actions": ["action 1", "action 2", "action 3"]
}
Do not invent facts not present in the evidence. IP intel is context only --
use it to characterize the source (e.g. "hosting-provider IP"), never as
proof of malice. No markdown, no extra text."""

VALID_SEVERITIES = {"Low", "Medium", "High", "Critical"}


def _validate_brief(data):
    """Return the brief dict if it matches the schema, else None."""
    if not isinstance(data, dict):
        return None
    severity = data.get("severity")
    pattern = data.get("observed_pattern")
    actions = data.get("recommended_actions")
    if severity not in VALID_SEVERITIES:
        return None
    if not isinstance(pattern, str) or not pattern.strip():
        return None
    if (not isinstance(actions, list) or not actions
            or not all(isinstance(a, str) and a.strip() for a in actions)):
        return None
    return {"severity": severity,
            "observed_pattern": pattern.strip(),
            "recommended_actions": [a.strip() for a in actions]}


def rule_based_brief(ip, count, severity):
    """Fallback brief in the same structured shape as the LLM output."""
    return {
        "severity": severity,
        "observed_pattern": (f"{ip} made {count} failed SSH login attempts. "
                             "Consistent with a brute-force attack."),
        "recommended_actions": [
            "Block the IP at the firewall (or fail2ban).",
            "Check logs for any successful logins from this IP.",
            "Review and rotate credentials on targeted accounts.",
        ],
    }


def write_brief(ip, count, severity):
    """Return (brief_dict, source). LLM when a key is available, else rules."""
    # Tool use: enrich the IP before reasoning. Best-effort -- an empty
    # dict means "no intel", and the brief is written without it.
    intel = lookup_ip(ip)
    evidence = (f"{ip} made {count} failed SSH login attempts "
                f"(rule-based severity: {severity}).")
    if intel:
        evidence += f" IP intel: {describe_intel(intel)}."
    api_key = os.environ.get("OPENAI_API_KEY")
    if api_key and cfgm.ai_enabled():
        try:
            from openai import OpenAI  # optional dependency
            # Council review 2026-10-18 (security + robustness, quorum):
            # timeout=30, matching ai_assist.py/explainer.py -- a hung
            # API call must never wedge a demo worker for the SDK's
            # ~10-minute default.
            client = OpenAI(api_key=api_key, timeout=30)
            resp = client.chat.completions.create(
                model=cfgm.ai_model(),
                messages=[{"role": "user",
                           "content": BRIEF_PROMPT.format(evidence=evidence)}],
                response_format={"type": "json_object"},
                max_tokens=300,
            )
            brief = _validate_brief(json.loads(resp.choices[0].message.content))
            if brief:
                return brief, "llm"
            # Invalid shape -> fall through to the rule-based brief below.
        except Exception:
            pass
    brief = rule_based_brief(ip, count, severity)
    if intel:
        brief["observed_pattern"] += f" IP intel: {describe_intel(intel)}."
    return brief, "rule-based"


# ------------------------------------------------- /brief rate limiting (S2)
# Every /brief call with the LLM on is a paid API call, and the route is
# unauthenticated. Per-IP sliding windows (ai.ask_per_min per 60s,
# ai.ask_per_hour per 3600s in config.yaml) guard the AI budget from a
# runaway script or a shared machine. Mirrors the dashboard's
# _ai_ask_allowed pattern (netmon/dashboard.py): check-and-record in one
# lock, no check-then-record race; the cheap rule-based fallback is never
# limited -- only the spendy calls count. Breaches return 429 + Retry-After.

_BRIEF_USAGE = {}
_BRIEF_LOCK = threading.Lock()


def _brief_limits():
    """(per_min, per_hour) caps from config.yaml; floor 1, never raises."""
    cfg = cfgm.load_cached()

    def _int(key, default):
        try:
            return max(1, int(cfgm.get(cfg, key, default)))
        except (TypeError, ValueError):
            return default

    return _int("ai.ask_per_min", 10), _int("ai.ask_per_hour", 100)


def _brief_llm_on():
    """Would this /brief call spend an LLM call? Key AND provider != off."""
    return bool(os.environ.get("OPENAI_API_KEY")) and cfgm.ai_enabled()


def _sliding_allowed(usage, ip, now, limits):
    """Sliding-window core shared by the /brief and POST / limiters.

    Check AND record in one lock hold -- no check-then-record race.
    Returns (allowed, retry_after_s). On allowed the call is recorded
    immediately; on denied nothing is recorded. Stale IP keys (last call
    over an hour old) are pruned here, so the dict cannot grow without
    bound from one-shot visitors. `now` must come from ONE clock per
    usage dict (wall for briefs, monotonic for scans); mixing clocks
    inside a dict would corrupt its windows.
    """
    per_min, per_hour = limits
    with _BRIEF_LOCK:
        for key in [k for k, v in usage.items()
                    if not v or max(v) < now - 3600]:
            del usage[key]
        stamps = [t for t in usage.get(ip, []) if now - t < 3600]
        retry = 0
        recent_min = [t for t in stamps if now - t < 60]
        if len(recent_min) >= per_min:
            retry = max(retry, math.ceil(60 - (now - min(recent_min))))
        if len(stamps) >= per_hour:
            retry = max(retry, math.ceil(3600 - (now - min(stamps))))
        if retry > 0:
            usage[ip] = stamps
            return False, retry
        stamps.append(now)
        usage[ip] = stamps
        return True, 0


def _brief_allowed(ip, now=None, limits=None):
    """Per-IP limiter for /brief (LLM spend). Window logic is pure
    (injectable `now` and `limits`) so the unit tests never have to
    sleep."""
    now = time.time() if now is None else now
    return _sliding_allowed(
        _BRIEF_USAGE, ip, now,
        limits if limits is not None else _brief_limits())


_SCAN_USAGE = {}
# M2 (security, 2026-10-20): POST / caps -- a person pasting logs scans a
# handful of times a minute at most; these sit far above that and far
# below a scripted write loop. Fixed values, not config: the cost being
# capped is disk/CPU on the demo box, not a budget the owner tunes.
SCAN_LIMITS = (30, 600)


def _scan_allowed(ip, now=None, limits=None):
    """Per-IP limiter for the POST / write path (security M2).

    Deliberately NOT gated on the LLM being on (unlike /brief): every
    scan runs detection and appends to detections.db whether or not a
    brief is ever requested. Uses a monotonic clock (council ADAPT,
    2026-10-20) so a wall-clock reset cannot reopen the window.
    """
    now = time.monotonic() if now is None else now
    return _sliding_allowed(
        _SCAN_USAGE, ip, now,
        limits if limits is not None else SCAN_LIMITS)


# ---------------------------------------------------------------------- pages
STYLE = """
body{background:#0d1117;color:#c9d1d9;font-family:monospace;max-width:900px;margin:2em auto;padding:0 1em}
h1{color:#58a6ff} table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #30363d;padding:.5em;text-align:left}
th{background:#161b22} .high{color:#f85149;font-weight:bold} .medium{color:#d29922}
a{color:#58a6ff} textarea{width:100%;background:#161b22;color:#c9d1d9;border:1px solid #30363d}
button{background:#238636;color:#fff;border:0;padding:.5em 1.2em;cursor:pointer;font-family:monospace}
pre{background:#161b22;padding:1em;white-space:pre-wrap} .tag{color:#f85149;font-weight:bold}
"""

INDEX_HTML = """<html><head><title>brutedash</title><style>""" + STYLE + """</style></head><body>
<h1>brutedash &mdash; mini SOC analyst</h1>
<p>Paste an SSH auth log below, hit <b>Analyze</b>.</p>
<form method="post">
<textarea name="log" rows="14">{{ sample }}</textarea><br><br>
<button type="submit">Analyze</button>
</form>
<p><a href="/history">View scan history</a></p>
</body></html>"""

RESULTS_HTML = """<html><head><title>brutedash results</title><style>""" + STYLE + """</style></head><body>
<h1>Scan results <small style="color:#8b949e">{{ scanned_at }}</small></h1>
{% if findings %}
<table><tr><th>IP</th><th>Failed attempts</th><th>Severity</th><th></th><th></th></tr>
{% for f in findings %}
<tr><td>{{ f.ip }}</td><td>{{ f.count }}</td>
<td class="{{ f.severity|lower }}">{{ f.severity }}</td>
<td>{% if f.repeat %}<span class="tag">repeat attacker</span>{% endif %}</td>
<td><form method="post" action="/brief" style="margin:0">
<input type="hidden" name="ip" value="{{ f.ip }}">
<input type="hidden" name="count" value="{{ f.count }}">
<input type="hidden" name="severity" value="{{ f.severity }}">
<button type="submit">Generate brief</button></form></td></tr>
{% endfor %}</table>
{% else %}<p>No brute-force activity detected.</p>{% endif %}
<p><a href="/">New scan</a> | <a href="/history">History</a></p>
</body></html>"""

HISTORY_HTML = """<html><head><title>brutedash history</title><style>""" + STYLE + """</style></head><body>
<h1>Scan history</h1>
{% if rows %}
<table><tr><th>Scanned at</th><th>IP</th><th>Failed attempts</th><th>Severity</th></tr>
{% for ip, count, severity, scanned_at in rows %}
<tr><td>{{ scanned_at }}</td><td>{{ ip }}</td><td>{{ count }}</td>
<td class="{{ severity|lower }}">{{ severity }}</td></tr>
{% endfor %}</table>
{% else %}<p>No scans yet.</p>{% endif %}
<p><a href="/">New scan</a></p>
</body></html>"""

BRIEF_HTML = """<html><head><title>brutedash brief</title><style>""" + STYLE + """</style></head><body>
<h1>Technical brief: {{ ip }}</h1>
<p style="color:#8b949e">origin: {{ origin }}</p>
<pre>Severity: {{ brief.severity }}
Observed pattern: {{ brief.observed_pattern }}
Recommended actions:
{% for a in brief.recommended_actions %}- {{ a }}
{% endfor %}</pre>
<p><a href="/">New scan</a> | <a href="/history">History</a></p>
</body></html>"""


def sample_log():
    # Demo UX: pre-fill the whole sample file so a first-time visitor who
    # just hits "Analyze" immediately sees real Critical findings.
    path = os.path.join(BASE_DIR, "auth.log")
    if os.path.exists(path):
        with open(path) as f:
            return "".join(f.readlines())
    return ""


# ---------------------------------------------------------------------- routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        # M2 (security, 2026-10-20): the write path is unauthenticated
        # and grows detections.db on every call -- rate-limit per IP,
        # unconditionally. X-Forwarded-For is deliberately NOT honored
        # (same reasoning as /brief: spoofable on a direct bind).
        requester = request.remote_addr or "unknown"
        allowed, retry_after = _scan_allowed(requester)
        if not allowed:
            return ("Too many scans -- give it a short breather and "
                    "try again shortly.",
                    429, {"Retry-After": str(retry_after)})
        log_text = request.form.get("log", "")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as tmp:
            tmp.write(log_text)
            tmp_path = tmp.name
        try:
            findings = detect_brute_force(tmp_path, threshold=3)
        finally:
            os.unlink(tmp_path)
        seen = known_ips()  # repeat-offender check BEFORE saving this run
        for f in findings:
            f["repeat"] = f["ip"] in seen
        scanned_at = save_detections(findings)
        return render_template_string(RESULTS_HTML, findings=findings,
                                      scanned_at=scanned_at)
    return render_template_string(INDEX_HTML, sample=sample_log())


@app.route("/history")
def history():
    conn = get_db()
    rows = conn.execute(
        "SELECT ip, count, severity, scanned_at FROM detections "
        "ORDER BY scanned_at DESC, count DESC LIMIT 500").fetchall()
    conn.close()
    return render_template_string(HISTORY_HTML, rows=rows)


@app.route("/brief", methods=["POST"])
def brief():
    # L7: these fields feed the LLM prompt -- validate at the boundary.
    ip = request.form.get("ip", "")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return "Invalid IP", 400
    try:
        count = int(request.form.get("count", ""))
    except (TypeError, ValueError):
        return "Invalid count", 400
    severity = request.form.get("severity", "")
    if severity not in VALID_SEVERITIES:
        return "Invalid severity", 400
    if _brief_llm_on():
        # X-Forwarded-For is deliberately NOT honored: trusting it on a
        # direct-bind demo would let anyone spoof the limiter key (same
        # reasoning as the dashboard's _ai_rate_limited).
        requester = request.remote_addr or "unknown"
        allowed, retry_after = _brief_allowed(requester)
        if not allowed:
            return ("Too many brief requests -- the AI budget needs a "
                    "breather. Try again shortly.",
                    429, {"Retry-After": str(retry_after)})
    brief, source = write_brief(ip, count, severity)
    return render_template_string(BRIEF_HTML, ip=ip, brief=brief, origin=source)


if __name__ == "__main__":
    # M1: debug=True enables the Werkzeug debugger -- never ship it.
    app.run()
