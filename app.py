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
import sqlite3
import tempfile
from datetime import datetime

from flask import Flask, request, render_template_string

from detector import detect_brute_force
from ipintel import lookup_ip, describe as describe_intel
from netmon import config as cfgm

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "detections.db")


# ---------------------------------------------------------------- persistence
def get_db():
    conn = sqlite3.connect(DB_PATH)
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
            client = OpenAI(api_key=api_key)
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
    path = os.path.join(BASE_DIR, "auth.log")
    if os.path.exists(path):
        with open(path) as f:
            return "".join(f.readlines()[:12])
    return ""


# ---------------------------------------------------------------------- routes
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
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
        "ORDER BY scanned_at DESC, count DESC").fetchall()
    conn.close()
    return render_template_string(HISTORY_HTML, rows=rows)


@app.route("/brief", methods=["POST"])
def brief():
    ip = request.form["ip"]
    count = request.form["count"]
    severity = request.form["severity"]
    brief, source = write_brief(ip, count, severity)
    return render_template_string(BRIEF_HTML, ip=ip, brief=brief, origin=source)


if __name__ == "__main__":
    app.run(debug=True)
