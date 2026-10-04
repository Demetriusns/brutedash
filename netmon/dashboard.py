"""netmon/dashboard.py -- live Flask dashboard for the network monitor.

Pages:
  /        live dashboard (polls /api/stats every 5s)
  /pcap    upload a .pcap (e.g. from Wireshark) -> analyze -> AI explanation
  /explain POST -> regenerate the plain-English summary on demand

Run via netmon/run.py (starts capture + watchdog threads), or standalone
for viewing an existing database:  python -m netmon.dashboard
"""
import hmac
import functools
import json
import os
import re
import sys
import tempfile
import threading
import time

from flask import Flask, request, jsonify, render_template_string, redirect, \
    session, Response

from . import db as dbm
from . import config as cfgm
from . import relay as relaym

app = Flask(__name__)
app.secret_key = os.environ.get("NETMON_SECRET_KEY", "") or os.urandom(24)

# M4: cap uploads -- a multi-GB pcap is a disk/memory DoS. Flask aborts
# oversized bodies with 413 before we ever touch them.
app.config["MAX_CONTENT_LENGTH"] = 100 * 1024 * 1024


@app.after_request
def _no_cache_html(resp):
    # The dashboard is a live view. A stale cached copy after an update
    # looks exactly like a broken monitor, so browsers must never cache
    # the HTML pages (API JSON is fetched fresh every 5s anyway).
    if resp.content_type.startswith("text/html"):
        resp.headers["Cache-Control"] = "no-store, must-revalidate"
        resp.headers["Pragma"] = "no-cache"
    return resp
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

# Dashboard sign-in: owner vs viewer roles (Phase 3.5 batch 16).
#
# Two shared secrets, no user database -- right-sized for a home/small-biz
# box. The owner password unlocks everything; the viewer password gives a
# read-only dashboard (sees everything, changes nothing).
#
# Resolution (see netmon/config.py auth_passwords): BRUTEDASH_AUTH_* env
# vars win, then config.yaml auth.*, then the legacy NETMON_PASSWORD as
# the owner password (deprecated alias). If only one password is set it
# is the owner and viewer sign-in stays disabled. No passwords at all =
# open dashboard (localhost dev), exactly like before roles existed.
#
# The role lives in the signed Flask session -- it comes from the
# server-side password check at login, never from a client parameter.
# Every mutating route is wrapped with @_owner_required (403 otherwise);
# the login page is rate-limited as before (H2).


def _auth():
    """(owner_password, viewer_password), resolved fresh each call."""
    return cfgm.auth_passwords()


def _role():
    """The signed-in role: "owner" | "viewer" | None."""
    role = session.get("role")
    return role if role in ("owner", "viewer") else None


def _auth_enabled():
    owner_pw, _viewer_pw = _auth()
    return bool(owner_pw)


@app.before_request
def _password_gate():
    if not _auth_enabled():
        return None
    if request.path in ("/login", "/api/health"):
        return None
    if _role() is not None:
        return None
    return redirect("/login")


def _owner_required(fn):
    """Route decorator: only the owner role may mutate the monitor.

    Viewers get a 403 with a plain-English reason (JSON for API calls,
    a short page for page views). When no owner password is configured
    the dashboard is open (backwards compatible: no gate at all) and
    the decorator is a no-op.
    """
    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        if _auth_enabled() and _role() != "owner":
            msg = ("Owner sign-in required -- this changes the monitor."
                   " Viewers can look, not touch.")
            if request.method == "GET":
                return render_template_string(
                    _OWNER_ONLY_HTML, message=msg), 403
            return jsonify({"ok": False, "error": msg}), 403
        return fn(*args, **kwargs)
    return wrapper


# --- loop-down watchdog (batch 16, sensor-down alerting, local layer) ---------
# The monitor loop stamps a tick watermark every pass; if the loop thread
# dies, the dashboard -- which usually outlives it -- is the thing that
# notices. Checked at most once a minute (cheap: one pid-file stat + one
# meta read); a dead loop records ONE High self-alert per episode, shown
# on the next page view. Dashboard-only mode (no pid file) never pages.
_LOOP_WATCH_LAST = 0


@app.before_request
def _loop_watchdog_tick():
    global _LOOP_WATCH_LAST
    now = time.time()
    if now - _LOOP_WATCH_LAST < 60:
        return None
    _LOOP_WATCH_LAST = now
    try:
        from . import pipeline as pipelinem
        pipelinem.safe_step("loop-watchdog",
                            pipelinem.check_and_alert_loop_down)
    except Exception:
        pass
    return None


STYLE = """
body{background:#0d1117;color:#c9d1d9;font-family:monospace;max-width:1000px;margin:2em auto;padding:0 1em}
h1{color:#58a6ff} h2{color:#8b949e;border-bottom:1px solid #30363d;padding-bottom:.3em}
table{border-collapse:collapse;width:100%;margin:1em 0}
th,td{border:1px solid #30363d;padding:.5em;text-align:left;font-size:.9em}
th{background:#161b22}
.card{display:inline-block;background:#161b22;border:1px solid #30363d;border-radius:6px;padding:1em 1.5em;margin:.4em;min-width:150px}
.card.graphcard{min-width:300px;vertical-align:top}
#pktgraph{display:block;margin-top:.4em;width:100%;height:auto}
.card .v{font-size:1.6em;color:#58a6ff} .card .l{color:#8b949e;font-size:.85em}
.up{color:#3fb950;font-weight:bold} .down{color:#f85149;font-weight:bold}
.high{color:#f85149;font-weight:bold} .medium{color:#d29922} .low{color:#8b949e} .critical{color:#f85149;font-weight:bold;background:#3d1113}
.bar{background:#30363d;border-radius:3px;height:1em;margin:.2em 0}
.bar>div{background:#58a6ff;height:1em;border-radius:3px}
a{color:#58a6ff} button{background:#238636;color:#fff;border:0;padding:.5em 1.2em;cursor:pointer;font-family:monospace;border-radius:4px}
.btn-sm{background:#238636;color:#fff;border:0;padding:.25em .8em;cursor:pointer;font-family:monospace;border-radius:4px;font-size:.85em;margin:.25em .2em 0 0}
.btn-sm.ghost{background:#21262d;border:1px solid #30363d}
.badge{display:inline-block;padding:.15em .6em;border-radius:999px;font-size:.8em;white-space:nowrap}
.badge.ok{background:#1a3a24;color:#7ee787;border:1px solid #2d6a3f}
.badge.warn{background:#3d2e12;color:#f0b429;border:1px solid #8a6d1f}
.badge.bad{background:#3d1113;color:#f85149;border:1px solid #8a1f1f}
.badge.mitre{background:#1c2b4a;color:#9ecbff;border:1px solid #2f4a7a;cursor:help}
.sugcard{background:#0d1117;border:1px solid #30363d;border-radius:6px;padding:.8em 1em;margin:.6em 0}
p.warn{background:#3d2e12;border:1px solid #8a6d1f;color:#f0b429;padding:.5em .8em;border-radius:4px}
input,textarea,select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;font-family:monospace;padding:.4em;border-radius:4px}
.banner-red{background:#3d1113;border:1px solid #f85149;color:#f85149;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
.banner-blue{background:#0d2137;border:1px solid #58a6ff;color:#58a6ff;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
.banner-amber{background:#2e1f0d;border:1px solid #d29922;color:#d29922;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
pre{background:#161b22;padding:1em;white-space:pre-wrap;border:1px solid #30363d;border-radius:6px}
.alert{border-left:4px solid #d29922;background:#161b22;padding:.6em 1em;margin:.5em 0}
.alert.High{border-color:#f85149} .alert.Critical{border-color:#f85149;background:#2a1215}
.note{color:#8b949e;font-size:.85em}
html{scroll-behavior:smooth}
nav.top{position:sticky;top:0;z-index:50;background:rgba(13,17,23,.94);
backdrop-filter:blur(6px);border-bottom:1px solid #30363d;padding:.55em 1em;
display:flex;align-items:center;gap:1.1em;margin:0 -1em 1em;flex-wrap:wrap}
nav.top .brand{color:#58a6ff;font-weight:bold;font-size:1.15em;text-decoration:none}
nav.top a.nl{color:#8b949e;text-decoration:none;font-size:.9em;padding:.3em .55em;border-radius:4px}
nav.top a.nl:hover{background:#161b22;color:#c9d1d9}
.pill{display:inline-block;padding:.2em .8em;border-radius:999px;font-size:.78em;font-weight:bold;letter-spacing:.03em}
.pill.ok{background:#1a3a24;color:#7ee787;border:1px solid #2d6a3f}
.pill.warn{background:#3d1113;color:#f85149;border:1px solid #f85149}
.badge-count{background:#f85149;color:#fff;border-radius:999px;font-size:.72em;padding:.1em .5em;font-weight:bold;margin-left:.25em}
.hero{background:#161b22;border:1px solid #30363d;border-radius:10px;padding:1.2em 1.5em;margin:0 0 1.5em}
.hero h1{margin-top:0}
section.block{margin:0 0 2.2em}
section.block>h2{font-size:1.25em;margin-bottom:.4em}
.card.kpi .v{font-size:2em}
.tnode{cursor:pointer}
.tnode circle{stroke-width:2}
.tnode text{fill:#c9d1d9;font-family:monospace}
.tnode:hover circle{stroke:#58a6ff;stroke-width:3}
.tnode.sel circle{stroke:#f0b429;stroke-width:3}
.tedge{stroke:#58a6ff;opacity:.4}
.tedge.lan{stroke:#8b949e;opacity:.28}
.tedge.flow{stroke-dasharray:7 7;animation:tflow 1.1s linear infinite}
@keyframes tflow{to{stroke-dashoffset:-14}}
.tlabel{font-size:11px;text-anchor:middle}
.tsub{font-size:9px;fill:#8b949e;text-anchor:middle}
#topomap svg{width:100%;height:auto;display:block}
#topodetails{margin-top:.6em}
.card.kpi-ok{border-color:#2d6a3f} .card.kpi-ok .v{color:#7ee787}
.card.kpi-warn{border-color:#8a6d1f} .card.kpi-warn .v{color:#f0b429}
.card.kpi-bad{background:#3d1113;border-color:#f85149} .card.kpi-bad .v{color:#f85149}
details.settings{border:1px solid #30363d;border-radius:8px;margin:.6em 0;background:#0d1117}
details.settings>summary{cursor:pointer;padding:.75em 1em;font-weight:bold;color:#c9d1d9;list-style:none}
details.settings>summary::-webkit-details-marker{display:none}
details.settings>summary::before{content:"\\25B8  ";color:#58a6ff}
details.settings[open]>summary::before{content:"\\25BE  "}
details.settings .inner{padding:0 1.2em 1.2em}
footer.site{margin-top:2.5em;padding-top:1em;border-top:1px solid #30363d}
/* viewer role: hide owner-only controls (server still 403s them) */
.viewonly .owneronly{display:none!important}
/* ---- mobile: phones and narrow tablets ---- */
@media (max-width:640px){
  body{margin:0 auto;padding:0 .7em;font-size:15px}
  h1{font-size:1.35em} h2{font-size:1.1em}
  nav.top{gap:.5em;padding:.5em .7em;margin:0 -.7em .8em}
  nav.top .brand{font-size:1em}
  .hero{padding:.9em 1em;margin-bottom:1em}
  .card{display:block;min-width:0;margin:.5em 0;padding:.9em 1em}
  .card.graphcard{min-width:0}
  .card .v{font-size:1.4em} .card.kpi .v{font-size:1.7em}
  table{display:block;overflow-x:auto;-webkit-overflow-scrolling:touch}
  th,td{padding:.45em;font-size:.82em;white-space:nowrap}
  th:first-child,td:first-child{white-space:normal}
  button,.btn-sm{min-height:44px;min-width:44px;font-size:1em}
  .btn-sm{padding:.5em 1em}
  input,textarea,select{font-size:16px;max-width:100%}
  pre{font-size:.78em}
  .alert{padding:.6em .8em}
  section.block{margin-bottom:1.5em}
}
"""

LOGIN_HTML = """<html><head><title>netmon -- sign in</title>
<style>""" + STYLE + """</style></head><body>
<h1>netmon sign in</h1>
<p class="note">This dashboard is password-protected. Enter the dashboard
password to continue.</p>
{% if viewer_note %}<p class="note">Viewer sign-in isn't set up on this box --
use the owner password. (The owner can add a read-only viewer password under
<code>auth.viewer_password</code> in config.yaml.)</p>{% endif %}
{% if error %}<p class="high">{{ error }}</p>{% endif %}
<form method="post">
<input type="password" name="password" autofocus autocomplete="current-password"><br><br>
<button type="submit">Sign in</button>
</form>
</body></html>"""


_OWNER_ONLY_HTML = """<html><head><title>netmon -- owner only</title>
<style>""" + STYLE + """</style></head><body>
<h1>Owner sign-in required</h1>
<p>{{ message }}</p>
<p><a href="/">Back to the dashboard</a> | <a href="/logout">Sign in as owner</a></p>
</body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    owner_pw, viewer_pw = _auth()
    if request.method == "GET":
        return render_template_string(
            LOGIN_HTML, error=None,
            viewer_note=not viewer_pw)
    ip = request.remote_addr or "unknown"
    # H2: no unlimited guessing. 5 failures/minute per IP -> 5-min block.
    if not _login_allowed(ip):
        return render_template_string(
            LOGIN_HTML, error="Too many attempts. Try again later.",
            viewer_note=not viewer_pw), 429
    password = request.form.get("password", "")
    role = None
    if owner_pw and hmac.compare_digest(password, owner_pw):
        role = "owner"
    elif viewer_pw and hmac.compare_digest(password, viewer_pw):
        role = "viewer"
    if role is not None:
        _clear_login_failures(ip)
        # Session fixation: drop any pre-login session contents, then
        # record the role that the server-side password check granted.
        session.clear()
        session["role"] = role
        return redirect("/")
    _record_login_failure(ip)
    return render_template_string(
        LOGIN_HTML, error="Wrong password, try again.",
        viewer_note=not viewer_pw)


# --- login rate limiting (H2, stdlib only) ---------------------------------
# Per-IP sliding window: 5 failures in 60s earns a 5-minute block.
# Successful logins clear the record. State is in-memory; a restart
# resets it, which is fine for a single-owner home monitor.

_LOGIN_ATTEMPTS = {}
_LOGIN_LOCK = threading.Lock()
_LOGIN_MAX = 5
_LOGIN_WINDOW = 60
_LOGIN_BLOCK = 300


def _login_allowed(ip):
    now = time.time()
    with _LOGIN_LOCK:
        stamps = [t for t in _LOGIN_ATTEMPTS.get(ip, [])
                  if now - t < _LOGIN_BLOCK]
        if not stamps:
            _LOGIN_ATTEMPTS.pop(ip, None)
            return True
        _LOGIN_ATTEMPTS[ip] = stamps
        recent = [t for t in stamps if now - t < _LOGIN_WINDOW]
        return len(recent) < _LOGIN_MAX


def _record_login_failure(ip):
    now = time.time()
    with _LOGIN_LOCK:
        stamps = [t for t in _LOGIN_ATTEMPTS.get(ip, [])
                  if now - t < _LOGIN_BLOCK]
        stamps.append(now)
        _LOGIN_ATTEMPTS[ip] = stamps


def _clear_login_failures(ip):
    with _LOGIN_LOCK:
        _LOGIN_ATTEMPTS.pop(ip, None)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/login" if _auth_enabled() else "/")

INDEX_HTML = """<html><head><title>netmon -- your network, explained</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>""" + STYLE + """</style></head><body class="%%BODY_CLASS%%">
<nav class="top">
<a class="brand" href="/">netmon</a>
<span id="status-pill" class="pill ok">&#9679; LIVE</span>
%%ROLE_BADGE%%
<a class="nl" href="#overview">Overview</a>
<a class="nl" href="#alerts">Alerts <span id="nav-alert-badge"></span></a>
<a class="nl" href="#surface">Attack surface</a>
<a class="nl" href="#intel">Threat intel</a>
<a class="nl" href="#traffic">Traffic</a>
<a class="nl" href="#devices">Devices</a>
<a class="nl" href="#assets">Assets</a>
<a class="nl" href="#map">Map</a>
<a class="nl" href="#scan">Open doors</a>
<a class="nl" href="#reports">Reports</a>
<a class="nl" href="#settings">Settings</a>
</nav>
<div id="stalebanner" class="banner-red" style="display:none"></div>
<div id="loopbanner" class="banner-red" style="display:none"></div>
<div id="wnbanner" class="banner-blue" style="display:none">&#128225; Whole-network view: this computer is relaying the LAN, so every device's traffic is monitored.</div>

<div class="hero" id="overview">
<h1>Your network, explained</h1>
<p class="note" id="pagesub">This page watches your computer's network traffic and explains
it in plain English. It never reads <i>what</i> you send or receive -- only
<i>who</i> your computer talks to and <i>how much</i> data moves.
<span id="clock"></span></p>
<div id="cards"></div>
</div>

<section class="block" id="alerts">
<h2>&#128680; What needs your eyes</h2>
<p class="note">Most urgent first. Show: <select id="alertstatusfilter" onchange="refresh()">
<option value="all" selected>All</option><option value="new">New</option>
<option value="acknowledged">Acknowledged</option>
<option value="dismissed">Dismissed</option></select>
Urgency: <select id="alertsevfilter" onchange="refresh()">
<option value="all" selected>All</option><option value="Critical">Critical</option>
<option value="High">High</option><option value="Medium">Medium</option>
<option value="Low">Low</option></select></p>
<div id="alertslist"><p class="note">Loading...</p></div>
</section>

<section class="block" id="surface">
<h2>&#127760; Attack surface <span class="note">where you are exposed, in one place</span>
<button class="btn-sm ghost" onclick="loadAttackSurface();loadAmass()">refresh</button></h2>
<p class="note">Two halves of the same question. <b>What your network exposes</b> is the inside view:
your devices, their open doors, what the internet can reach, and anything sketchy they have
talked to. <b>What the internet sees</b> is the outside view (via Amass, optional): your domain
as the rest of the world sees it. This is a review, not an alarm -- it never pages you, it just
lays out what it sees.</p>
<h3>What your network exposes</h3>
<div id="surface"><p class="note">Loading...</p></div>
<h3>What the internet sees</h3>
<div id="amass"><p class="note">Loading...</p></div>
</section>

<section class="block" id="cases">
<h2>&#128193; Cases <span class="note">related alerts, bundled like an analyst would</span>
<button class="btn-sm ghost" onclick="loadCases()">refresh</button></h2>
<p class="note">Show: <select id="casestatusfilter" onchange="loadCases()">
<option value="open" selected>Open</option><option value="escalated">Escalated</option><option value="closed">Closed</option>
</select></p>
<div id="caseslist"><p class="note">Loading...</p></div>
</section>

<section class="block" id="intel">
<h2>&#128737;&#65039; Threat intel <span class="note">known bad addresses &amp; sites</span>
<button class="btn-sm ghost" onclick="loadIntelStatus()">refresh</button></h2>
<p class="note">Lists of addresses and sites flagged by security researchers. When your network talks to one, you hear about it here. The lists update on their own every 12 hours.</p>
<div id="feedstatus"><p class="note">Loading...</p></div>
<p class="note">Look up an address or a site:
<input id="intelq" placeholder="e.g. 203.0.113.7 or evil.example.com" size="34">
<button class="btn-sm" onclick="intelLookup()">Check</button>
<span class="note" id="intelmsg"></span></p>
<div id="intelresult"></div>
</section>

<section class="block" id="summary">
<h2>&#128172; Summary <button class="owneronly" onclick="explain()">Explain now</button></h2>
<div id="summarybody"><p class="note">Loading...</p></div>
<h2>&#127968; What's normal?</h2>
<p>On a normal day, almost everything your computer does online is one of a few
things: loading websites and apps (encrypted, port 443), looking up website
addresses (port 53), and quiet background chatter like checking the time. If
the alerts above are empty, everything is fine -- <b>a quiet network is a healthy network.</b></p>
<div id="normalnow"><p class="note">Loading...</p></div>
</section>

<section class="block" id="traffic">
<h2>&#128202; Biggest conversations (last 15 min)</h2>
<div id="talkers"></div>
<h2>&#128246; Who is using the internet (last hour)</h2>
<p class="note">Per device, up = sent, down = received. Click a column to sort.</p>
<div id="toptalkers"><p class="note">Loading...</p></div>
<h2>&#128268; Internet uptime</h2>
<div id="outages"><p class="note">Loading...</p></div>
</section>

<section class="block" id="devices">
<h2>&#128241; Your devices</h2>
<p class="note">Name your devices so alerts read like English instead of hardware addresses.</p>
<div id="devices"><p class="note">Loading...</p></div>
<div id="devicedetails"></div>
</section>

<section class="block" id="assets">
<h2>&#128203; Asset inventory <button class="btn-sm ghost" onclick="loadAssets()">refresh</button></h2>
<p class="note">Every device the monitor has seen, with what it could learn without touching it: hostname, maker, OS guess, and open doors from the self scan.</p>
<div id="assets"><p class="note">Loading...</p></div>
</section>

<section class="block" id="map">
<h2>&#128506;&#65039; Network map <button class="btn-sm ghost" onclick="loadTopology()">refresh</button></h2>
<p class="note">Every device on your network and how they connect. Types are best guesses &mdash; click a device for details or to fix its type.</p>
<div id="topomap"><p class="note">Loading...</p></div>
<div id="topodetails"></div>
</section>

<section class="block" id="scan">
<h2>&#128273; Open doors check <button class="btn-sm ghost owneronly" onclick="startScan()">Run scan now</button> <span class="note" id="scanmsg"></span></h2>
<p class="note">A gentle knock on your own devices' doors -- the way an attacker would check them. Weekly scans run automatically; this button runs one on demand. Scans only ever touch your own network.</p>
<div id="scanstatus"><p class="note">Loading...</p></div>
<div id="scanfindings"></div>
<h3 style="margin-top:1em">Deeper check <span class="note">(Nuclei)</span> <button class="btn-sm ghost owneronly" onclick="startNucleiScan()">Run deeper scan</button> <span class="note" id="nucleimsg"></span></h3>
<p class="note">Nuclei runs thousands of known vulnerability checks against your own devices -- deeper than the door-knock above, still your network only. Weekly when enabled; this button runs one on demand. <span id="nucleiinstall"></span></p>
<div id="nucleistatus"><p class="note">Loading...</p></div>
<div id="nucleifindings"></div>
</section>

<section class="block" id="reports">
<h2>&#128202; Reports <span class="note">your score, briefings, exports</span></h2>

<h3>Security score</h3>
<p class="note">One grade for your network, 0 to 100. The monitor computes it
from alerts, open cases, exposed doors, and door-check findings -- a fixed
formula, no AI involved.</p>
<div id="scorecard"><p class="note">Loading...</p></div>

<h3>Morning briefing</h3>
<p class="note">One email a day with the last 24 hours: alerts, cases, your
score, and exposed doors. Preview it here first, or send one now.</p>
<p><button class="btn-sm" onclick="previewBriefing()">Preview briefing</button>
<button class="btn-sm owneronly" onclick="sendBriefing()">Send briefing now</button>
<span class="note" id="briefingmsg"></span></p>
<div id="briefingpreview"></div>

<h3>Downloads</h3>
<p class="note">Compliance reports for your records (or your insurer):
incidents with MITRE tags, what you did about them, alert volume, and score
history.</p>
<p>Compliance report:
<a href="/reports/compliance.html?period=weekly">HTML (week)</a> |
<a href="/reports/compliance.html?period=monthly">HTML (month)</a> |
<a href="/reports/compliance.csv?period=weekly">CSV (week)</a> |
<a href="/reports/compliance.csv?period=monthly">CSV (month)</a></p>
<p>Weekly summary as PDF: <a href="/reports/weekly.pdf">Download PDF</a><br>
<span class="note">Incident briefs download as PDFs from each case timeline.</span></p>

<h3>Forensic rewind</h3>
<div id="rewindstatus"><p class="note">Loading...</p></div>
</section>

<section class="block" id="settings">
<h2>&#9881;&#65039; Settings</h2>

<details class="settings"><summary>Quiet hours</summary><div class="inner">
<p class="note">Email alerts stay silent during these windows. The dashboard still records everything.</p>
<div id="quiethours"><p class="note">Loading...</p></div>
<p class="note">Add a window:
<input id="qh_start" type="time" value="22:00"> to <input id="qh_end" type="time" value="07:00">
<label><input type="checkbox" class="qh_day" value="0" checked>Mon</label>
<label><input type="checkbox" class="qh_day" value="1" checked>Tue</label>
<label><input type="checkbox" class="qh_day" value="2" checked>Wed</label>
<label><input type="checkbox" class="qh_day" value="3" checked>Thu</label>
<label><input type="checkbox" class="qh_day" value="4" checked>Fri</label>
<label><input type="checkbox" class="qh_day" value="5" checked>Sat</label>
<label><input type="checkbox" class="qh_day" value="6" checked>Sun</label>
<button class="btn-sm owneronly" onclick="addQuietWindow()">Add</button></p>
</div></details>

<details class="settings"><summary>Detection rules</summary><div class="inner">
<p class="note">How useful each detection has been, based on what you've acknowledged or dismissed in the last 30 days.</p>
<div id="rulehealth"><p class="note">Loading...</p></div>
</div></details>

<details class="settings"><summary>Never alert me about</summary><div class="inner">
<p class="note">Things the monitor should never bother you about again. A pattern matches when it appears anywhere in the alert's identifying text -- a hardware address, an IP:port, a domain.</p>
<div id="allowlist"><p class="note">Loading...</p></div>
<p class="note">Add:
<select id="al_kind">
<option value="new_device">new_device</option>
<option value="unusual_port">unusual_port</option>
<option value="traffic_spike">traffic_spike</option>
<option value="beaconing">beaconing</option>
<option value="new_external_ip">new_external_ip</option>
<option value="volume_anomaly">volume_anomaly</option>
<option value="dns_lookup_burst">dns_lookup_burst</option>
<option value="dns_tunneling">dns_tunneling</option>
<option value="new_busy_domain">new_busy_domain</option>
<option value="arp_spoof">arp_spoof</option>
</select>
<input id="al_pattern" placeholder="e.g. aa:bb:cc:dd:ee:ff or 8080" size="28">
<button class="btn-sm owneronly" onclick="addAllow()">Add</button></p>
</div></details>

<details class="settings"><summary>Learning from your dismissals</summary><div class="inner">
<p class="note">When you dismiss the same kind of alert a few times, the monitor proposes a "never alert me about this" entry. Nothing changes until you click Apply.</p>
<div id="learnsug"><p class="note">Loading...</p></div>
</div></details>

<details class="settings"><summary>Email digest</summary><div class="inner">
<p><button class="btn-sm owneronly" onclick="sendDigest()">Send digest now</button> <span class="note" id="digestmsg"></span></p>
<p class="note">A digest email goes out automatically once a day (Medium alerts and up, skipping anything you dismissed). Change the timing in config.yaml under alerts &rarr; digest_hours (0 turns it off).</p>
</div></details>

<details class="settings"><summary>Data retention</summary><div class="inner">
<p class="note">How long each kind of data is kept. A daily prune deletes expired rows in small batches so the database never locks up. Alerts on open or escalated cases are never pruned. Change the windows in config.yaml under <code>retention</code> (0 disables pruning for that type).</p>
<div id="retention"><p class="note">Loading...</p></div>
<p><button class="btn-sm owneronly" onclick="pruneNow()">Prune now</button> <span class="note" id="prunemsg"></span></p>
</div></details>

<details class="settings"><summary>Windows logs</summary><div class="inner">
<p class="note">Exported Windows Event Log and firewall logs (see INGEST.md for the export steps). The monitor reads new entries every few minutes: failed logons, new services, USB drives, Defender detections.</p>
<div id="hostevents"><p class="note">Loading...</p></div>
</div></details>

<details class="settings"><summary>This box (sensor health)</summary><div class="inner">
<p class="note">Lightweight self-checks on the computer running brutedash: new listening ports, new services or autorun entries vs. baseline, and Defender real-time protection status. First run learns the baseline silently.</p>
<div id="selfcheck"><p class="note">Loading...</p></div>
<h4 style="margin-top:1em">Software on this box</h4>
<p class="note">What is installed here, checked against the list of security flaws attackers are actively using right now. Local check only -- nothing leaves this box.</p>
<div id="swaudit"><p class="note">Loading...</p></div>
<h4 style="margin-top:1em">Pipeline health</h4>
<p class="note">When each part of the monitor last did its job. A part that's been silent too long raises one alert, then stays quiet until it's healthy again.</p>
<div id="pipehealth"><p class="note">Loading...</p></div>
</div></details>

<details class="settings"><summary>What the numbers mean</summary><div class="inner">
<p class="note">Apps talk on numbered "channels" called ports. Here are the
ones you'll actually see. Anything not on this list is an uncommon channel --
the monitor flags those for you automatically.</p>
%%PORT_GUIDE%%
</div></details>
</section>

<p><a href="/pcap" class="owneronly">Analyze a pcap file</a><span class="owneronly"> | </span><a href="/ask" class="owneronly">Ask your network</a> | <a href="/logout" id="logoutlink" style="display:none">Logout</a></p>

<script>
var ORION_ROLE = "%%ORION_ROLE%%";  // "owner" | "viewer", from the server session
function canWrite(){ return ORION_ROLE === "owner"; }
const SEV_WORDS = {Critical:"Act now", High:"Needs attention", Medium:"Worth a look", Low:"Heads up"};
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
// Live traffic graph: MB and packets per 5s tick from cumulative counters, last ~6 min.
let TR_HIST = [];
let TR_LAST_B = null, TR_LAST_P = null;
const TR_MAX_TICKS = 72;
function drawTrafficGraph(){
  const cv = document.getElementById("pktgraph");
  if (!cv) return;
  const W = cv.width, H = cv.height;
  const ctx = cv.getContext("2d");
  ctx.clearRect(0, 0, W, H);
  const n = TR_HIST.length;
  if (!n) return;
  const maxV = Math.max(0.01, ...TR_HIST);
  const yOf = v => H - 4 - (v / maxV) * (H - 16);
  ctx.strokeStyle = "#21262d"; ctx.lineWidth = 1;
  for (const f of [0.25, 0.5, 0.75]) {
    const y = yOf(f * maxV);
    ctx.beginPath(); ctx.moveTo(0, y); ctx.lineTo(W, y); ctx.stroke();
  }
  const step = W / Math.max(1, TR_MAX_TICKS - 1);
  ctx.beginPath();
  ctx.moveTo(0, H);
  TR_HIST.forEach((v, i) => ctx.lineTo(i * step, yOf(v)));
  ctx.lineTo((n - 1) * step, H);
  ctx.closePath();
  ctx.fillStyle = "rgba(88,166,255,0.25)"; ctx.fill();
  ctx.beginPath();
  TR_HIST.forEach((v, i) => { const x = i * step, y = yOf(v); i ? ctx.lineTo(x, y) : ctx.moveTo(x, y); });
  ctx.strokeStyle = "#58a6ff"; ctx.lineWidth = 2; ctx.stroke();
  ctx.fillStyle = "#8b949e"; ctx.font = "10px sans-serif";
  ctx.fillText("peak " + maxV.toFixed(2) + " MB", 4, 10);
}
const VERDICTS = {};   // alert id -> AI verdict text; survives the 5s re-render
let DEV_COUNT = null;  // devices seen, filled by loadDevices(), shown as a KPI
const SEV_RANK = {Critical: 0, High: 1, Medium: 2, Low: 3};  // triage order
let ALERT_GROUPS = []; // groups from the latest refresh(), for triageGroup/toggleGroup
const PAGESUB_DEFAULT = document.getElementById("pagesub").innerHTML; // restore when relay drops
async function refreshInner(){
  const sf = document.getElementById("alertstatusfilter");
  const r = await fetch("/api/stats?status=" + (sf ? sf.value : "all"));
  const d = await r.json();
  document.getElementById("clock").textContent = "updated " + d.now;
  // Client-side severity filter for the triage queue.
  const sevf = document.getElementById("alertsevfilter");
  let alertList = d.alerts;
  if (sevf && sevf.value !== "all") alertList = alertList.filter(a => a.severity === sevf.value);

  const sb = document.getElementById("stalebanner");
  if (d.stale) {
    sb.style.display = "block";
    sb.textContent = "No fresh data \u2014 the monitor may have stopped. Check that netmon is still running.";
  } else {
    sb.style.display = "none";
  }
  // Loop-down watchdog (batch 16): the monitor loop itself went quiet.
  const lb = document.getElementById("loopbanner");
  if (d.loop_down && d.loop_down.down) {
    lb.style.display = "block";
    lb.textContent = "The monitor itself stopped checking (" + d.loop_down.detail + ") "
      + "Restart brutedash so it can watch your network again.";
  } else {
    lb.style.display = "none";
  }
  // Nav: live/stale pill + urgent-alert badge.
  const pill = document.getElementById("status-pill");
  if (pill) {
    if (d.stale) { pill.innerHTML = "&#9679; STALE"; pill.className = "pill warn"; }
    else { pill.innerHTML = "&#9679; LIVE"; pill.className = "pill ok"; }
  }
  const urgent = alertList.filter(a => a.status === "new" &&
    (a.severity === "High" || a.severity === "Critical")).length;
  const nb = document.getElementById("nav-alert-badge");
  if (nb) nb.innerHTML = urgent ? '<span class="badge-count">' + urgent + '</span>' : "";
  document.getElementById("logoutlink").style.display = d.auth_required ? "inline" : "none";
  const wb = document.getElementById("wnbanner");
  const ps = document.getElementById("pagesub");
  if (d.whole_network && d.relay_active) {
    wb.style.display = "block";
    wb.className = "banner-blue";
    wb.innerHTML = "&#128225; Whole-network view: this computer is relaying the LAN, so every device's traffic is monitored.";
    ps.innerHTML =
      'This page watches <b>every device on your home network</b> and explains ' +
      'it in plain English. It never reads <i>what</i> anyone sends or receives -- only ' +
      '<i>who</i> each device talks to and <i>how much</i> data moves. ' +
      '<span id="clock"></span>';
    document.getElementById("clock").textContent = "updated " + d.now;
  } else if (d.whole_network) {
    wb.style.display = "block";
    wb.className = "banner-amber";
    wb.innerHTML = "&#9888;&#65039; Whole-network mode is on, but the relay isn't running right now &mdash; showing this computer's traffic only.";
    ps.innerHTML = PAGESUB_DEFAULT;
    document.getElementById("clock").textContent = "updated " + d.now;
  } else {
    wb.style.display = "none";
    if (ps.innerHTML !== PAGESUB_DEFAULT) {
      ps.innerHTML = PAGESUB_DEFAULT;
      document.getElementById("clock").textContent = "updated " + d.now;
    }
  }

  // Group repeat alerts (same severity + title) into one card so the
  // list stays readable; expanders reveal individual occurrences.
  // Then Splunk-style urgency sort: Critical first, newest first.
  ALERT_GROUPS = [];
  const gmap = {};
  alertList.forEach(a => {
    const k = a.severity + "|" + a.title;
    if (!gmap[k]) { gmap[k] = {sev: a.severity, title: a.title, items: []}; ALERT_GROUPS.push(gmap[k]); }
    gmap[k].items.push(a);
  });
  ALERT_GROUPS.sort((a, b) => (SEV_RANK[a.sev] ?? 4) - (SEV_RANK[b.sev] ?? 4)
    || String(b.items[0].ts).localeCompare(String(a.items[0].ts)));
  document.getElementById("alertslist").innerHTML = ALERT_GROUPS.length ? ALERT_GROUPS.map((g, gi) => {
    const lead = g.items[0], n = g.items.length;
    const vtxt = VERDICTS[lead.id] ? esc(VERDICTS[lead.id]) : "";
    return `<div class="alert ${esc(g.sev)}"><b>[${SEV_WORDS[g.sev]||esc(g.sev)}] ${esc(g.title)}</b>`
    + (n > 1 ? ` <span class="note">&times;${n}</span>` : "")
    + ` <span class="note">[${esc(lead.status)}]</span>`
    + (lead.mitre_id ? ` <span class="badge mitre" title="${esc(lead.mitre_name || "")} — tactic: ${esc(lead.mitre_tactic || "")}">${esc(lead.mitre_id)}</span>` : "")
    + (lead.meaning ? `<br><b>What this means:</b> ${esc(lead.meaning)}` : "")
    + (lead.is_normal ? `<br><b>Is this normal?</b> ${esc(lead.is_normal)}` : "")
    + (lead.what_to_do ? `<br><b>What to do:</b> ${esc(lead.what_to_do)}` : "")
    + (lead.note ? `<br><b>Your note:</b> ${esc(lead.note)}` : "")
    + `<br><span class="note">${esc(lead.ts)}${lead.detail ? " -- " + esc(lead.detail) : ""}</span>`
    + (lead.trace_id ? `<br><span class="note">Follow-up ID: ${esc(lead.trace_id)}</span>` : "")
    + (n > 1 ? `<br><button class="btn-sm ghost" onclick="toggleGroup(${gi}, this)">show all ${n}</button>`
      + `<div id="group-${gi}" style="display:none">`
      + g.items.slice(1).map(a=>`<span class="note">${esc(a.ts)}${a.detail ? " -- " + esc(a.detail) : ""}</span><br>`).join("")
      + `</div>` : "")
    + `<br>${canWrite()
      ? `<button class="btn-sm" onclick="triageGroup(${gi},'ack')">Ack${n > 1 ? " all" : ""}</button>`
        + `<button class="btn-sm ghost" onclick="triageGroup(${gi},'dismiss')">Dismiss${n > 1 ? " all" : ""}</button>`
        + `<button class="btn-sm ghost" onclick="aiVerdict(${lead.id})">AI verdict</button>`
      : `<span class="note">View-only sign-in: ask the owner to act on this.</span>`}`
    + ` <span class="note" id="verdict-${lead.id}">${vtxt}</span></div>`;
  }).join("") : '<p class="note">No alerts in the last hour. All quiet.</p>';

  const s = d.summary;
  if (s && !EXPLAINING) document.getElementById("summarybody").innerHTML =
    `<p><b>${esc(s.headline)}</b> <span class="note">(${esc(s.origin)}, ${s.window_min} min window)</span></p>`
    + `<p>${esc(s.whats_happening)}</p>`
    + (s.stands_out.length ? "<b>Stands out:</b><ul>" + s.stands_out.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "")
    + (s.suggested_actions.length ? "<b>Suggested:</b><ul>" + s.suggested_actions.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "");

  // Row 1: KPI single-values, Splunk-style -- the "so what" goes first.
  const acNew = (d.alert_counts && d.alert_counts["new"]) || {};
  const openN = Object.values(acNew).reduce((x, y) => x + y, 0);
  const critHighN = (acNew.Critical || 0) + (acNew.High || 0);
  const kpiCls = critHighN ? "kpi-bad" : (openN ? "kpi-warn" : "kpi-ok");
  let cards = `<div class="card kpi ${kpiCls}"><div class="v">${openN}</div><div class="l">things to look at &middot; ${critHighN} urgent</div></div>`;
  cards += `<div class="card"><div class="v">${d.throughput_mbps.toFixed(2)}</div><div class="l">MB per second, right now</div></div>`;
  if (DEV_COUNT !== null) cards += `<div class="card"><div class="v">${DEV_COUNT}</div><div class="l">devices on your network</div></div>`;
  cards += `<div class="card graphcard"><div class="v"><span id="pktrate">&ndash;</span> MB</div><div class="l">live traffic &middot; <span id="pktrate2"></span> packets per tick</div><canvas id="pktgraph" width="280" height="72"></canvas></div>`;
  for (const [label, st] of Object.entries(d.connectivity))
    cards += `<div class="card"><div class="v ${st.up?"up":"down"}">${st.up?"UP":"DOWN"}</div><div class="l">${esc(label)}</div></div>`;
  document.getElementById("cards").innerHTML = cards;

  const bt = d.bytes_total, pt = d.packets_total;
  if (typeof bt === "number" && !d.stale) {
    const mb = (TR_LAST_B === null || bt < TR_LAST_B) ? 0 : (bt - TR_LAST_B) / 1e6;
    const pk = (typeof pt === "number" && TR_LAST_P !== null && pt >= TR_LAST_P) ? pt - TR_LAST_P : 0;
    TR_HIST.push(mb);
    if (TR_HIST.length > TR_MAX_TICKS) TR_HIST.shift();
    TR_LAST_B = bt;
    if (typeof pt === "number") TR_LAST_P = pt;
    const pr = document.getElementById("pktrate");
    if (pr) pr.textContent = mb.toFixed(2);
    const pr2 = document.getElementById("pktrate2");
    if (pr2) pr2.textContent = pk;
  }
  drawTrafficGraph();

  document.getElementById("normalnow").innerHTML =
    `<p>In the last 15 minutes: <b>${d.normal_now.mb} MB</b> across ${d.normal_now.flows} conversations.`
    + (d.normal_now.top_words ? ` Mostly: ${esc(d.normal_now.top_words)}.` : " Nothing moving right now.")
    + `</p>`;

  const maxB = Math.max(1, ...d.talkers.map(t=>t.bytes));
  const dnames = d.device_names || {};
  const named = ip => dnames[ip] ? `<br><span class="note">${esc(dnames[ip])}</span>` : "";
  document.getElementById("talkers").innerHTML = d.talkers.length ?
    `<table><tr><th>From</th><th>To</th><th>Channel (port)</th><th>MB</th><th></th></tr>` +
    d.talkers.map(t=>`<tr><td>${esc(t.src)}${named(t.src)}</td><td>${esc(t.dst)}${named(t.dst)}</td><td>${t.port} (${esc(t.port_words)})</td><td>${(t.bytes/1e6).toFixed(2)}</td><td><div class="bar"><div style="width:${(100*t.bytes/maxB).toFixed(0)}%"></div></div></td></tr>`).join("") + `</table>`
    : '<p class="note">No conversations yet.</p>';

  const wk = d.outage_week || {count: 0, total_s: 0, longest_s: 0, uptime_pct: 100, ongoing_s: 0};
  const wkline = wk.count
    ? `Down ${wk.count} time${wk.count === 1 ? "" : "s"} this week, ${fmtDur(wk.total_s)} total (${(wk.uptime_pct || 0).toFixed(1)}% up)`
    : `No drops this week (${(wk.uptime_pct || 0).toFixed(1)}% up)`;
  document.getElementById("outages").innerHTML =
    (wk.ongoing_s > 0 ? `<p class="down">INTERNET DOWN right now — out for ${fmtDur(wk.ongoing_s)}</p>` : "") +
    (d.ongoing.length ? d.ongoing.map(o=>`<p class="down">INTERNET DOWN: ${esc(o.target)} since ${esc(o.since)}</p>`).join("") : "") +
    `<p><b>${esc(wkline)}</b></p>` +
    (d.outage_log && d.outage_log.length ? `<table><tr><th>What dropped</th><th>Down for</th><th>From</th><th>To</th></tr>` +
      d.outage_log.map(o=>`<tr><td>${esc(o.target)}</td><td>${esc(o.dur)}</td><td class="note">${esc(o.start)}</td><td class="note">${esc(o.end)}</td></tr>`).join("") + `</table>`
      : '<p class="note">No drops recorded. Your connection has been steady.</p>');
}
// refresh() wraps refreshInner so a failed update can never leave the
// whole page stuck on "Loading..." -- the error is shown instead, and
// the next 5-second tick retries automatically.
async function refresh(){
  try { await refreshInner(); }
  catch(e) {
    const el = document.getElementById("alertslist");
    if (el) el.innerHTML = '<div class="banner-red">Dashboard refresh hit a snag: '
      + esc(String((e && e.message) || e))
      + ' — the monitor keeps recording; this is a display hiccup. Retrying…</div>';
  }
}
async function triageGroup(gi, action){
  if(!canWrite()) return;  // viewer role: read-only
  const g = ALERT_GROUPS[gi];
  if (!g) return;
  const note = action === "ack" ? prompt("Optional note (leave blank for none):", "") : "";
  if (note === null) return;  // cancelled
  for (const a of g.items) {
    await fetch("/api/alerts/" + a.id + "/" + action, {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({note: note})});
  }
  refresh();
}
function toggleGroup(gi, btn){
  const el = document.getElementById("group-" + gi);
  const open = el.style.display === "none";
  el.style.display = open ? "block" : "none";
  btn.textContent = open ? "hide" : ("show all " + ALERT_GROUPS[gi].items.length);
}
async function aiVerdict(aid){
  if(!canWrite()) return;  // viewer role: read-only
  const el = document.getElementById("verdict-" + aid);
  if (el) el.textContent = "thinking...";
  const r = await fetch("/api/triage/" + aid, {method:"POST"});
  const d = await r.json();
  const txt = d.unavailable ? d.message : (d.verdict + " \u2014 " + d.reasoning);
  VERDICTS[aid] = txt;  // cache so the 5s refresh doesn't wipe it
  const el2 = document.getElementById("verdict-" + aid);
  if (el2) el2.textContent = txt;
}
let EXPLAINING = false;
async function explain(){
  if(!canWrite()) return;  // viewer role: read-only
  const sdiv = document.getElementById("summarybody");
  EXPLAINING = true;
  sdiv.innerHTML = '<p class="note">Writing summary...</p>';
  try {
    const r = await fetch("/explain", {method:"POST"});
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || "server refused");
    sdiv.innerHTML = '<p class="note">Summary updated (' + esc(d.origin) + ').</p>';
  } catch(e) {
    sdiv.innerHTML = '<p class="note">Could not regenerate the summary: '
      + esc(e.message) + '. It retries on its own every 15 minutes.</p>';
  } finally {
    EXPLAINING = false;
  }
  refresh();
}
let DEV_NAMES = {};
async function loadDevices(){
  try {
    const r = await fetch("/api/devices");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
  DEV_NAMES = {};
  DEV_COUNT = d.devices.length;
  d.devices.forEach(v => { DEV_NAMES[v.mac] = v.name; });
  const nprob = d.devices.filter(v => v.on_probation).length;
  document.getElementById("devices").innerHTML =
    (nprob ? `<p><span class="badge warn">🟡 ${nprob} device${nprob>1?"s":""} on 24h probation watch</span></p>` : "") +
    (d.devices.length ?
    `<table><tr><th>Device</th><th>Status</th><th>Last address</th><th>Traffic (15 min)</th><th>Normal for this device</th><th>First seen</th><th>Last seen</th><th></th></tr>` +
    d.devices.map(v=>{
      const status = v.on_probation
        ? `<span class="badge warn">🟡 Probation · trusted in ${v.probation_left_h}h</span>`
        : `<span class="badge ok">✅ Trusted</span>`;
      const traf = `<span class="note">↑${v.up_mb} ↓${v.down_mb} MB</span>`;
      const prof = v.profile
        ? `<span class="note">~${v.profile.avg_mb_per_hr} MB/hr · busiest ${esc(v.profile.busy)} · learned over ${v.profile.days}d</span>`
        : `<span class="note">Still learning (needs 3 days)</span>`;
      return `<tr><td>${v.name?`<b>${esc(v.name)}</b><br>` :""}<span class="note">${esc(v.mac)}</span></td><td>${status}</td><td>${esc(v.last_ip)}</td><td>${traf}</td><td>${prof}</td><td class="note">${esc(v.first_seen)}</td><td class="note">${esc(v.last_seen)}</td><td><button class="btn-sm ghost" data-mac="${esc(v.mac)}" onclick="showDeviceDetails(this.dataset.mac)">Details</button>${canWrite() ? ` <button class="btn-sm ghost" data-mac="${esc(v.mac)}" onclick="renameDevice(this.dataset.mac)">Rename</button> ${v.quarantined ? `<button class="btn-sm" data-mac="${esc(v.mac)}" data-label="${esc((v.name || v.mac).replace(/"/g, ""))}" onclick="releaseDevice(this.dataset.mac, this.dataset.label)">Release</button>` : `<button class="btn-sm ghost" data-mac="${esc(v.mac)}" data-label="${esc((v.name || v.mac).replace(/"/g, ""))}" onclick="quarantineDevice(this.dataset.mac, this.dataset.label)">Isolate</button>`}` : ""}</td></tr>`;
    }).join("") + `</table>`
    : '<p class="note">No devices seen yet.</p>');
  } catch(e) {
    document.getElementById("devices").innerHTML =
      '<p class="banner-red">Could not load devices: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
async function renameDevice(mac){
  if(!canWrite()) return;  // viewer role: read-only
  const name = prompt("Name for " + mac + " (blank clears it):", DEV_NAMES[mac] || "");
  if (name === null) return;
  await fetch("/api/devices/name", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({mac: mac, name: name})});
  loadDevices();
}

// --- per-device detail page (rap sheets: local device page) ---
async function showDeviceDetails(mac){
  const box = document.getElementById("devicedetails");
  box.innerHTML = '<p class="note">Loading details...</p>';
  try {
    const r = await fetch("/api/device/" + encodeURIComponent(mac));
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || "lookup failed");
    const head = d.name ? `<b>${esc(d.name)}</b> <span class="note">${esc(d.mac)}</span>`
                       : `<b>${esc(d.mac)}</b>`;
    let html = `<div class="sugcard"><h3>${head}</h3>`;
    html += `<p class="note">First seen: ${esc(d.first_seen || "unknown")} &middot; Last seen: ${esc(d.last_seen || "unknown")}`;
    if (d.ips && d.ips.length) html += ` &middot; Addresses: ${d.ips.map(x=>esc(x)).join(", ")}`;
    if (d.hostname) html += `<br>Hostname: ${esc(d.hostname)}`;
    if (d.vendor) html += ` &middot; Maker: ${esc(d.vendor)}`;
    if (d.os_guess) html += ` &middot; OS guess: ${esc(d.os_guess)}`;
    html += `</p>`;
    html += `<p>Traffic (last 24h): <b>&uarr;${esc(String(d.up_mb_24h || 0))} MB</b> sent &middot; <b>&darr;${esc(String(d.down_mb_24h || 0))} MB</b> received</p>`;
    if (d.ports && d.ports.length) {
      html += `<p><b>Ports it talked on (last 24h):</b></p><table><tr><th>Port</th><th>Type</th><th>Connections</th><th>MB</th></tr>` +
        d.ports.map(p=>`<tr><td>${esc(String(p.port))}</td><td>${esc(p.proto)}</td><td>${esc(String(p.flows))}</td><td>${esc(String(p.mb))}</td></tr>`).join("") + `</table>`;
    } else {
      html += `<p class="note">No outbound connections recorded in the last 24h.</p>`;
    }
    if (d.alerts && d.alerts.length) {
      html += `<p><b>Alert history (${d.alerts.length}):</b></p>` +
        d.alerts.map(a=>`<div class="alert ${esc(a.severity)}"><b>[${esc(a.severity)}]</b> ${esc(a.title)} <span class="note">${esc(a.ts)} &middot; ${esc(a.kind)}</span></div>`).join("");
    } else {
      html += `<p class="note">No alerts ever involved this device. A quiet device is a healthy device.</p>`;
    }
    html += `<p><button class="btn-sm ghost" onclick="document.getElementById('devicedetails').innerHTML=''">Close</button></p></div>`;
    box.innerHTML = html;
    box.scrollIntoView();
  } catch(e) {
    box.innerHTML = '<p class="banner-red">Could not load device details: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}

// --- threat intel section (rap sheets) ---
async function loadIntelStatus(){
  const box = document.getElementById("feedstatus");
  try {
    const r = await fetch("/api/intel/status");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    let html = "";
    if (d.feeds && d.feeds.length) {
      html += `<table><tr><th>Feed</th><th>Kind</th><th>Entries</th><th>Last updated</th></tr>` +
        d.feeds.map(f=>`<tr><td>${esc(f.label)}</td><td>${esc(f.kind)}</td><td>${esc(String(f.entries))}</td><td class="note">${esc(f.last_updated)}${f.stale ? ' <span class="badge warn">stale</span>' : ""}</td></tr>`).join("") +
        `</table><p class="note">${esc(String(d.total_entries))} known-bad addresses and sites on file, checked locally.</p>`;
    } else {
      html += `<p class="note">No feeds loaded yet. They load automatically in the background${canWrite() ? `, or <button class="btn-sm" onclick="refreshFeeds()">load them now</button>` : ""}.</p>`;
    }
    if (d.feed_health && d.feed_health.failed_recently) {
      html += `<p class="note">The last refresh didn't go through (network down?), so these are the saved lists from the last good refresh. Detection keeps working from the saved lists.</p>`;
    }
    if (d.abuseipdb) {
      html += `<p class="note">AbuseIPDB scores are on (API key configured).</p>`;
    }
    box.innerHTML = html;
  } catch(e) {
    box.innerHTML = '<p class="banner-red">Could not load feed status: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
async function refreshFeeds(){
  if(!canWrite()) return;  // viewer role: read-only
  const box = document.getElementById("feedstatus");
  box.innerHTML = '<p class="note">Fetching the latest lists... this can take a few seconds.</p>';
  try {
    const r = await fetch("/api/intel/refresh", {method:"POST"});
    const d = await r.json();
    if (!d.ok) throw new Error("refresh failed");
    const parts = Object.entries(d.results || {}).map(([k, v]) =>
      v.ok ? (k + ": " + v.entries + " entries") : (k + ": failed"));
    box.innerHTML = `<p class="note">Refresh done: ${esc(parts.join(" | "))}</p>`;
    loadIntelStatus();
  } catch(e) {
    box.innerHTML = '<p class="banner-red">Feed refresh failed: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
function intelMeaning(d){
  // Plain-English read of an intel result: what it means, what to do.
  if (d.listed && d.listed.length) {
    return {meaning: "This one is on a known-bad list, so treat anything involving it as worth a careful look -- not proof of a break-in, but a real flag.",
            todo: "Check the Cases view for what your network did with it and when. If nothing on your network explains it, disconnect the device and run an antivirus scan."};
  }
  return {meaning: "Not on any of the known-bad lists. That does not make it safe -- it just means nobody has flagged it yet.",
          todo: "If it showed up in an alert, read the alert above for what to do next."};
}
async function intelLookup(){
  const q = document.getElementById("intelq").value.trim();
  const msg = document.getElementById("intelmsg");
  const box = document.getElementById("intelresult");
  msg.textContent = "";
  if (!q) { msg.textContent = "Type an address or a site first."; return; }
  const isIp = /^[0-9a-fA-F:.]+$/.test(q) && (q.indexOf(".") >= 0 || q.indexOf(":") >= 0);
  box.innerHTML = '<p class="note">Checking...</p>';
  try {
    const url = isIp ? "/api/intel/ip/" + encodeURIComponent(q)
                     : "/api/intel/domain/" + encodeURIComponent(q);
    const r = await fetch(url);
    const d = await r.json();
    if (!r.ok || !d.ok) throw new Error(d.error || ("server returned " + r.status));
    const copy = intelMeaning(d);
    let html = `<div class="sugcard"><h3>Here is what we found: ${esc(isIp ? d.ip : d.domain)}</h3>`;
    if (d.listed && d.listed.length) {
      html += `<p><span class="badge warn">&#9888;&#65039; On ${d.listed.length} known-bad list${d.listed.length>1?"s":""}</span></p>`;
      d.listed.forEach(h => {
        html += `<p><b>${esc(h.feed)}</b><br><span class="note">${esc(h.detail)}${h.matched ? " (matched: " + esc(h.matched) + ")" : ""}<br>Listed since ${esc(h.first_seen || "unknown")} &middot; last confirmed ${esc(h.last_seen || "unknown")}</span></p>`;
      });
    } else {
      html += `<p><span class="badge ok">&#10003; Not on any known-bad list</span></p>`;
    }
    if (d.tags && d.tags.length)
      html += `<p class="note">Seen doing: ${d.tags.map(t=>`<span class="badge warn">${esc(t)}</span>`).join(" ")}</p>`;
    if (d.reverse_dns)
      html += `<p class="note">Reverse lookup: ${esc(d.reverse_dns)}</p>`;
    const ab = [];
    if (d.abuse_score !== undefined && d.abuse_score !== null)
      ab.push("abuse score " + esc(String(d.abuse_score)) + "/100");
    if (d.abuse_country) ab.push(esc(d.abuse_country));
    if (d.abuse_isp) ab.push(esc(d.abuse_isp));
    if (d.abuse_asn) ab.push("AS" + esc(String(d.abuse_asn)));
    if (d.abuse_usage) ab.push(esc(d.abuse_usage));
    if (d.abuse_reports) ab.push(esc(String(d.abuse_reports)) + " reports");
    if (d.abuse_domain) ab.push("domain: " + esc(d.abuse_domain));
    if (ab.length) html += `<p><b>AbuseIPDB:</b> ${ab.join(" &middot; ")}${d.abuse_last_reported ? `<br><span class="note">last reported ${esc(d.abuse_last_reported)}</span>` : ""}</p>`;
    if (d.first_seen_here || d.first_lookup)
      html += `<p class="note">On your network: first seen ${esc(d.first_seen_here || d.first_lookup || "never")}${d.last_seen_here || d.last_lookup ? " &middot; last seen " + esc(d.last_seen_here || d.last_lookup) : ""}${d.up_mb_24h !== undefined ? ` &middot; last 24h: &uarr;${esc(String(d.up_mb_24h))} MB &darr;${esc(String(d.down_mb_24h))} MB` : ""}${d.lookups_total !== undefined ? ` &middot; ${esc(String(d.lookups_total))} lookups on file` : ""}</p>`;
    html += `<p><b>Here is what it means:</b> ${esc(copy.meaning)}</p>`;
    html += `<p><b>Here is what to do:</b> ${esc(copy.todo)}</p>`;
    if (d.alerts && d.alerts.length) {
      html += `<p><b>Alerts involving it (${d.alerts.length}):</b></p>` +
        d.alerts.map(a=>`<div class="alert ${esc(a.severity)}"><b>[${esc(a.severity)}]</b> ${esc(a.title)} <span class="note">${esc(a.ts)} &middot; ${esc(a.kind)}</span></div>`).join("");
    }
    html += `</div>`;
    box.innerHTML = html;
  } catch(e) {
    box.innerHTML = '<p class="banner-red">Lookup failed: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
const DAY_NAMES = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
let QH_CACHE = [];
async function loadQuietHours(){
  const r = await fetch("/api/settings/quiet_hours");
  const d = await r.json();
  QH_CACHE = d.windows || [];
  document.getElementById("quiethours").innerHTML = QH_CACHE.length ?
    `<table><tr><th>Days</th><th>From</th><th>To</th><th>Applies to</th><th></th></tr>` +
    QH_CACHE.map((x,i)=>`<tr><td>${x.days.map(dd=>DAY_NAMES[dd]).join(", ")}</td><td>${esc(x.start)}</td><td>${esc(x.end)}</td><td>${esc((x.kinds||["all"]).join(", "))}</td><td>${canWrite() ? `<button class="btn-sm ghost" onclick="delQuietWindow(${i})">Remove</button>` : ""}</td></tr>`).join("") + `</table>`
    : '<p class="note">No quiet hours set -- emails send any time.</p>';
}
async function saveQuietWindows(wins){
  await fetch("/api/settings/quiet_hours", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({windows: wins})});
  loadQuietHours();
}
async function addQuietWindow(){
  if(!canWrite()) return;  // viewer role: read-only
  const days = [...document.querySelectorAll(".qh_day:checked")].map(c=>parseInt(c.value,10));
  saveQuietWindows(QH_CACHE.concat([{days: days,
    start: document.getElementById("qh_start").value || "22:00",
    end: document.getElementById("qh_end").value || "07:00",
    kinds: ["all"]}]));
}
async function delQuietWindow(i){
  if(!canWrite()) return;  // viewer role: read-only
  saveQuietWindows(QH_CACHE.filter((_,j)=>j!==i));
}
async function loadRuleHealth(){
  const r = await fetch("/api/rule_health");
  const d = await r.json();
  let html = d.suggestions.map(s=>
    `<p class="note" style="border-left:4px solid #d29922;padding:.4em .8em;background:#161b22">${esc(s.text)}</p>`
  ).join("");
  html += d.rules.length ?
    `<table><tr><th>Rule</th><th>Alerts (30d)</th><th>Acknowledged</th><th>Dismissed</th><th>Precision</th></tr>` +
    d.rules.map(x=>`<tr><td>${esc(x.kind)}</td><td>${x.total}</td><td>${x.acknowledged}</td><td>${x.dismissed}</td><td>${x.precision===null?"--":(x.precision*100).toFixed(0)+"%"}</td></tr>`).join("") + `</table>`
    : '<p class="note">No alert history yet -- rule health appears once alerts have been acknowledged or dismissed.</p>';
  document.getElementById("rulehealth").innerHTML = html;
}
async function loadAllowlist(){
  const r = await fetch("/api/allowlist");
  const d = await r.json();
  document.getElementById("allowlist").innerHTML = d.entries.length ?
    `<table><tr><th>Rule</th><th>Pattern</th><th>Note</th><th></th></tr>` +
    d.entries.map(e=>`<tr><td>${esc(e.kind)}</td><td>${esc(e.pattern)}</td><td>${esc(e.note)}</td><td>${canWrite() ? `<button class="btn-sm ghost" onclick="delAllow(${e.id})">Remove</button>` : ""}</td></tr>`).join("") + `</table>`
    : '<p class="note">Allowlist is empty.</p>';
}
async function addAllow(){
  if(!canWrite()) return;  // viewer role: read-only
  const kind = document.getElementById("al_kind").value;
  const pattern = document.getElementById("al_pattern").value.trim();
  if (!pattern) return;
  await fetch("/api/allowlist", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({kind: kind, pattern: pattern})});
  document.getElementById("al_pattern").value = "";
  loadAllowlist();
}
async function delAllow(id){
  if(!canWrite()) return;  // viewer role: read-only
  await fetch("/api/allowlist/" + id, {method:"DELETE"});
  loadAllowlist();
}
async function loadSuggestions(){
  const r = await fetch("/api/learn/suggestions");
  const d = await r.json();
  document.getElementById("learnsug").innerHTML = d.suggestions.length ?
    d.suggestions.map(s=>
      `<div class="sugcard"><p>${esc(s.why)}</p>` +
      (s.broad ? `<p class="warn">This would silence every '${esc(s.kind)}' alert -- only apply if the whole rule is noise for you.</p>` : ``) +
      `<p class="note">Pattern: <code>${esc(s.pattern)}</code> &middot; Rule: <code>${esc(s.kind)}</code><br>` +
      `The pattern matches anywhere it appears in the alert text, so it can cover more than one exact case (e.g. "port 80" also matches "port 8000").</p>` +
      (canWrite()
        ? `<button class="btn-sm" onclick="decideSug(${s.id},'apply')">Apply -- never alert me about this</button> ` +
          `<button class="btn-sm ghost" onclick="decideSug(${s.id},'ignore')">Ignore</button></div>`
        : `</div>`)).join("")
    : '<p class="note">No suggestions yet. Dismiss a few alerts you do not care about and the monitor will start proposing these.</p>';
}
async function decideSug(id, what){
  if(!canWrite()) return;  // viewer role: read-only
  await fetch("/api/learn/suggestions/" + id + "/" + what, {method:"POST"});
  loadSuggestions(); loadAllowlist();
}
async function sendDigest(){
  if(!canWrite()) return;  // viewer role: read-only
  const el = document.getElementById("digestmsg");
  el.textContent = "sending...";
  const r = await fetch("/api/digest/send", {method:"POST"});
  const d = await r.json();
  el.textContent = d.sent ? "Digest sent."
    : "Nothing to send (no recent alerts, or email isn't configured).";
}
// --- data retention (Phase 3.5 batch 16) ---
async function loadRetention(){
  const el = document.getElementById("retention");
  try {
    const r = await fetch("/api/retention");
    const d = await r.json();
    const labels = {flows_days:"Flow records", observations_days:"DNS/ARP observations",
      alerts_days:"Alerts", summaries_days:"Summaries", outages_days:"Internet uptime log",
      score_snapshots_days:"Score snapshots"};
    let html = "<table><tr><th>Data</th><th>Kept</th></tr>" +
      Object.entries(d.policy || {}).map(([k,v]) =>
        `<tr><td>${esc(labels[k] || k)}</td><td>${v > 0 ? esc(String(v)) + " days" : "forever (pruning off)"}</td></tr>`).join("") +
      "</table>";
    html += `<p class="note">${esc(d.policy_note || "")}</p>`;
    if (d.last_run) {
      const parts = Object.entries(d.last_counts || {}).filter(([,n])=>n)
        .map(([t,n])=>`${esc(t)}: ${esc(String(n))}`).join(", ");
      html += `<p class="note">Last prune: ${esc(d.last_run)} -- deleted ${parts || "nothing (nothing had expired)"}.</p>`;
    } else {
      html += `<p class="note">No prune has run yet.</p>`;
    }
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = '<p class="note">Could not load retention info.</p>';
  }
}
async function pruneNow(){
  if(!canWrite()) return;  // viewer role: read-only
  const el = document.getElementById("prunemsg");
  el.textContent = "pruning...";
  try {
    const r = await fetch("/api/retention/prune", {method:"POST"});
    const d = await r.json();
    el.textContent = d.ok ? "Done." : ("Prune failed: " + (d.error || "unknown"));
  } catch(e) {
    el.textContent = "Prune failed.";
  }
  loadRetention();
}
// --- cases (Phase 3.5): incidents, not scattered alerts -------------------
let CASES_CACHE = [];
async function loadCases(){
  const sf = document.getElementById("casestatusfilter");
  const status = sf ? sf.value : "open";
  const el = document.getElementById("caseslist");
  try {
    const r = await fetch("/api/incidents?status=" + encodeURIComponent(status));
    const d = await r.json();
    CASES_CACHE = d.incidents || [];
    el.innerHTML = CASES_CACHE.length ? CASES_CACHE.map(c =>
      `<div class="alert ${esc(c.severity)}"><b>${esc(c.title)}</b>`
      + ` <span class="note">${c.alert_count} alert${c.alert_count === 1 ? "" : "s"} &middot; updated ${esc(c.updated)}</span>`
      + `<br><span class="note">${esc(c.summary || "")}</span>`
      + `<br><button class="btn-sm ghost" onclick="toggleCase(${c.id}, this)">show timeline</button>`
      + (c.status === "escalated"
          ? ` <span class="badge warn">awaiting admin</span>`
          : "")
      + (canWrite() ? (status === "open"
          ? ` <button class="btn-sm ghost" onclick="closeCase(${c.id})">close case</button>`
            + ` <button class="btn-sm" data-iid="${c.id}" onclick="escalateCase(this.dataset.iid)">escalate to admin</button>`
          : (status === "escalated"
              ? ` <button class="btn-sm ghost" onclick="closeCase(${c.id})">close case</button>`
              : ` <button class="btn-sm ghost" onclick="reopenCase(${c.id})">reopen</button>`))
        : "")
      + `<div id="case-${c.id}" style="display:none"></div></div>`
    ).join("") : '<p class="note">No ' + esc(status) + ' cases. A quiet network is a healthy network.</p>';
  } catch(e) {
    el.innerHTML = '<p class="note">Could not load cases.</p>';
  }
}
async function toggleCase(iid, btn){
  const el = document.getElementById("case-" + iid);
  const open = el.style.display === "none";
  if (open && !el.dataset.loaded) {
    el.innerHTML = '<p class="note">Loading timeline...</p>';
    try {
      const r = await fetch("/api/incidents/" + iid);
      const d = await r.json();
      if (!d.ok) throw new Error(d.error || "not found");
      let escBanner = "";
      const sentEsc = (d.incident.escalations || []).filter(e => e.sent_ok);
      if (sentEsc.length) {
        const last = sentEsc[sentEsc.length - 1];
        escBanner = `<p><span class="badge warn">awaiting admin</span> <span class="note">escalated to ${esc(last.admin_email)} &middot; ${esc(last.when)}</span></p>`;
      }
      el.innerHTML = escBanner + d.incident.alerts.map(a =>
        `<p><b>[${esc(a.severity)}]</b> ${esc(a.title)}`
        + (a.mitre_id ? ` <span class="badge mitre" title="${esc(a.mitre_name || "")} — tactic: ${esc(a.mitre_tactic || "")}">${esc(a.mitre_id)}</span>` : "")
        + `<br><span class="note">${esc(a.ts)}${a.detail ? " — " + esc(a.detail) : ""}</span>`
        + (a.trace_id ? `<br><span class="note">Follow-up ID: ${esc(a.trace_id)}</span>` : "")
        + (a.meaning ? `<br><span class="note">${esc(a.meaning)}</span>` : "")
        + (a.what_to_do ? `<br><span class="note">Next step: ${esc(a.what_to_do)}</span>` : "")
        + (a.playbook ? `<br><a href="/playbook/${esc(a.playbook)}">fix-it guide &rarr;</a>` : "")
        + `</p>`
      ).join("") || '<p class="note">No alerts in this case.</p>';
      el.innerHTML += `<p><a href="/api/rewind/export?incident_id=${iid}">download packets from this case&#39;s window (.pcap)</a> <span class="note">raw packets from the forensic buffer -- opens in Wireshark</span><br>`
        + `<a href="/reports/incident/${iid}.pdf">download incident brief (.pdf)</a></p>`;
      el.dataset.loaded = "1";
    } catch(e) {
      el.innerHTML = '<p class="note">Could not load timeline.</p>';
    }
  }
  el.style.display = open ? "block" : "none";
  btn.textContent = open ? "hide timeline" : "show timeline";
}
async function closeCase(iid){
  if(!canWrite()) return;  // viewer role: read-only
  await fetch("/api/incidents/" + iid + "/close", {method:"POST"});
  loadCases();
}
async function reopenCase(iid){
  if(!canWrite()) return;  // viewer role: read-only
  await fetch("/api/incidents/" + iid + "/reopen", {method:"POST"});
  loadCases();
}
async function escalateCase(iid){
  if(!canWrite()) return;  // viewer role: read-only
  const c = CASES_CACHE.find(x => x.id === Number(iid));
  const title = c ? c.title : "this case";
  const msg = `Escalate "${title}" to your administrator?

This packages the whole case -- timeline, what was found, what you already tried -- and emails it to the admin address in your config. The case will show as "awaiting admin" until it is closed.`;
  if (!confirm(msg)) return;
  const r = await fetch("/api/incidents/" + iid + "/escalate", {method:"POST"});
  const d = await r.json();
  alert(d.ok ? d.message : "Could not escalate: " + (d.error || "unknown error"));
  loadCases();
}
// --- reports: score card, morning briefing, forensic rewind -----------------
// The score is computed by a fixed formula (alerts, open cases, exposed
// doors, door-check findings) -- never the AI. The briefing is one email
// a day; the preview below shows it without sending anything.
async function loadScore(){
  const el = document.getElementById("scorecard");
  try {
    const r = await fetch("/api/score");
    const d = await r.json();
    if (d.neutral || d.score === null || d.score === undefined) {
      el.innerHTML = '<p class="note"><b>Not enough data yet</b> -- ' + esc(d.why || "") + "</p>";
      return;
    }
    const color = d.score >= 80 ? "up" : (d.score >= 50 ? "medium" : "down");
    let html = `<div class="card"><div class="v ${color}">${d.score}</div>`
      + `<div class="l">out of 100</div></div><p>${esc(d.why || "")}</p>`;
    if ((d.factors || []).length) {
      html += "<ul>" + d.factors.map(f =>
        `<li>${esc(f.label)} <span class="note">(-${f.points})</span>`
        + (f.link ? ` <a href="${esc(f.link)}">take a look</a>` : "") + "</li>"
      ).join("") + "</ul>";
    }
    const hist = (d.history || []).filter(h => h.score !== null && h.score !== undefined);
    if (hist.length > 1) {
      html += '<p class="note">Last ' + hist.length + ' days:</p>' + hist.map(h =>
        `<div><span class="note">${esc(h.day)}</span> <span class="bar" style="display:inline-block;width:120px"><div style="width:${Math.max(0, Math.min(100, h.score))}%"></div></span> ${h.score}</div>`
      ).join("");
    }
    el.innerHTML = html;
  } catch(e) {
    el.innerHTML = '<p class="note">Could not load the score.</p>';
  }
}
async function previewBriefing(){
  const el = document.getElementById("briefingpreview");
  const msg = document.getElementById("briefingmsg");
  el.innerHTML = '<p class="note">Building the preview...</p>';
  try {
    const r = await fetch("/api/briefing/preview");
    const d = await r.json();
    el.innerHTML = "<h4>" + esc(d.subject || "") + "</h4>"
      + "<pre>" + esc(d.body || "") + "</pre>"
      + '<p class="note">This is a preview -- nothing was sent.</p>';
    if (msg) msg.textContent = "";
  } catch(e) {
    el.innerHTML = '<p class="note">Could not build the preview.</p>';
  }
}
async function sendBriefing(){
  if(!canWrite()) return;  // viewer role: read-only
  const msg = document.getElementById("briefingmsg");
  if (msg) msg.textContent = "sending...";
  try {
    const r = await fetch("/api/briefing/send", {method:"POST"});
    const d = await r.json();
    if (msg) msg.textContent = d.ok ? "Briefing sent." : ("Could not send: " + (d.error || "unknown error"));
  } catch(e) {
    if (msg) msg.textContent = "Could not send.";
  }
}
async function loadRewindStatus(){
  const el = document.getElementById("rewindstatus");
  try {
    const r = await fetch("/api/rewind/status");
    const d = await r.json();
    if (!d.enabled) {
      el.innerHTML = '<p class="note">Forensic rewind is <b>off</b>. Turn it on in config.yaml under <span class="note">reporting &rarr; rewind_enabled</span> to keep a rolling buffer of raw packets for post-incident review.</p>'
        + '<p class="note">' + esc(d.privacy_note || "") + "</p>";
      return;
    }
    const mb = (d.bytes_kept / 1048576).toFixed(1);
    el.innerHTML = '<p class="note">' + esc(d.retention || "") + "</p>"
      + `<p class="note">Holding right now: ${esc(String(d.segments))} segments, ${mb} MB.</p>`
      + '<p class="note">' + esc(d.privacy_note || "") + "</p>"
      + '<p><a href="/api/rewind/export?hours=1">download the last hour (.pcap)</a></p>';
  } catch(e) {
    el.innerHTML = '<p class="note">Could not load rewind status.</p>';
  }
}
async function quarantineDevice(mac, label){
  if(!canWrite()) return;  // viewer role: read-only
  const msg = `Isolate ${label} (${mac})?

This cuts the device off from the internet: its traffic gets redirected to this monitor box, which drops it. The device can still talk to other devices on your own network.

Undo any time: click Release on this device row and full access comes back in seconds.

Only do this on a network you own.`;
  if (!confirm(msg)) return;
  const r = await fetch("/api/devices/quarantine", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({mac: mac})});
  const d = await r.json();
  if (!d.ok) alert("Could not isolate it: " + (d.error || "unknown error"));
  loadDevices();
}
async function releaseDevice(mac, label){
  if(!canWrite()) return;  // viewer role: read-only
  if (!confirm(`Bring ${label} (${mac}) back? Full network access returns in seconds.`)) return;
  const r = await fetch("/api/devices/quarantine/release", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({mac: mac})});
  const d = await r.json();
  if (!d.ok) alert("Could not release it: " + (d.error || "unknown error"));
  loadDevices();
}
function fmtDur(s){
  s = Math.max(0, Math.round(s || 0));
  if (s < 90) return s + "s";
  const m = Math.round(s / 60);
  if (m < 90) return m + " min";
  return (s / 3600).toFixed(1) + " hr";
}
async function loadAssets(){
  try {
    const r = await fetch("/api/assets");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    document.getElementById("assets").innerHTML = d.assets.length ?
      `<table><tr><th>Device</th><th>Address / hostname</th><th>Maker</th><th>OS guess</th><th>Open doors</th><th>First seen</th><th>Last seen</th></tr>` +
      d.assets.map(a=>{
        const doors = a.open_ports.length
          ? a.open_ports.map(p=>`<span class="badge ${p.risk === "Medium" ? "warn" : "ok"}" title="${esc(p.service)} — ${esc(p.risk)} risk">${p.port}</span>`).join(" ")
          : `<span class="note">none found</span>`;
        const host = a.hostname ? `${esc(a.hostname)} <span class="note">(${esc(a.hostname_source)})</span><br>` : "";
        return `<tr><td>${a.name ? `<b>${esc(a.name)}</b><br>` : ""}<span class="note">${esc(a.mac)}</span></td><td>${host}<span class="note">${esc(a.ip)}</span></td><td>${esc(a.vendor) || '<span class="note">?</span>'}</td><td>${esc(a.os_guess) || '<span class="note">?</span>'}</td><td>${doors}</td><td class="note">${esc(a.first_seen)}</td><td class="note">${esc(a.last_seen)}</td></tr>`;
      }).join("") + `</table>`
      : '<p class="note">No devices seen yet.</p>';
  } catch(e) {
    document.getElementById("assets").innerHTML =
      '<p class="banner-red">Could not load assets: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
let TT_DATA = [], TT_SORT = "total_mb", TT_DIR = -1;
// --- attack surface -------------------------------------------------------
// "Where am I exposed?" -- the inside view (devices, open doors,
// internet reachability, threat-intel context, lateral paths) plus the
// outside view (Amass: what the internet sees of your domain).
// On-demand review only: loaded once at boot, not on the 5s refresh.
function sevBadge(sev){
  const cls = sev === "High" ? "bad" : (sev === "Medium" ? "warn" : "ok");
  return '<span class="badge ' + cls + '">' + esc(sev) + "</span>";
}
async function loadAttackSurface(){
  const el = document.getElementById("surface");
  try {
    const r = await fetch("/api/attack_surface");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    if (!d.ok) throw new Error(d.error || "report failed");
    el.innerHTML = renderAttackSurface(d);
  } catch(e) {
    el.innerHTML = '<p class="banner-red">Could not load attack surface: '
      + esc(String((e && e.message) || e)) + "</p>";
  }
}
function renderAttackSurface(d){
  let h = "<p><b>" + esc(d.summary_line || "") + "</b></p>";
  const exps = d.exposures || [];
  if (exps.length) {
    h += "<h4>Worth a look</h4>" + exps.map(e =>
      '<div class="alert ' + esc(e.severity) + '">'
      + sevBadge(e.severity) + " <b>" + esc(e.title) + "</b>"
      + ' <span class="note">' + esc(e.device || "")
      + (e.device_ip ? " (" + esc(e.device_ip) + ")" : "") + "</span>"
      + "<br>" + esc(e.what_it_means)
      + '<br><span class="note">' + esc(e.why_it_matters) + "</span>"
      + '<br><a href="/playbook/' + esc(e.playbook) + '">fix-it guide &rarr;</a>'
      + "</div>").join("");
  } else {
    h += '<p class="note">No exposures found. A quiet network is a healthy network.</p>';
  }
  const paths = d.lateral_paths || [];
  if (paths.length) {
    h += "<h4>Paths an intruder could walk</h4>"
      + '<p class="note">Observed traffic only -- one hop, no guessing.</p>'
      + paths.map(p =>
      '<div class="alert ' + esc(p.severity) + '">'
      + sevBadge(p.severity) + " <b>" + esc(p.title) + "</b>"
      + "<br>" + esc(p.what_it_means)
      + '<br><span class="note">' + esc(p.why_it_matters) + "</span>"
      + '<br><a href="/playbook/' + esc(p.playbook) + '">fix-it guide &rarr;</a>'
      + "</div>").join("");
  }
  const devs = (d.devices || []).slice().sort((a, b) =>
    ((b.exposures || []).length - (a.exposures || []).length));
  if (devs.length) {
    h += "<h4>Your devices</h4><div>" + devs.map(a => {
      const doors = (a.open_ports || []).map(p =>
        '<span class="badge ' + (p.risk === "Medium" ? "warn" : "ok") + '">'
        + esc(String(p.port)) + "</span>").join(" ")
        || '<span class="note">none found</span>';
      const rb = a.reachable
        ? '<span class="badge warn">Seen from outside</span>'
        : '<span class="badge ok">No sign of outside access</span>';
      const nhits = (a.ti_hits || []).length;
      const tih = nhits
        ? '<br><span class="badge warn">' + nhits + " known-bad contact"
          + (nhits === 1 ? "" : "s") + "</span>" : "";
      return '<div class="card"><div><b>'
        + esc(a.name || a.hostname || a.ip || "device")
        + '</b> <span class="note">' + esc(a.type_label || "") + "</span></div>"
        + "<div>" + rb + tih + "</div>"
        + '<div class="note">' + esc(a.reachability_note || "") + "</div>"
        + "<div>Doors: " + doors + "</div>"
        + '<div class="note"><a href="#map">map</a> &middot; '
        + '<a href="#assets">assets</a> &middot; '
        + '<a href="#intel">threat intel</a></div>'
        + "</div>";
    }).join("") + "</div>";
  }
  return h;
}
async function loadAmass(){
  const el = document.getElementById("amass");
  try {
    const r = await fetch("/api/amass");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    el.innerHTML = renderAmass(d);
  } catch(e) {
    el.innerHTML = '<p class="banner-red">Could not load external scan: '
      + esc(String((e && e.message) || e)) + "</p>";
  }
}
function renderAmass(d){
  if (!d.installed) {
    return '<p class="note">' + esc(d.install_note || "Amass is not installed.")
      + "</p>";
  }
  if (!d.enabled) {
    return "<p class='note'>Amass is installed, but the external scan is switched off. "
      + "Turn it on under <code>amass.enabled</code> in config.yaml, and list your own "
      + "domain(s) under <code>amass.domains</code>.</p>";
  }
  if (!(d.domains || []).length) {
    return "<p class='note'>No domains configured. Add your own domain(s) under "
      + "<code>amass.domains</code> in config.yaml -- only configured domains are ever scanned.</p>";
  }
  let h = (canWrite() ? '<p><button class="btn-sm" onclick="startAmass()">Run scan now</button> '
    + '<span class="note" id="amassmsg"></span></p>' : "")
    + "<p class='note'>Passive sources only -- this never touches your servers directly. "
    + "Weekly scans run automatically.</p>";
  for (const dom of d.domains) {
    const run = (d.runs || []).find(x => x.domain === dom);
    const assets = (d.assets || {})[dom] || [];
    const subs = assets.filter(a => a.kind === "subdomain");
    h += "<h4>" + esc(dom) + "</h4>";
    h += run
      ? "<p class='note'>Last scan: "
        + esc(new Date(run.when * 1000).toLocaleString())
        + " &mdash; " + run.subdomains + " subdomains, " + run.ips + " addresses.</p>"
      : "<p class='note'>No scan yet.</p>";
    if (subs.length) {
      h += "<table><tr><th>Subdomain</th><th>Addresses</th><th>First seen</th></tr>"
        + subs.slice(0, 50).map(s => {
          let det = {};
          try { det = JSON.parse(s.detail || "{}"); } catch(e2) { det = {}; }
          return "<tr><td>" + esc(s.value) + "</td><td class='note'>"
            + esc((det.ips || []).join(", ")) + "</td><td class='note'>"
            + (s.first_seen ? esc(new Date(s.first_seen * 1000).toLocaleDateString()) : "?")
            + "</td></tr>";
        }).join("") + "</table>";
      if (subs.length > 50) {
        h += "<p class='note'>...and " + (subs.length - 50) + " more.</p>";
      }
    } else if (run) {
      h += "<p class='note'>No subdomains found in the last scan.</p>";
    }
  }
  return h;
}
async function startAmass(){
  if(!canWrite()) return;  // viewer role: read-only
  const m = document.getElementById("amassmsg");
  m.textContent = "starting...";
  try {
    const r = await fetch("/api/amass/run", {method:"POST"});
    const d = await r.json();
    m.textContent = d.started
      ? "scan running for: " + (d.domains || []).join(", ")
      : (d.error || d.note || "not started");
  } catch(e) { m.textContent = "could not start: " + String((e && e.message) || e); }
}
async function loadTopTalkers(){
  try {
    const r = await fetch("/api/top_talkers");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    TT_DATA = d.talkers || [];
    renderTopTalkers();
  } catch(e) {
    document.getElementById("toptalkers").innerHTML =
      '<p class="banner-red">Could not load: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
function sortTopTalkers(col){
  if (TT_SORT === col) { TT_DIR = -TT_DIR; } else { TT_SORT = col; TT_DIR = -1; }
  renderTopTalkers();
}
function renderTopTalkers(){
  const rows = TT_DATA.slice().sort((a,b)=> TT_DIR * ((a[TT_SORT] || 0) - (b[TT_SORT] || 0)));
  const maxT = Math.max(1, ...rows.map(x=>x.total_mb || 0));
  const arrow = c => TT_SORT === c ? (TT_DIR === -1 ? " &#9660;" : " &#9650;") : "";
  document.getElementById("toptalkers").innerHTML = rows.length ?
    `<table><tr><th>Device</th><th onclick="sortTopTalkers('up_mb')" style="cursor:pointer">Up MB${arrow("up_mb")}</th><th onclick="sortTopTalkers('down_mb')" style="cursor:pointer">Down MB${arrow("down_mb")}</th><th onclick="sortTopTalkers('total_mb')" style="cursor:pointer">Total MB${arrow("total_mb")}</th><th></th></tr>` +
    rows.map(t=>`<tr><td>${t.name ? `<b>${esc(t.name)}</b><br>` : ""}<span class="note">${esc(t.ip)}</span></td><td>${(t.up_mb || 0).toFixed(1)}</td><td>${(t.down_mb || 0).toFixed(1)}</td><td>${(t.total_mb || 0).toFixed(1)}</td><td><div class="bar"><div style="width:${(100 * (t.total_mb || 0) / maxT).toFixed(0)}%"></div></div></td></tr>`).join("") + `</table>`
    : '<p class="note">No traffic in the last hour.</p>';
}
async function loadScanStatus(){
  try {
    const r = await fetch("/api/scan");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    const lr = d.last_run;
    document.getElementById("scanstatus").innerHTML =
      (d.running ? `<p><span class="badge warn">Scanning your network&hellip;</span> <span class="note">this takes a minute or two</span></p>` : "") +
      (lr ? `<p class="note">Last door-knock scan: ${esc(lr.when)} &mdash; ${lr.devices_scanned} devices, ${lr.findings} open doors, took ${lr.duration_s}s.</p>`
          : `<p class="note">No scan yet. Weekly scans run automatically; you can run one now.</p>`);
    const fs = d.findings || [];
    document.getElementById("scanfindings").innerHTML = fs.length ?
      `<table><tr><th>Device</th><th>Door</th><th>Risk</th><th>What it means</th></tr>` +
      fs.map(f=>`<tr><td>${f.name ? `<b>${esc(f.name)}</b><br>` : ""}<span class="note">${esc(f.ip)}</span></td><td>${f.port} <span class="note">(${esc(f.service)})</span>${f.source === "template" ? ` <span class="note">[check file]</span>` : ""}</td><td><span class="badge ${f.risk === "Medium" ? "warn" : "ok"}">${esc(f.risk)}</span></td><td>${esc(f.what_it_means)}</td></tr>`).join("") + `</table>`
      : (lr ? `<p class="note">No open doors found. A quiet network is a healthy network.</p>` : "");
    renderNuclei(d.nuclei || {});
    if (d.running) setTimeout(loadScanStatus, 5000);
  } catch(e) {
    document.getElementById("scanstatus").innerHTML =
      '<p class="banner-red">Could not load scan status: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
function renderNuclei(n){
  const lr = n.last_run;
  const statusEl = document.getElementById("nucleistatus");
  const installEl = document.getElementById("nucleiinstall");
  if (!n.installed) {
    statusEl.innerHTML = `<p class="note">${esc(n.install_note || "Nuclei is not installed.")}</p>`;
    installEl.innerHTML = "";
    document.getElementById("nucleifindings").innerHTML = "";
    return;
  }
  installEl.innerHTML = "";
  statusEl.innerHTML =
    (n.running ? `<p><span class="badge warn">Deeper scan running&hellip;</span> <span class="note">this takes a while -- thousands of checks</span></p>` : "") +
    (lr ? `<p class="note">Last deeper scan: ${esc(new Date(lr.when * 1000).toLocaleString())} &mdash; ${lr.targets} devices, ${lr.findings} findings (${lr.new_findings} new), took ${lr.duration_s}s.</p>`
        : `<p class="note">No deeper scan yet. ${n.enabled ? "Weekly scans run automatically; you can run one now." : "Turn on <code>nuclei.enabled</code> in config.yaml for weekly scans, or run one now."}</p>`);
  const fs = n.findings || [];
  document.getElementById("nucleifindings").innerHTML = fs.length ?
    `<table><tr><th>Device</th><th>Finding</th><th>Urgency</th><th>What it means</th></tr>` +
    fs.map(f=>`<tr><td><span class="note">${esc(f.ip)}</span></td><td><b>${esc(f.name)}</b><br><span class="note">${esc(f.template_id)}${f.cves ? " &middot; " + esc(f.cves) : ""}</span></td><td><span class="badge ${f.severity === "High" ? "bad" : (f.severity === "Medium" ? "warn" : "ok")}">${esc(f.severity)}</span></td><td>${esc(f.description || "See the finding name above.")}${f.matched_at ? `<br><span class="note">${esc(f.matched_at)}</span>` : ""}</td></tr>`).join("") + `</table>`
    : (lr ? `<p class="note">No findings. A quiet network is a healthy network.</p>` : "");
  if (n.running) setTimeout(loadScanStatus, 10000);
}
async function startNucleiScan(){
  if(!canWrite()) return;  // viewer role: read-only
  const m = document.getElementById("nucleimsg");
  m.textContent = "starting...";
  try {
    const r = await fetch("/api/nuclei/run", {method:"POST"});
    const d = await r.json();
    m.textContent = d.started ? "deeper scan running..." : (d.error || "could not start");
  } catch(e) { m.textContent = "could not start: " + String((e && e.message) || e); }
  loadScanStatus();
}
async function startScan(){
  if(!canWrite()) return;  // viewer role: read-only
  const m = document.getElementById("scanmsg");
  m.textContent = "starting...";
  try {
    const r = await fetch("/api/scan/run", {method:"POST"});
    const d = await r.json();
    m.textContent = d.started ? "scan running..." : (d.error || "already running");
  } catch(e) { m.textContent = "could not start: " + String((e && e.message) || e); }
  loadScanStatus();
}
async function loadHostEvents(){
  try {
    const r = await fetch("/api/host_events");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    const ing = d.ingest || {};
    const head = ing.enabled
      ? `<p class="note">Watching <code>${esc(ing.dir)}</code> &mdash; ${ing.events_stored || 0} events stored, last check ${esc(ing.last_run || "never")}.</p>`
      : `<p class="note">Not configured. Set <code>ingest.watch_dir</code> in config.yaml (see INGEST.md) to start reading exported Windows logs.</p>`;
    const evs = d.events || [];
    document.getElementById("hostevents").innerHTML = head + (evs.length ?
      `<table><tr><th>When</th><th>Event</th><th>Computer</th><th>What happened</th></tr>` +
      evs.map(e=>`<tr><td class="note">${esc(e.when)}</td><td>${esc(e.source)} ${esc(e.event_id)}</td><td>${esc(e.computer)}</td><td>${esc(e.summary)}${e.matched_alert ? ` <span class="note">(linked to a network alert)</span>` : ""}</td></tr>`).join("") + `</table>`
      : `<p class="note">No host events yet.</p>`);
  } catch(e) {
    document.getElementById("hostevents").innerHTML =
      '<p class="banner-red">Could not load host events: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
async function loadSelfcheck(){
  try {
    const r = await fetch("/api/selfcheck");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    const s = d.summary || {};
    const head = s.last_run_ts
      ? `<p class="note">Last check: ${esc(new Date(s.last_run_ts * 1000).toLocaleString())} &mdash; status: <b>${esc(s.status)}</b> <span class="note">(${esc(s.platform)} / ${esc(s.hostname)})</span></p>`
      : `<p class="note">Not run yet. The first check learns the baseline silently; it runs every 6 hours.</p>`;
    const rows = d.checks || [];
    document.getElementById("selfcheck").innerHTML = head + (rows.length ?
      `<table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>` +
      rows.map(c=>`<tr><td>${esc(c.name)}</td><td><span class="badge ${c.status === "ok" ? "ok" : (c.status === "drift" ? "warn" : "")}">${esc(c.status)}</span></td><td>${esc(c.detail)}</td></tr>`).join("") + `</table>` : "");
    renderSwaudit(d.swaudit || {});
    loadPipelineHealth();
  } catch(e) {
    document.getElementById("selfcheck").innerHTML =
      '<p class="banner-red">Could not load self-check status: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
async function loadPipelineHealth(){
  const el = document.getElementById("pipehealth");
  if (!el) return;
  try {
    const r = await fetch("/api/pipeline_health");
    if (!r.ok) throw new Error("server returned " + r.status);
    const d = await r.json();
    const rows = d.stages || [];
    if (!rows.length) {
      el.innerHTML = '<p class="note">No pipeline data yet.</p>';
      return;
    }
    el.innerHTML = `<table><tr><th>Part</th><th>Last did its job</th><th>Status</th></tr>` +
      rows.map(s=>{
        const cls = s.state === "ok" ? "ok" : (s.state === "stale" ? "warn" : "");
        const when = (typeof s.last_ts === "number" && s.last_ts > 0)
          ? esc(new Date(s.last_ts * 1000).toLocaleString()) : "&mdash;";
        return `<tr><td>${esc(s.label)}</td><td class="note">${when}<br>${esc(s.note || "")}</td><td><span class="badge ${cls}">${esc(s.state)}</span></td></tr>`;
      }).join("") + `</table>`;
  } catch(e) {
    el.innerHTML = '<p class="banner-red">Could not load pipeline health: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
function renderSwaudit(sw){
  const el = document.getElementById("swaudit");
  if (!el) return;
  if (!sw.enabled) {
    el.innerHTML = `<p class="note">Disabled. Turn on <code>swaudit.enabled</code> in config.yaml to check installed software against the known-exploited list.</p>`;
    return;
  }
  const head = sw.last_run_ts
    ? `<p class="note">Last check: ${esc(new Date(sw.last_run_ts * 1000).toLocaleString())} &mdash; ${sw.packages} programs inventoried, ${sw.kev_entries} known-exploited flaws on the list.</p>`
    : `<p class="note">Not run yet. Runs daily; the first run is quiet.</p>`;
  const ms = sw.matches || [];
  el.innerHTML = head + (ms.length ?
    `<table><tr><th>Program</th><th>Flaw</th><th>What it is</th></tr>` +
    ms.map(m=>`<tr><td><b>${esc(m.package)}</b> <span class="note">${esc(m.version)} (${esc(m.source)})</span></td><td><span class="badge warn">Medium</span> ${esc(m.cve_id)}${m.due_date ? `<br><span class="note">fix-by ${esc(m.due_date)}</span>` : ""}</td><td>${esc(m.vuln_name || m.product)}<br><span class="note">${esc(m.description)}</span></td></tr>`).join("") + `</table>`
    : (sw.last_run_ts ? `<p class="note">Nothing installed here matches the known-exploited list. A quiet box is a healthy box.</p>` : ""));
}
// --- network map ----------------------------------------------------------
// SVG topology: gateway at top, devices on an arc below. Pure JS, no deps.
// Edge width ~ traffic volume; animated dashes = traffic in the last 5 min.
let TOPO_CACHE = null, TOPO_SEL = null;
const TOPO_COLORS = {phone:"#f9a8d4",laptop:"#fcd34d",desktop:"#fdba74",
  tv:"#c4b5fd",printer:"#9ca3af",iot:"#6ee7b7",ap:"#a5b4fc",
  router:"#93c5fd",server:"#fca5a5",unknown:"#6b7280"};
async function loadTopology(){
  try {
    const r = await fetch("/api/topology");
    if (!r.ok) throw new Error("server returned " + r.status);
    TOPO_CACHE = await r.json();
    if (TOPO_CACHE.ok === false) throw new Error(TOPO_CACHE.error || "map failed");
    renderTopology();
  } catch(e) {
    document.getElementById("topomap").innerHTML =
      '<p class="banner-red">Could not load network map: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
function renderTopology(){
  const d = TOPO_CACHE;
  const box = document.getElementById("topomap");
  if (!d || !d.nodes || !d.nodes.length) {
    box.innerHTML = '<p class="note">No devices seen yet. The map fills in as the monitor watches your network.</p>';
    document.getElementById("topodetails").innerHTML = "";
    return;
  }
  const W = 920, H = 560, CX = 460;
  const gwKey = d.gateway && d.gateway.key;
  const nodes = d.nodes.slice();
  const pos = {};
  const others = nodes.filter(n => n.key !== gwKey);
  if (gwKey) {
    pos[gwKey] = [CX, 92];
    const n = others.length;
    others.forEach((nd, i) => {
      let x, y;
      if (n === 1) { x = CX; y = 400; }
      else {
        const a = Math.PI * (0.12 + 0.76 * i / (n - 1)); // lower arc
        x = CX + 370 * Math.cos(a);
        y = 300 + 195 * Math.sin(a);
      }
      pos[nd.key] = [x, y];
    });
  } else {
    nodes.forEach((nd, i) => {
      const a = 2 * Math.PI * i / nodes.length - Math.PI / 2;
      pos[nd.key] = [CX + 330 * Math.cos(a), 290 + 190 * Math.sin(a)];
    });
  }
  const maxB = Math.max(1, ...d.edges.map(e => e.bytes || 0));
  let svg = '<svg viewBox="0 0 ' + W + ' ' + H + '" role="img" aria-label="Network map">';
  svg += d.edges.map(e => {
    const p1 = pos[e.a], p2 = pos[e.b];
    if (!p1 || !p2) return "";
    const w = (1 + 5 * Math.sqrt((e.bytes || 0) / maxB)).toFixed(1);
    const cls = "tedge" + (e.kind === "lan" ? " lan" : "") + (e.active ? " flow" : "");
    const mb = ((e.bytes || 0) / 1e6).toFixed(1);
    return '<line x1="' + p1[0].toFixed(0) + '" y1="' + p1[1].toFixed(0)
      + '" x2="' + p2[0].toFixed(0) + '" y2="' + p2[1].toFixed(0)
      + '" class="' + cls + '" stroke-width="' + w + '"><title>'
      + esc(e.a) + " \u2194 " + esc(e.b) + " \u2014 " + mb + " MB"
      + (e.active ? " (active now)" : "") + "</title></line>";
  }).join("");
  svg += nodes.map(nd => {
    const p = pos[nd.key] || [CX, 300];
    const col = TOPO_COLORS[nd.dtype] || TOPO_COLORS.unknown;
    const label = nd.name || nd.hostname || nd.vendor || nd.ip || "unknown";
    const sub = [nd.vendor, nd.ip].filter(Boolean).join(" \u00B7 ");
    const sel = TOPO_SEL === nd.key ? " sel" : "";
    return '<g class="tnode' + sel + '" data-key="' + esc(nd.key) + '" onclick="selectTopoNode(this)">' +
      + '<circle cx="' + p[0].toFixed(0) + '" cy="' + p[1].toFixed(0)
      + '" r="26" fill="#161b22" stroke="' + col + '"/>'
      + '<text x="' + p[0].toFixed(0) + '" y="' + (p[1] + 8).toFixed(0)
      + '" text-anchor="middle" font-size="22">' + esc(nd.icon) + "</text>"
      + '<text class="tlabel" x="' + p[0].toFixed(0) + '" y="' + (p[1] + 44).toFixed(0)
      + '">' + esc(label) + "</text>"
      + '<text class="tsub" x="' + p[0].toFixed(0) + '" y="' + (p[1] + 58).toFixed(0)
      + '">' + esc(sub) + "</text>"
      + "<title>" + esc(label) + " \u2014 " + esc(nd.type_label)
      + " (" + esc(nd.ip) + ")</title></g>";
  }).join("");
  svg += "</svg>";
  if (!gwKey) svg += '<p class="note">Gateway not identified yet \u2014 it appears once DHCP traffic is observed, otherwise the most-connected device stands in.</p>';
  box.innerHTML = svg;
  renderTopoDetails();
}
function selectTopoNode(el){
  const key = el.getAttribute("data-key");
  TOPO_SEL = (TOPO_SEL === key) ? null : key;
  renderTopology();
}
function renderTopoDetails(){
  const el = document.getElementById("topodetails");
  const d = TOPO_CACHE;
  if (!d || !TOPO_SEL) { el.innerHTML = ""; return; }
  const n = (d.nodes || []).find(x => x.key === TOPO_SEL);
  if (!n) { el.innerHTML = ""; return; }
  const src = n.dtype_source === "manual" ? "set by you" : "auto-detected";
  const doors = (n.open_ports || []).map(p =>
    esc(String(p.port)) + " " + esc(p.service || "")).join(", ") || "none found";
  const opts = (d.types || []).map(t =>
    '<option value="' + esc(t.key) + '"' + (t.key === n.dtype ? " selected" : "")
    + ">" + esc(t.icon) + " " + esc(t.label) + "</option>").join("");
  el.innerHTML =
    "<table><tr><th>Device</th><td>"
    + (n.name ? "<b>" + esc(n.name) + "</b><br>" : "")
    + (n.hostname ? esc(n.hostname) + "<br>" : "")
    + '<span class="note">' + esc(n.mac) + " \u00B7 " + esc(n.ip) + "</span></td></tr>"
    + "<tr><th>Type</th><td>" + esc(n.icon) + " " + esc(n.type_label)
    + ' <span class="note">(' + esc(src) + ")</span><br>"
    + (n.mac
      ? (canWrite()
        ? '<label class="note">Wrong type? Fix it: </label>'
          + '<select id="topo-relabel" data-mac="' + esc(n.mac)
          + '" onchange="relabelTopo(this)">'
          + '<option value="">auto-detect</option>' + opts + "</select>"
        : "")
      : '<span class="note">MAC unknown \u2014 type cannot be pinned for this node.</span>')
    + "</td></tr>"
    + "<tr><th>Traffic (last hour)</th><td>up " + esc(String(n.up_mb))
    + " MB \u00B7 down " + esc(String(n.down_mb)) + " MB</td></tr>"
    + "<tr><th>Maker / OS guess</th><td>" + (esc(n.vendor) || "?")
    + " \u00B7 " + (esc(n.os_guess) || "?") + "</td></tr>"
    + "<tr><th>Open doors</th><td>" + doors + "</td></tr>"
    + "<tr><th>Alerts (24h)</th><td>" + (n.alerts_24h || 0) + "</td></tr>"
    + '<tr><th>First seen</th><td class="note">'
    + (n.first_seen ? esc(new Date(n.first_seen * 1000).toLocaleString()) : "?")
    + "</td></tr></table>";
}
async function relabelTopo(sel){
  if(!canWrite()) return;  // viewer role: read-only
  const mac = sel.getAttribute("data-mac");
  const dtype = sel.value;
  try {
    const r = await fetch("/api/device_type", {method:"POST",
      headers:{"Content-Type":"application/json"},
      body: JSON.stringify({mac: mac, dtype: dtype})});
    const dd = await r.json();
    if (!dd.ok) throw new Error(dd.error || "rejected");
  } catch(e) {
    document.getElementById("topodetails").innerHTML =
      '<p class="banner-red">Could not save device type: '
      + esc(String((e && e.message) || e)) + "</p>";
    return;
  }
  loadTopology();
}
refresh(); setInterval(refresh, 5000);
loadDevices(); loadQuietHours(); loadRuleHealth(); loadAllowlist(); loadSuggestions(); loadCases(); loadTopology();
loadAssets(); loadTopTalkers(); setInterval(loadTopTalkers, 30000);
loadAttackSurface(); loadAmass(); loadRetention();
loadIntelStatus();
loadScanStatus(); loadHostEvents(); loadSelfcheck();
loadScore(); loadRewindStatus();
</script></body></html>
"""


PCAP_HTML = """<html><head><title>netmon -- analyze pcap</title>
<style>""" + STYLE + """</style></head><body>
<h1>Analyze a pcap file</h1>
<p class="note">Upload a .pcap (e.g. exported from Wireshark). It runs through the
same pipeline: flows, detection rules, and a plain-English AI explanation.</p>
<form method="post" enctype="multipart/form-data">
<input type="file" name="pcap" accept=".pcap,.pcapng,.cap"><br><br>
<button type="submit">Analyze</button>
</form>
<p><a href="/">Back to live dashboard</a></p>
</body></html>"""

PCAP_RESULT_HTML = """<html><head><title>netmon -- pcap results</title>
<style>""" + STYLE + """</style></head><body>
<h1>pcap results: {{ filename }}</h1>
<p class="note">{{ packets }} packets processed.</p>
<h2>AI explanation</h2>
<p><b>{{ summary.headline }}</b> <span class="note">({{ summary.origin }})</span></p>
<p>{{ summary.whats_happening }}</p>
{% if summary.stands_out %}<b>Stands out:</b><ul>
{% for s in summary.stands_out %}<li>{{ s }}</li>{% endfor %}</ul>{% endif %}
{% if summary.suggested_actions %}<b>Suggested:</b><ul>
{% for s in summary.suggested_actions %}<li>{{ s }}</li>{% endfor %}</ul>{% endif %}
<h2>Alerts</h2>
{% if alerts %}{% for a in alerts %}
<div class="alert {{ a.severity }}"><b>[{{ a.severity }}] {{ a.title }}</b><br>
{% if a.meaning %}<b>What this means:</b> {{ a.meaning }}<br>{% endif %}
{% if a.is_normal %}<b>Is this normal?</b> {{ a.is_normal }}<br>{% endif %}
{% if a.what_to_do %}<b>What to do:</b> {{ a.what_to_do }}<br>{% endif %}
<span class="note">{{ a.detail }}</span></div>
{% endfor %}{% else %}<p class="note">No alerts fired on this capture.</p>{% endif %}
<p><a href="/pcap">Analyze another</a> | <a href="/">Live dashboard</a></p>
</body></html>"""


def _fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


def _fmt_dur(seconds):
    """Plain-English duration: 45s, 12 min, 2.5 hr."""
    s = max(0, int(seconds or 0))
    if s < 90:
        return f"{s}s"
    minutes = round(s / 60)
    if minutes < 90:
        return f"{minutes} min"
    return f"{s / 3600:.1f} hr"


def _get_meta(key):
    """Read a dashboard meta value (e.g. last_flow_ts). The teammate's
    get_meta may not exist yet, so guard and return None."""
    try:
        return dbm.get_meta(key)
    except Exception:
        return None


def _flow_health():
    """(last_flow_ts, stale). stale = no flow seen in 5+ minutes."""
    now = time.time()
    last = _get_meta("last_flow_ts")
    try:
        last = float(last) if last is not None else None
    except (TypeError, ValueError):
        last = None
    stale = last is not None and (now - last) > 300
    return last, stale


@app.route("/api/health")
def api_health():
    last, stale = _flow_health()
    return jsonify({
        "ok": True,
        "now": _fmt_ts(time.time()),
        "last_flow_ts": last,
        "stale": stale,
    })


# --- alert triage workflow -------------------------------------------------
# A teammate is adding `status` ('new' default) and `note` columns to alerts,
# plus dbm.set_alert_status(alert_id, status, note=None). Code against it,
# guarded: fall back gracefully if the columns/function aren't there yet.

_ALERT_COLS = ("id, severity, title, detail, meaning, is_normal, what_to_do,"
               " ts")
_ALERT_COLS_EXT = _ALERT_COLS + ", status, note"
_ALERT_COLS_MITRE = _ALERT_COLS_EXT + ", mitre_id, mitre_name, mitre_tactic"

_VALID_STATUS = ("new", "acknowledged", "dismissed")


_ALERT_COLS_TRACE = _ALERT_COLS_MITRE + ", trace_id"


def _alerts(status_filter="all"):
    """Alert dicts for the last hour, newest first, with optional triage
    status filter."""
    try:
        rows = dbm.query(
            f"SELECT {_ALERT_COLS_TRACE} FROM alerts WHERE ts > ?"
            " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
        with_trace = True
        with_mitre = True
        extended = True
    except Exception:
        try:
            rows = dbm.query(
                f"SELECT {_ALERT_COLS_MITRE} FROM alerts WHERE ts > ?"
                " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
            with_trace = False
            with_mitre = True
            extended = True
        except Exception:
            try:
                rows = dbm.query(
                    f"SELECT {_ALERT_COLS_EXT} FROM alerts WHERE ts > ?"
                    " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
                with_trace = False
                with_mitre = False
                extended = True
            except Exception:
                rows = dbm.query(
                    f"SELECT {_ALERT_COLS} FROM alerts WHERE ts > ?"
                    " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
                with_trace = False
                with_mitre = False
                extended = False
    alerts = []
    for r in rows:
        if with_trace:
            (aid, sev, t, d, m, n, w, ts, st, note,
             mitre_id, mitre_name, mitre_tactic, trace_id) = r
        elif with_mitre:
            (aid, sev, t, d, m, n, w, ts, st, note,
             mitre_id, mitre_name, mitre_tactic) = r
            trace_id = ""
        elif extended:
            aid, sev, t, d, m, n, w, ts, st, note = r
            mitre_id = mitre_name = mitre_tactic = None
            trace_id = ""
        else:
            aid, sev, t, d, m, n, w, ts = r
            st, note = "new", ""
            mitre_id = mitre_name = mitre_tactic = None
            trace_id = ""
        alerts.append({
            "id": aid, "severity": sev, "title": t, "detail": d,
            "meaning": m, "is_normal": n, "what_to_do": w,
            "ts": _fmt_ts(ts), "status": st or "new", "note": note or "",
            "mitre_id": mitre_id, "mitre_name": mitre_name,
            "mitre_tactic": mitre_tactic, "trace_id": trace_id or "",
        })
    if status_filter in _VALID_STATUS:
        alerts = [a for a in alerts if a["status"] == status_filter]
    return alerts


def _note_from_request():
    if request.is_json:
        data = request.get_json(silent=True) or {}
    else:
        data = request.form
    note = (data.get("note") or "").strip()
    return note or None


def _set_alert_status(aid, status, note=None):
    """Call the teammate's dbm.set_alert_status; False if unavailable."""
    try:
        dbm.set_alert_status(aid, status, note)
        return True
    except Exception:
        return False


@app.route("/api/alerts/<int:aid>/ack", methods=["POST"])
@_owner_required
def alert_ack(aid):
    note = _note_from_request()
    if not _set_alert_status(aid, "acknowledged", note):
        return jsonify({"ok": False,
                        "error": "triage is not available yet"}), 500
    return jsonify({"ok": True})


@app.route("/api/alerts/<int:aid>/dismiss", methods=["POST"])
@_owner_required
def alert_dismiss(aid):
    note = _note_from_request()
    if not _set_alert_status(aid, "dismissed", note):
        return jsonify({"ok": False,
                        "error": "triage is not available yet"}), 500
    # Learning from the dismissal must never break the dismiss itself,
    # but a broken extractor should not be invisible either.
    try:
        dbm.learn_from_dismissal(aid)
    except Exception as exc:
        print(f"netmon dashboard: learn_from_dismissal failed: {exc!r}",
              file=sys.stderr)
    return jsonify({"ok": True})


# --- incidents: cases, not scattered alerts ------------------------------
# Phase 3.5. Related alerts are bundled into one case with a timeline,
# the way a senior analyst works.

@app.route("/api/incidents")
def api_incidents():
    status = request.args.get("status", "open")
    if status not in ("open", "escalated", "closed"):
        status = "open"
    try:
        cases = dbm.list_incidents(status=status)
    except Exception:
        cases = []
    return jsonify({"incidents": [
        {**c, "created": _fmt_ts(c["created_ts"]),
         "updated": _fmt_ts(c["updated_ts"])} for c in cases]})


@app.route("/api/incidents/<int:iid>")
def api_incident(iid):
    try:
        case = dbm.get_incident(iid)
    except Exception:
        case = None
    if not case:
        return jsonify({"ok": False, "error": "case not found"}), 404
    case["created"] = _fmt_ts(case["created_ts"])
    case["updated"] = _fmt_ts(case["updated_ts"])
    from . import playbooks as _pbm
    for a in case["alerts"]:
        a["ts"] = _fmt_ts(a["ts"])
        a["playbook"] = _pbm.playbook_slug_for_kind(a.get("kind"))
    try:
        case["escalations"] = [
            {**e, "when": _fmt_ts(e["ts"])} for e in
            dbm.list_escalations(iid)]
    except Exception:
        case["escalations"] = []
    return jsonify({"ok": True, "incident": case})


@app.route("/api/incidents/<int:iid>/close", methods=["POST"])
@_owner_required
def api_incident_close(iid):
    if not dbm.set_incident_status(iid, "closed"):
        return jsonify({"ok": False, "error": "case not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/incidents/<int:iid>/reopen", methods=["POST"])
@_owner_required
def api_incident_reopen(iid):
    if not dbm.set_incident_status(iid, "open"):
        return jsonify({"ok": False, "error": "case not found"}), 404
    return jsonify({"ok": True})


@app.route("/api/incidents/<int:iid>/escalate", methods=["POST"])
@_owner_required
def api_incident_escalate(iid):
    """Escalate a case to the administrator (his feature call).

    Packages the full incident bundle -- timeline, MITRE tags, evidence,
    the plain-English brief, recommended actions, what the owner already
    tried -- and emails it to response.admin_email. The case moves to
    'escalated' only when the email actually went out.
    """
    from . import escalate as escm
    ok, message = escm.send_escalation(iid, actor="dashboard")
    if ok:
        return jsonify({"ok": True, "message": message})
    # 409 when the case simply isn't in a state to escalate; 400 for
    # config problems; the message always says what to do next.
    code = 409 if "Only open cases" in message else 400
    return jsonify({"ok": False, "error": message}), code


# --- one-click quarantine (Phase 3.5: act, not just watch) -----------------
# Approval-only, always: a human clicks Isolate/Release on the dashboard.
# No code path in this repo quarantines autonomously -- the safety rules
# live in netmon/quarantine.py (gateway/self/viewer blocklist) and every
# outcome is audit-logged.


@app.route("/api/quarantine", methods=["GET"])
def api_quarantine_list():
    """Devices currently isolated."""
    try:
        active = dbm.active_quarantines()
    except Exception:
        active = []
    names = dbm.device_name_map()
    return jsonify({"quarantined": [
        {**q, "name": names.get((q["mac"] or "").lower(), ""),
         "since": _fmt_ts(q["created_ts"])} for q in active]})


@app.route("/api/devices/quarantine", methods=["POST"])
@_owner_required
def api_device_quarantine():
    """Isolate one device (ARP-isolate it from the internet).

    The safety blocklist (gateway, this box, the viewer's device) is
    enforced server-side in netmon/quarantine.py -- the UI can't skip it.
    """
    from . import quarantine as qm
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"ok": False, "error": "mac is required"}), 400
    ok, message = qm.request_quarantine(
        mac, actor="dashboard", viewer_ip=request.remote_addr)
    if ok:
        return jsonify({"ok": True, "message": message})
    return jsonify({"ok": False, "error": message}), 403


@app.route("/api/devices/quarantine/release", methods=["POST"])
@_owner_required
def api_device_quarantine_release():
    """Lift the isolation on one device (one-click undo)."""
    from . import quarantine as qm
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    if not mac:
        return jsonify({"ok": False, "error": "mac is required"}), 400
    ok, message = qm.release_quarantine(mac, actor="dashboard")
    if ok:
        return jsonify({"ok": True, "message": message})
    return jsonify({"ok": False, "error": message}), 400


# --- devices: friendly names ---------------------------------------------
# Name your hardware ("PS5", "Mom's iPhone") so alerts and tables read
# like English instead of MAC addresses.

PROBATION_HOURS = 24  # new devices stay on probation watch this long


@app.route("/api/devices")
def api_devices():
    now = time.time()
    devs = dbm.known_devices(limit=100)
    try:
        quarantined = {q["mac"] for q in dbm.active_quarantines()}
    except Exception:
        quarantined = set()
    up = {ip: (b or 0) for ip, b in dbm.query(
        "SELECT src_ip, SUM(bytes) FROM flows WHERE ts > ?"
        " AND direction='outbound' GROUP BY src_ip", (now - 900,)) if ip}
    down = {ip: (b or 0) for ip, b in dbm.query(
        "SELECT dst_ip, SUM(bytes) FROM flows WHERE ts > ?"
        " AND direction='inbound' GROUP BY dst_ip", (now - 900,)) if ip}
    profiles = dbm.device_profile_summaries()
    out = []
    for d in devs:
        first = d.get("first_seen") or 0
        probation_ends = first + PROBATION_HOURS * 3600
        on_prob = bool(first) and now < probation_ends
        left_h = max(0.0, (probation_ends - now) / 3600) if on_prob else 0
        lip = d.get("last_ip", "")
        mac = d.get("mac", "")
        prof = profiles.get(mac or "", None)
        out.append({
            "mac": mac, "name": d.get("name", ""),
            "last_ip": lip,
            "quarantined": mac in quarantined,
            "up_mb": round(up.get(lip, 0) / 1e6, 2),
            "down_mb": round(down.get(lip, 0) / 1e6, 2),
            "last_seen": _fmt_ts(d["last_seen"]) if d.get("last_seen") else "",
            "first_seen": _fmt_ts(first) if first else "",
            "on_probation": on_prob,
            "probation_left_h": round(left_h, 1),
            "profile": prof,  # None until 3+ days of history are learned
        })
    return jsonify({"devices": out})


@app.route("/api/devices/name", methods=["POST"])
@_owner_required
def api_device_name():
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    name = (data.get("name") or "").strip()
    if not mac:
        return jsonify({"ok": False, "error": "mac is required"}), 400
    if len(name) > 40:
        return jsonify({"ok": False, "error": "name is too long"}), 400
    try:
        dbm.set_device_name(mac, name)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True})


# --- know the network: assets, top talkers, uptime, scans, host logs -------


@app.route("/api/assets")
def api_assets():
    """Enriched device inventory (asset inventory, Phase 3.5)."""
    from . import assets as assetsm
    names = dbm.device_name_map()
    out = []
    for a in assetsm.get_assets():
        out.append({
            "mac": a["mac"], "ip": a["ip"],
            "name": names.get(a["mac"], ""),
            "hostname": a["hostname"],
            "hostname_source": a["hostname_source"],
            "vendor": a["vendor"], "os_guess": a["os_guess"],
            "open_ports": a["open_ports"],
            "first_seen": _fmt_ts(a["first_seen"]) if a.get("first_seen")
            else "",
            "last_seen": _fmt_ts(a["last_seen"]) if a.get("last_seen")
            else "",
        })
    return jsonify({"assets": out})


@app.route("/api/attack_surface")
def api_attack_surface():
    """The attack surface review: devices, open doors, internet
    reachability, threat-intel context, lateral paths. Read-only --
    this view never fires alerts."""
    from . import attacksurface as asm
    try:
        return jsonify(asm.build_report())
    except Exception as exc:
        import sys as _sys
        print(f"attack_surface report failed: {exc}", file=_sys.stderr)
        return jsonify({"ok": False, "error": "report failed"}), 500


@app.route("/api/amass")
def api_amass():
    """External attack-surface status (OWASP Amass): binary, config,
    last runs, discovered assets per domain. Graceful when the binary
    is missing or nothing is configured."""
    from . import amass as amassm
    try:
        return jsonify(amassm.amass_status())
    except Exception:
        return jsonify({"installed": False,
                        "install_note": "external scan unavailable",
                        "enabled": False, "domains": [], "runs": [],
                        "assets": {}})


@app.route("/api/amass/run", methods=["POST"])
@_owner_required
def api_amass_run():
    """On-demand external scan. SECURITY BOUNDARY: targets come from
    config.yaml only -- the request body is ignored entirely, so the UI
    can never point the scanner at an arbitrary domain."""
    from . import amass as amassm
    try:
        if not amassm.amass_enabled():
            return jsonify({"started": False,
                            "note": "amass.enabled is off in config.yaml"})
        if not amassm.find_binary():
            return jsonify({"started": False,
                            "error": "amass binary not installed"})
        domains = amassm.start_amass_async()
        if not domains:
            return jsonify({"started": False,
                            "note": "no domains configured under"
                                    " amass.domains"})
        return jsonify({"started": True, "domains": domains})
    except Exception as exc:
        return jsonify({"started": False, "error": str(exc)[:200]})


@app.route("/playbook/<slug>")
def playbook(slug):
    """Fix-it guides, one per exposure type and detection kind.

    Full step-by-step guides live in netmon/playbooks.py (content) with
    titles/blurbs in netmon/attacksurface.py PLAYBOOK_SLUGS. Malformed
    slugs 404; well-formed but unknown slugs keep the friendly "coming
    soon" placeholder so nothing ever 404s on valid grammar.
    """
    import html as _html
    from . import attacksurface as asm
    from . import playbooks as pbm
    if not asm.valid_playbook_slug(slug):
        return "Not found", 404
    info = asm.PLAYBOOK_SLUGS.get(slug, {})
    title = info.get("title") or "Fix-it guide"
    blurb = info.get("blurb") or ""
    nav = ('<nav class="top"><a class="brand" href="/">netmon</a>'
           '<a class="nl" href="/#surface">Attack surface</a>'
           '<a class="nl" href="/#cases">Cases</a></nav>')
    head = ("<html><head><title>" + _html.escape(title)
            + " -- netmon playbook</title>"
            + '<meta name="viewport" content="width=device-width,'
            ' initial-scale=1">'
            + "<style>" + STYLE + "</style></head><body>" + nav
            + "<h1>" + _html.escape(title) + "</h1>"
            + ("<p>" + _html.escape(blurb) + "</p>" if blurb else ""))
    guide = pbm.get_guide(slug)
    if guide is None:
        # Well-formed but no guide written yet: the friendly placeholder.
        return (head
                + "<p>Here is the deal: the step-by-step guide for this one"
                + " is still being written -- it lands with the next"
                + " update.</p>"
                + "<p>What you can do right now:</p>"
                + "<ul><li>Read the exposure above it on the"
                + ' <a href="/#surface">Attack surface</a> page -- it says'
                + " what we found and why it matters.</li>"
                + "<li>If something is reachable from the internet and"
                + " should not be, your router's port-forwarding and UPnP"
                + " settings are the first place to look.</li>"
                + "<li>When in doubt, unplug the device until you have had"
                + " a proper look -- you cannot be hacked through a cable"
                + " that is not plugged in.</li></ul>"
                + '<p><a href="/#surface">&larr; Back to Attack surface</a>'
                + "</p></body></html>")
    # Full guide: what we found / what to do / when to escalate.
    parts = [head]
    parts.append("<h2>Here's what we found</h2>")
    for para in guide["found"]:
        parts.append("<p>" + _html.escape(para) + "</p>")
    parts.append("<h2>Here's what to do</h2><ol>")
    for step, detail in guide["do"]:
        parts.append("<li><b>" + _html.escape(step) + "</b>"
                     + ("<br>" + _html.escape(detail) if detail else "")
                     + "</li>")
    parts.append("</ol>")
    parts.append("<h2>When to escalate</h2>")
    parts.append("<p>" + _html.escape(guide["escalate"]) + "</p>")
    parts.append(
        '<p>To escalate: open the <a href="/#cases">Cases</a> page, find'
        ' the case for this, and hit <b>Escalate to admin</b>. It packages'
        ' the whole timeline, what was found, and what you already tried,'
        ' and emails it to your administrator. If the button says no admin'
        ' email is set, add <code>response.admin_email</code> to'
        ' config.yaml first.</p>')
    parts.append('<p><a href="/#surface">&larr; Back to Attack surface</a>'
                 ' | <a href="/#cases">Cases</a></p>')
    parts.append("</body></html>")
    return "".join(parts)


@app.route("/api/top_talkers")
def api_top_talkers():
    """Per-device up/down over the last hour, attributed by MAC."""
    now = time.time()
    ip2mac = dbm.ip_to_mac_map()
    mac2ips = {}
    for ip, mac in ip2mac.items():
        mac2ips.setdefault(mac, []).append(ip)
    names = dbm.device_name_map()
    up, down = {}, {}
    for src, dst, nbytes in dbm.query(
            "SELECT src_ip, dst_ip, SUM(bytes) FROM flows WHERE ts > ?"
            " GROUP BY src_ip, dst_ip", (now - 3600,)):
        m1 = ip2mac.get(src)
        m2 = ip2mac.get(dst)
        if m1:
            up[m1] = up.get(m1, 0) + (nbytes or 0)
        if m2:
            down[m2] = down.get(m2, 0) + (nbytes or 0)
    out = []
    for mac in set(up) | set(down):
        u, d = up.get(mac, 0), down.get(mac, 0)
        ips = mac2ips.get(mac, [])
        out.append({
            "mac": mac, "name": names.get(mac, ""),
            "ip": ips[0] if ips else "",
            "up_mb": round(u / 1e6, 2), "down_mb": round(d / 1e6, 2),
            "total_mb": round((u + d) / 1e6, 2),
        })
    out.sort(key=lambda t: t["total_mb"], reverse=True)
    return jsonify({"talkers": out[:25], "window_min": 60})


@app.route("/api/scan")
def api_scan():
    """Self vulnerability scan status + current open findings.

    Covers the built-in TCP connect scan AND the Nuclei-powered deeper
    scan: one status line per scanner, one findings list each.
    """
    from . import nuclei as nucleim
    running = dbm.get_meta("vuln_scan_running") == "1"
    lr = dbm.latest_scan_run()
    findings = []
    if lr:
        names = dbm.device_name_map()
        ip2mac = dbm.ip_to_mac_map()
        for f in dbm.list_scan_findings(status="open"):
            findings.append({
                "ip": f["ip"],
                "name": names.get(f["mac"] or ip2mac.get(f["ip"], ""), ""),
                "port": f["port"], "service": f["service"],
                "risk": f["risk"], "what_it_means": f["what_it_means"],
                "source": f["source"],
            })
    return jsonify({
        "running": running,
        "last_run": ({
            "when": _fmt_ts(lr["ts"]),
            "duration_s": round(lr["duration_s"] or 0, 1),
            "devices_scanned": lr["devices_scanned"],
            "findings": lr["findings"], "note": lr["note"],
        } if lr else None),
        "findings": findings,
        "nuclei": nucleim.nuclei_status(),
    })


@app.route("/api/scan/run", methods=["POST"])
@_owner_required
def api_scan_run():
    """Start an on-demand self scan in the background."""
    from . import scan as scanm
    if scanm.scan_already_running():
        return jsonify({"started": False,
                        "error": "a scan is already running"})
    scanm.start_scan_async(note="manual")
    return jsonify({"started": True})


@app.route("/api/nuclei/run", methods=["POST"])
@_owner_required
def api_nuclei_run():
    """Start an on-demand Nuclei scan in the background.

    Targets are ALWAYS the LAN asset inventory -- this endpoint takes
    no parameters and there is no way to supply a target through it.
    """
    from . import nuclei as nucleim
    ok, note = nucleim.check_binary()
    if not ok:
        return jsonify({"started": False, "error": note})
    if nucleim._nuclei_already_running():
        return jsonify({"started": False,
                        "error": "a scan is already running"})
    nucleim.start_nuclei_async()
    return jsonify({"started": True})


@app.route("/api/host_events")
def api_host_events():
    """Recent Windows host events + ingestion status."""
    from . import ingest as ingm
    events = []
    for e in dbm.host_events_since(time.time() - 7 * 86400, limit=50):
        try:
            summary = (json.loads(e["detail"] or "{}")).get("summary", "")
        except Exception:
            summary = ""
        events.append({
            "when": _fmt_ts(e["ts"]), "source": e["source"],
            "event_id": e["event_id"], "computer": e["computer"],
            "summary": summary, "matched_alert": e["matched_alert"],
        })
    info = {"enabled": bool(ingm.watch_dir())}
    if info["enabled"]:
        last = dbm.get_meta("ingest_last_run_ts")
        try:
            last_txt = _fmt_ts(float(last)) if last else ""
        except (TypeError, ValueError):
            last_txt = ""
        info.update({
            "dir": ingm.watch_dir(),
            "last_run": last_txt,
            "events_stored": dbm.query(
                "SELECT COUNT(*) FROM host_events")[0][0],
        })
    return jsonify({"ingest": info, "events": events})


@app.route("/api/pipeline_health")
def api_pipeline_health():
    """Per-stage pipeline watermarks for the sensor-health view.

    [{stage, label, last_ts, age_s, state, note}] where state is
    ok | stale | unknown. "Haven't heard from the sensor" groundwork:
    a stage silent too long shows stale here (and raises one self-alert
    from the monitor loop).
    """
    try:
        from . import pipeline as pipelinem
        stages = pipelinem.health_snapshot(
            capture_expected=pipelinem.get_capture_expected())
        return jsonify({"ok": True, "stages": stages})
    except Exception as exc:
        return jsonify({"ok": False,
                        "error": str(exc)[:120]}), 500


@app.route("/api/selfcheck")
def api_selfcheck():
    """Sensor-box self-health: last run + per-check status.

    Also carries the software-inventory/CVE check (swaudit) -- it audits
    this same box, so it lives in the same section of the dashboard.
    """
    from . import selfcheck as selfm
    from . import swaudit as swam
    summary = selfm.status_summary()
    results = []
    try:
        raw = dbm.get_meta("selfcheck_last_results")
        data = json.loads(raw) if raw else {}
        for name, r in data.items():
            results.append({
                "name": name, "status": r.get("status", ""),
                "detail": r.get("detail", "")})
    except Exception:
        pass
    return jsonify({"summary": summary, "checks": results,
                    "swaudit": swam.swaudit_status()})


@app.route("/api/topology")
def api_topology():
    """Visual network map data: gateway, nodes, edges (Phase 3.5)."""
    from . import topology as topom
    try:
        return jsonify(topom.build_topology())
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200],
                        "gateway": None, "nodes": [], "edges": [],
                        "types": []})


@app.route("/api/device_type", methods=["POST"])
@_owner_required
def api_device_type():
    """Pin (or clear) a device's type by MAC -- the map's correction loop.

    Body: {mac, dtype}. dtype must be a known type key; "" clears the
    override back to auto-detection.
    """
    from . import topology as topom
    data = request.get_json(silent=True) or {}
    mac = (data.get("mac") or "").strip().lower()
    dtype = (data.get("dtype") or "").strip().lower()
    if not re.match(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$", mac):
        return jsonify({"ok": False, "error": "mac is required"}), 400
    if dtype and not topom.valid_dtype(dtype):
        return jsonify({"ok": False,
                        "error": "unknown device type: %s" % dtype[:16]}), 400
    try:
        dbm.set_device_type(mac, dtype)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "dtype": dtype or "auto"})


# --- threat intel ("rap sheets", phase 3.5) ---------------------------------
# Per-IP and per-domain intel pages, feed status, and on-demand feed
# refresh. All input is validated (400 on junk); every dynamic value is
# esc()-escaped by the JS that renders it.

_MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# Alert kinds -> plain behavior tags for the intel page. host_event only
# counts as brute-force when its detail names a 4625 (failed logon).
_BEHAVIOR_TAGS = {
    "port_scan": "scanning",
    "beaconing": "botnet",
    "phishing_domain": "phishing",
    "malicious_ip": "malware",
    "defender_detection": "malware",
    "host_compromise": "botnet",
}


def _ip_mentioned(detail, ip):
    """True if `ip` appears in detail as a whole address (not as a prefix
    of a longer address -- the 192.168.1.1 vs 192.168.1.10 class of bug)."""
    return re.search(r"(?<![0-9.])" + re.escape(ip) + r"(?![0-9.])",
                     detail or "") is not None


def _behavior_tags_for_ip(ip):
    """Plain behavior tags from alerts that name this IP."""
    tags = set()
    try:
        rows = dbm.query(
            "SELECT kind, detail FROM alerts WHERE detail LIKE ?",
            (f"%{ip}%",))
    except Exception:
        return []
    for kind, detail in rows:
        if not _ip_mentioned(detail, ip):
            continue
        tag = _BEHAVIOR_TAGS.get(kind)
        if kind == "host_event":
            tag = "brute-force" if "4625" in (detail or "") else None
        if tag:
            tags.add(tag)
    return sorted(tags)


def _alerts_mentioning_ip(ip, limit=20):
    """Recent alerts whose detail names this IP, newest first."""
    try:
        rows = dbm.query(
            "SELECT id, ts, kind, severity, title, detail FROM alerts"
            " WHERE detail LIKE ? ORDER BY ts DESC LIMIT ?",
            (f"%{ip}%", limit * 3))
    except Exception:
        return []
    out = []
    for aid, ts, kind, sev, title, detail in rows:
        if _ip_mentioned(detail, ip):
            out.append({"id": aid, "ts": _fmt_ts(ts), "kind": kind,
                        "severity": sev, "title": title})
        if len(out) >= limit:
            break
    return out


def _alerts_mentioning_domain(domain, limit=20):
    """Recent alerts whose detail names this domain, newest first."""
    try:
        rows = dbm.query(
            "SELECT id, ts, kind, severity, title, detail FROM alerts"
            " WHERE detail LIKE ? ORDER BY ts DESC LIMIT ?",
            (f"%{domain}%", limit * 3))
    except Exception:
        return []
    out = []
    for aid, ts, kind, sev, title, detail in rows:
        if domain.lower() in (detail or "").lower():
            out.append({"id": aid, "ts": _fmt_ts(ts), "kind": kind,
                        "severity": sev, "title": title})
        if len(out) >= limit:
            break
    return out


@app.route("/api/intel/status")
def api_intel_status():
    """Feed health for the dashboard: label, entries, last update.

    Pipeline robustness (batch 14): when the last refresh failed, the
    dashboard says so plainly ("showing the saved lists") instead of
    silently serving stale data -- see dbm.ti_feed_health().
    """
    from . import threatintel as tim
    try:
        feeds = dbm.ti_feed_status()
        total = dbm.ti_entry_count()
        feed_health = dbm.ti_feed_health()
    except Exception:
        feeds, total = [], 0
        feed_health = {"failed_recently": False, "last_attempt_ts": None,
                       "last_success_ts": None}
    for f in feeds:
        f["last_updated"] = (_fmt_ts(f["last_updated"])
                             if f.get("last_updated") else "never")
    return jsonify({"feeds": feeds, "total_entries": total,
                    "abuseipdb": tim.abuseipdb_configured(),
                    "feed_health": feed_health})


@app.route("/api/intel/refresh", methods=["POST"])
@_owner_required
def api_intel_refresh():
    """Refresh the community feeds on demand. Best-effort per feed."""
    from . import threatintel as tim
    try:
        results = tim.refresh_feeds()
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)[:200]}), 500
    return jsonify({"ok": True, "results": results})


@app.route("/api/intel/ip/<ip>")
def api_intel_ip(ip):
    """Per-IP rap sheet: blocklist status/reason, abuse score, behavior
    tags, country/city, ISP + ASN, associated domains, first/last seen
    (feed + our network), reverse DNS. Only fields with data are sent."""
    import ipaddress as _ipm
    from . import threatintel as tim
    ip = (ip or "").strip()
    try:
        _ipm.ip_address(ip)
    except ValueError:
        return jsonify({"ok": False, "error": "not a valid IP"}), 400
    now = time.time()
    try:
        intel = tim.lookup_ip(ip)
    except Exception:
        intel = {"listed": [], "abuseipdb": None}
    listed = [{
        "feed": h.get("feed", ""), "detail": h.get("detail", ""),
        "first_seen": _fmt_ts(h["first_seen"]) if h.get("first_seen")
        else "",
        "last_seen": _fmt_ts(h["last_seen"]) if h.get("last_seen") else "",
    } for h in intel.get("listed") or []]
    try:
        rdns = tim.reverse_dns(ip)
    except Exception:
        rdns = ""
    try:
        seen = dbm.query(
            "SELECT MIN(ts), MAX(ts), COUNT(*) FROM flows"
            " WHERE src_ip=? OR dst_ip=?", (ip, ip))[0]
        traf = dbm.query(
            "SELECT COALESCE(SUM(CASE WHEN src_ip=? THEN bytes END),0),"
            " COALESCE(SUM(CASE WHEN dst_ip=? THEN bytes END),0)"
            " FROM flows WHERE ts > ? AND (src_ip=? OR dst_ip=?)",
            (ip, ip, now - 86400, ip, ip))[0]
    except Exception:
        seen, traf = (None, None, 0), (0, 0)
    out = {
        "ok": True, "ip": ip,
        "listed": listed,
        "tags": _behavior_tags_for_ip(ip),
        "alerts": _alerts_mentioning_ip(ip),
    }
    if rdns:
        out["reverse_dns"] = rdns
    if seen and seen[0]:
        out["first_seen_here"] = _fmt_ts(seen[0])
        out["last_seen_here"] = _fmt_ts(seen[1]) if seen[1] else ""
        out["flows_seen"] = seen[2] or 0
    if (traf[0] or 0) or (traf[1] or 0):
        out["up_mb_24h"] = round((traf[0] or 0) / 1e6, 2)
        out["down_mb_24h"] = round((traf[1] or 0) / 1e6, 2)
    abuse = intel.get("abuseipdb") or {}
    for key in ("score", "country", "isp", "usage", "asn", "domain",
                "reports", "last_reported"):
        if abuse.get(key) not in (None, ""):
            out["abuse_" + key] = abuse[key]
    return jsonify(out)


@app.route("/api/intel/domain/<domain>")
def api_intel_domain(domain):
    """Per-domain rap sheet: feed listings, our lookup history, alerts."""
    from . import threatintel as tim
    domain = tim.normalize_domain(domain or "")
    if not tim.is_plausible_domain(domain):
        return jsonify({"ok": False, "error": "not a valid domain"}), 400
    try:
        hits = tim.lookup_domain(domain)
    except Exception:
        hits = []
    listed = [{
        "feed": h.get("feed", ""), "detail": h.get("detail", ""),
        "matched": h.get("matched", ""),
        "first_seen": _fmt_ts(h["first_seen"]) if h.get("first_seen")
        else "",
        "last_seen": _fmt_ts(h["last_seen"]) if h.get("last_seen") else "",
    } for h in hits]
    out = {"ok": True, "domain": domain, "listed": listed,
           "alerts": _alerts_mentioning_domain(domain)}
    try:
        row = dbm.query(
            "SELECT MIN(ts), MAX(ts), COUNT(*) FROM dns_queries"
            " WHERE name=?", (domain,))[0]
        if row and row[0]:
            out["first_lookup"] = _fmt_ts(row[0])
            out["last_lookup"] = _fmt_ts(row[1]) if row[1] else ""
            out["lookups_total"] = row[2] or 0
    except Exception:
        pass
    return jsonify(out)


@app.route("/api/device/<mac>")
def api_device(mac):
    """Per-LAN-device detail page: first/last seen, bytes sent/received,
    ports contacted, full alert history. (Complements the asset inventory
    at /api/assets and the map's click-for-details.)"""
    mac = (mac or "").strip().lower()
    if not _MAC_RE.match(mac):
        return jsonify({"ok": False, "error": "not a valid MAC"}), 400
    now = time.time()
    try:
        seen = dbm.query(
            "SELECT MIN(ts), MAX(ts) FROM arp_observations WHERE mac=?",
            (mac,))[0]
        ips = [r[0] for r in dbm.query(
            "SELECT DISTINCT ip FROM arp_observations WHERE mac=?"
            " AND ip IS NOT NULL AND ip != ''", (mac,)) if r[0]]
    except Exception:
        seen, ips = (None, None), []
    out = {"ok": True, "mac": mac, "name": "",
           "first_seen": _fmt_ts(seen[0]) if seen and seen[0] else "",
           "last_seen": _fmt_ts(seen[1]) if seen and seen[1] else "",
           "ips": ips, "ports": [], "alerts": []}
    try:
        out["name"] = dbm.device_name_map().get(mac, "")
        asset = next((a for a in dbm.get_assets() if a.get("mac") == mac),
                     None)
        if asset:
            for key in ("hostname", "vendor", "os_guess"):
                if asset.get(key):
                    out[key] = asset[key]
    except Exception:
        pass
    if ips:
        ph = ",".join("?" for _ in ips)
        try:
            traf = dbm.query(
                f"SELECT COALESCE(SUM(CASE WHEN src_ip IN ({ph})"
                f" THEN bytes END),0),"
                f" COALESCE(SUM(CASE WHEN dst_ip IN ({ph})"
                f" THEN bytes END),0)"
                f" FROM flows WHERE ts > ? AND (src_ip IN ({ph})"
                f" OR dst_ip IN ({ph}))",
                (*ips, *ips, now - 86400, *ips, *ips))[0]
            out["up_mb_24h"] = round((traf[0] or 0) / 1e6, 2)
            out["down_mb_24h"] = round((traf[1] or 0) / 1e6, 2)
            rows = dbm.query(
                f"SELECT dst_port, proto, COUNT(*),"
                f" COALESCE(SUM(bytes),0) FROM flows"
                f" WHERE ts > ? AND direction='outbound'"
                f" AND src_ip IN ({ph})"
                f" GROUP BY dst_port, proto ORDER BY SUM(bytes) DESC"
                f" LIMIT 15",
                (now - 86400, *ips))
            out["ports"] = [{"port": p, "proto": pr or "",
                             "flows": c or 0,
                             "mb": round((b or 0) / 1e6, 2)}
                            for p, pr, c, b in rows]
        except Exception:
            pass
        # Full alert history: alerts naming the MAC or any of its IPs.
        try:
            like_terms = [mac] + ips
            conds = " OR ".join(["detail LIKE ?"] * len(like_terms))
            rows = dbm.query(
                f"SELECT id, ts, kind, severity, title, detail FROM alerts"
                f" WHERE {conds} ORDER BY ts DESC LIMIT 150",
                tuple(f"%{t}%" for t in like_terms))
            seen_ids = set()
            for aid, ts, kind, sev, title, detail in rows:
                if aid in seen_ids:
                    continue
                dl = (detail or "").lower()
                if mac not in dl and not any(
                        _ip_mentioned(detail, ip) for ip in ips):
                    continue
                seen_ids.add(aid)
                out["alerts"].append({"id": aid, "ts": _fmt_ts(ts),
                                     "kind": kind, "severity": sev,
                                     "title": title})
                if len(out["alerts"]) >= 50:
                    break
        except Exception:
            pass
    return jsonify(out)


# --- quiet hours ------------------------------------------------------------
# Email silencing windows. The dashboard still records everything; only
# the emails go quiet.

_VALID_DAYS = set(range(7))


def _clean_windows(windows):
    """Validate/normalize quiet-hour windows; raises ValueError."""
    import re
    if not isinstance(windows, list):
        raise ValueError("windows must be a list")
    clean = []
    for w in windows:
        if not isinstance(w, dict):
            raise ValueError("each window must be an object")
        start = (w.get("start") or "").strip()
        end = (w.get("end") or "").strip()
        if not re.fullmatch(r"\d{2}:\d{2}", start) or \
                not re.fullmatch(r"\d{2}:\d{2}", end):
            raise ValueError("start/end must look like HH:MM")
        days = w.get("days")
        if days is None:
            days = list(range(7))
        try:
            days = [int(d) for d in days]
        except (TypeError, ValueError):
            raise ValueError("days must be numbers 0-6 (Mon-Sun)")
        if any(d not in _VALID_DAYS for d in days):
            raise ValueError("days must be 0-6 (Mon-Sun)")
        kinds = w.get("kinds") or ["all"]
        if isinstance(kinds, str):
            kinds = [kinds]
        kinds = [str(k).strip() for k in kinds if str(k).strip()]
        if not kinds:
            kinds = ["all"]
        clean.append({"days": sorted(set(days)), "start": start,
                      "end": end, "kinds": kinds})
    return clean


@app.route("/api/settings/quiet_hours")
def api_quiet_hours_get():
    return jsonify({"windows": dbm.get_quiet_hours()})


@app.route("/api/settings/quiet_hours", methods=["POST"])
@_owner_required
def api_quiet_hours_set():
    data = request.get_json(silent=True) or {}
    try:
        windows = _clean_windows(data.get("windows", []))
    except ValueError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    dbm.set_quiet_hours(windows)
    return jsonify({"ok": True, "windows": windows})


# --- rule health + allowlist -------------------------------------------------
# How often each detection rule earns its keep, judged by your own
# Ack/Dismiss history -- plus the allowlist that silences patterns
# you've decided are fine.

@app.route("/api/rule_health")
def api_rule_health():
    now = time.time()
    rows = dbm.query(
        "SELECT kind, status, COUNT(*) FROM alerts WHERE ts > ?"
        " GROUP BY kind, status", (now - 30 * 86400,))
    by_kind = {}
    for kind, status, n in rows:
        d = by_kind.setdefault(
            kind or "unknown",
            {"kind": kind or "unknown", "total": 0,
             "acknowledged": 0, "dismissed": 0})
        d["total"] += n
        if status == "acknowledged":
            d["acknowledged"] += n
        elif status == "dismissed":
            d["dismissed"] += n
    rules = []
    suggestions = []
    for kind in sorted(by_kind):
        d = by_kind[kind]
        judged = d["acknowledged"] + d["dismissed"]
        d["precision"] = (round(d["acknowledged"] / judged, 2)
                          if judged else None)
        rules.append(d)
        if d["dismissed"] >= 5 and d["precision"] is not None \
                and d["precision"] < 0.4:
            suggestions.append({
                "kind": kind,
                "text": (f"You've dismissed '{kind}' {d['dismissed']} times"
                         f" in the last 30 days. Add a pattern to the"
                         f" allowlist below so it stops bothering you?"),
            })
    return jsonify({"rules": rules, "suggestions": suggestions})


@app.route("/api/allowlist")
def api_allowlist_get():
    return jsonify({"entries": dbm.list_allowlist()})


@app.route("/api/allowlist", methods=["POST"])
@_owner_required
def api_allowlist_add():
    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "").strip()
    pattern = (data.get("pattern") or "").strip()
    note = (data.get("note") or "").strip()
    if not kind or not pattern:
        return jsonify({"ok": False,
                        "error": "kind and pattern are required"}), 400
    try:
        eid = dbm.add_allowlist(kind, pattern, note)
    except Exception as exc:
        return jsonify({"ok": False, "error": str(exc)}), 500
    return jsonify({"ok": True, "id": eid})


@app.route("/api/allowlist/<int:eid>", methods=["DELETE"])
@_owner_required
def api_allowlist_del(eid):
    dbm.remove_allowlist(eid)
    return jsonify({"ok": True})


# --- learning from dismissals ------------------------------------------------
# Pattern-level suggestions: dismissing alerts teaches the monitor; at
# threshold a pending suggestion appears here, and only the human's Apply
# click writes the allowlist row. Distinct from /api/rule_health's
# rule-level hints ("this whole rule cries wolf").


@app.route("/api/learn/suggestions")
def api_learn_suggestions():
    return jsonify({"suggestions": dbm.list_suggestions()})


@app.route("/api/learn/suggestions/<int:sid>/apply", methods=["POST"])
@_owner_required
def api_learn_apply(sid):
    ok = dbm.decide_suggestion(sid, "applied")
    return jsonify({"ok": ok})


@app.route("/api/learn/suggestions/<int:sid>/ignore", methods=["POST"])
@_owner_required
def api_learn_ignore(sid):
    ok = dbm.decide_suggestion(sid, "ignored")
    return jsonify({"ok": ok})


@app.route("/api/digest/send", methods=["POST"])
@_owner_required
def api_digest_send():
    from . import notify as notifm
    sent = notifm.send_digest()
    return jsonify({"ok": True, "sent": bool(sent)})


# --- Reports: score card, morning briefing, compliance, rewind ---------------
# Phase 3.5 "prove it". The score is a fixed deterministic formula
# (reporting.compute_score) -- never the LLM. Filenames are built only
# from validated ints/whitelisted periods, so exports can't traverse
# paths.


@app.route("/api/score")
def api_score():
    from . import reporting as repm
    data = repm.compute_score()
    return jsonify({
        "score": data["score"],
        "neutral": data["neutral"],
        "why": repm.explain_score(data),
        "factors": data["factors"],
        "history": repm.score_history(days=14),
    })


@app.route("/api/briefing/preview")
def api_briefing_preview():
    """Dry run: show the briefing email WITHOUT sending it."""
    from . import reporting as repm
    brief = repm.build_briefing()
    return jsonify({"subject": brief["subject"], "body": brief["body"]})


@app.route("/api/briefing/send", methods=["POST"])
@_owner_required
def api_briefing_send():
    """Send the morning briefing now (synchronous, reports the outcome)."""
    from . import reporting as repm
    ok, reason = repm.send_briefing()
    if ok:
        return jsonify({"ok": True})
    return jsonify({"ok": False,
                    "error": reason or "could not send the briefing"})


# --- data retention (Phase 3.5 batch 16) --------------------------------------
# Rolling windows per data type (config.yaml: retention.*), pruned daily by
# the monitor loop in bounded batches. This endpoint shows the policy and
# the last prune run; owners can trigger a prune on demand.

@app.route("/api/retention")
def api_retention():
    """Retention policy + last prune run. Read-only (viewers welcome)."""
    from . import retention as retm
    last_ts, last_counts = retm.last_prune()
    return jsonify({
        "policy": retm.policy(),
        "policy_note": ("Alerts attached to open or escalated cases are"
                        " never pruned; the forensic rewind buffer has its"
                        " own bounds."),
        "last_run": _fmt_ts(last_ts) if last_ts else None,
        "last_counts": last_counts,
    })


@app.route("/api/retention/prune", methods=["POST"])
@_owner_required
def api_retention_prune():
    """Run a prune pass now (owner only)."""
    from . import retention as retm
    counts = retm.prune_once()
    return jsonify({"ok": True, "pruned": counts})


def _report_period():
    period = (request.args.get("period") or "weekly").strip().lower()
    if period not in ("weekly", "monthly"):
        return None
    return period


def _download_response(payload, filename, mimetype):
    # The filename is built by us from validated values only -- never
    # from raw user input -- so this can't traverse directories.
    safe = "".join(c for c in filename
                   if c.isalnum() or c in ("-", "_", "."))
    return Response(
        payload, mimetype=mimetype,
        headers={"Content-Disposition":
                 f'attachment; filename="{safe or "report"}"'})


@app.route("/reports/compliance.html")
def reports_compliance_html():
    from . import reporting as repm
    period = _report_period()
    if period is None:
        return jsonify({"ok": False, "error": "bad period"}), 400
    data = repm.compliance_report_data(period=period)
    stamp = time.strftime("%Y-%m-%d")
    return _download_response(
        repm.compliance_html(data).encode("utf-8"),
        f"brutedash-compliance-{period}-{stamp}.html", "text/html")


@app.route("/reports/compliance.csv")
def reports_compliance_csv():
    from . import reporting as repm
    period = _report_period()
    if period is None:
        return jsonify({"ok": False, "error": "bad period"}), 400
    data = repm.compliance_report_data(period=period)
    stamp = time.strftime("%Y-%m-%d")
    return _download_response(
        repm.compliance_csv(data).encode("utf-8"),
        f"brutedash-compliance-{period}-{stamp}.csv", "text/csv")


@app.route("/reports/weekly.pdf")
def reports_weekly_pdf():
    from . import reporting as repm
    blob = repm.weekly_pdf_bytes()
    if not blob:
        return jsonify({"ok": False,
                        "error": "could not build the PDF"}), 500
    stamp = time.strftime("%Y-%m-%d")
    return _download_response(
        blob, f"brutedash-weekly-{stamp}.pdf", "application/pdf")


@app.route("/reports/incident/<int:iid>.pdf")
def reports_incident_pdf(iid):
    from . import reporting as repm
    blob = repm.incident_pdf_bytes(iid)
    if not blob:
        return jsonify({"ok": False,
                        "error": "case not found"}), 404
    return _download_response(
        blob, f"incident-{iid}-brief.pdf", "application/pdf")


@app.route("/api/rewind/status")
def api_rewind_status():
    from . import rewind as rwm
    return jsonify(rwm.status())


@app.route("/api/rewind/export")
def api_rewind_export():
    """Download a .pcap slice of the forensic buffer.

    One of: ?incident_id=N (the case's window), ?hours=H (the last H
    hours, 0 < H <= 24), or ?start=<epoch>&end=<epoch> (at most 24h).
    The filename is built from validated numbers only -- no path
    traversal possible."""
    from . import rewind as rwm
    now = time.time()
    fname = None
    window = None
    iid_raw = request.args.get("incident_id")
    hours_raw = request.args.get("hours")
    start_raw = request.args.get("start")
    end_raw = request.args.get("end")
    try:
        if iid_raw is not None:
            iid = int(iid_raw)
            if iid <= 0:
                raise ValueError
            window = rwm.incident_window(iid)
            if window is None:
                return jsonify({"ok": False, "error":
                                "no packets for this case's window"}), 404
            fname = f"incident-{iid}-window.pcap"
        elif hours_raw is not None:
            hours = float(hours_raw)
            if not (0 < hours <= 24):
                raise ValueError
            window = (now - hours * 3600, now)
            fname = "rewind-last-hours.pcap"
        elif start_raw is not None and end_raw is not None:
            start_ts, end_ts = float(start_raw), float(end_raw)
            if not (0 < end_ts - start_ts <= 86400):
                raise ValueError
            window = (start_ts, end_ts)
            fname = "rewind-window.pcap"
        else:
            return jsonify({"ok": False, "error":
                            "pick a case or a time window"}), 400
    except (TypeError, ValueError):
        return jsonify({"ok": False, "error": "bad time window"}), 400
    blob, count = rwm.export_window(*window)
    resp = _download_response(blob, fname, "application/vnd.tcpdump.pcap")
    resp.headers["X-Packets"] = str(count)
    return resp


# --- AI: ask-your-network + AI triage verdict -------------------------------
# A teammate builds netmon/ai_assist.py with answer_question(question) and
# triage_verdict(alert), each returning None when no API key is set. Guard
# everything so the dashboard works with no AI configured.

_AI_UNAVAILABLE = {"unavailable": True,
                   "message": "AI answers are off -- set OPENAI_API_KEY "
                              "and ai.provider in config.yaml to enable."}


def _ai_assist():
    try:
        from . import ai_assist
        return ai_assist
    except Exception:
        return None


ASK_HTML = """<html><head><title>netmon -- ask your network</title>
<style>""" + STYLE + """</style></head><body>
<h1>Ask your network</h1>
<p class="note">Ask a plain-English question about what's happening on your
network and get an AI answer based on what the monitor has seen.</p>
<textarea id="q" rows="3" style="width:100%" placeholder="e.g. Why is my computer so busy right now?"></textarea><br><br>
<button onclick="ask()">Ask</button>
<div id="ans" style="margin-top:1em"></div>
<p><a href="/">Back to live dashboard</a></p>
<script>
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
async function ask(){
  const q = document.getElementById("q").value;
  document.getElementById("ans").innerHTML = '<p class="note">Thinking...</p>';
  const r = await fetch("/api/ask", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({question: q})});
  const d = await r.json();
  document.getElementById("ans").innerHTML = d.unavailable
    ? '<p class="note">' + esc(d.message) + '</p>'
    : '<pre>' + esc(typeof d.answer === "string" ? d.answer : JSON.stringify(d.answer, null, 2)) + '</pre>';
}
</script></body></html>"""


@app.route("/ask")
def ask_page():
    if _auth_enabled() and _role() != "owner":
        return render_template_string(
            _OWNER_ONLY_HTML,
            message=("Ask-your-network spends the AI budget and can run"
                     " scans -- owner sign-in required. Viewers can look,"
                     " not touch.")), 403
    return render_template_string(ASK_HTML)


@app.route("/api/ask", methods=["POST"])
@_owner_required
def api_ask():
    if request.is_json:
        q = (request.get_json(silent=True) or {}).get("question", "")
    else:
        q = request.form.get("question", "")
    q = (q or "").strip()
    if not q:
        return jsonify({"ok": False, "error": "ask a question first"}), 400
    mod = _ai_assist()
    try:
        answer = (mod.answer_question(q)
                  if mod is not None and hasattr(mod, "answer_question")
                  else None)
    except Exception:
        answer = None
    if not answer:
        return jsonify(_AI_UNAVAILABLE)
    return jsonify({"answer": answer})


@app.route("/api/triage/<int:aid>", methods=["POST"])
@_owner_required
def api_triage(aid):
    rows = dbm.query(
        "SELECT severity, title, detail, meaning, is_normal, what_to_do, ts"
        " FROM alerts WHERE id = ?", (aid,))
    if not rows:
        return jsonify({"ok": False, "error": "alert not found"}), 404
    sev, t, d, m, n, w, ts = rows[0]
    alert = {"id": aid, "severity": sev, "title": t, "detail": d,
             "meaning": m, "is_normal": n, "what_to_do": w,
             "ts": _fmt_ts(ts)}
    mod = _ai_assist()
    try:
        verdict = (mod.triage_verdict(alert)
                   if mod is not None and hasattr(mod, "triage_verdict")
                   else None)
    except Exception:
        verdict = None
    if not verdict:
        return jsonify(_AI_UNAVAILABLE)
    return jsonify({"verdict": verdict.get("verdict"),
                    "reasoning": verdict.get("reasoning")})


# watchdog handle is attached by run.py; dashboard-only mode shows "unknown"
watchdog = None


def _loop_down_state():
    """Loop-down watchdog state for the banner: {"down": bool, "detail"}.

    State only -- firing the self-alert happens in _loop_watchdog_tick.
    Never raises.
    """
    try:
        from . import pipeline as pipelinem
        down, detail = pipelinem.check_loop_down()
        return {"down": bool(down), "detail": detail or ""}
    except Exception:
        return {"down": False, "detail": ""}


def _port_guide_html():
    from . import explainer as expl
    rows = "".join(
        f"<tr><td><b>{p}</b></td><td>{d}</td></tr>"
        for p, d in sorted(expl.PORT_GUIDE.items()))
    return (f"<table><tr><th>Port</th><th>What it means</th></tr>{rows}</table>"
            "<p class='note'>Anything not on this list is an 'uncommon"
            " channel' -- the monitor flags those for you automatically.</p>")


@app.route("/")
def index():
    role = _role() or "owner"  # no-password mode: everyone is the owner
    badge = ('<span class="badge warn" id="rolebadge">'
             "&#128065; View only</span>" if role == "viewer" else "")
    html = INDEX_HTML.replace("%%PORT_GUIDE%%", _port_guide_html())
    html = html.replace("%%ROLE_BADGE%%", badge)
    html = html.replace("%%BODY_CLASS%%", "viewonly" if role == "viewer"
                        else "")
    html = html.replace("%%ORION_ROLE%%", role)
    return render_template_string(html)


@app.route("/api/stats")
def api_stats():
    from . import explainer as expl
    now = time.time()
    one_min = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0)"
        " FROM flows WHERE ts > ?", (now - 60,))[0]
    mbps = one_min[0] / 60 / 1e6  # megabytes per second, plain words

    talkers = [
        {"src": s, "dst": d, "port": p, "proto": pr, "bytes": b,
         "port_words": expl._port_words(p)}
        for s, d, p, pr, b in dbm.query(
            "SELECT src_ip, dst_ip, dst_port, proto, SUM(bytes) FROM flows"
            " WHERE ts > ? GROUP BY src_ip, dst_ip, dst_port, proto"
            " ORDER BY SUM(bytes) DESC LIMIT 10", (now - 900,))
    ]
    alerts = [
        {"id": a["id"], "severity": a["severity"], "title": a["title"],
         "detail": a["detail"], "meaning": a["meaning"],
         "is_normal": a["is_normal"], "what_to_do": a["what_to_do"],
         "ts": a["ts"], "status": a["status"], "note": a["note"],
         "mitre_id": a.get("mitre_id"), "mitre_name": a.get("mitre_name"),
         "mitre_tactic": a.get("mitre_tactic"),
         "trace_id": a.get("trace_id") or ""}
        for a in _alerts(status_filter=request.args.get("status", "all"))
    ]
    last_flow_ts, stale = _flow_health()
    ongoing = [
        {"target": t, "since": _fmt_ts(s)}
        for _, t, s in dbm.ongoing_outages()
    ]
    outages = [
        {"target": t, "gap_s": g or 0, "when": _fmt_ts(s)}
        for t, s, _e, g in dbm.query(
            "SELECT target, start_ts, end_ts, gap_seconds FROM outages"
            " WHERE end_ts IS NOT NULL ORDER BY start_ts DESC LIMIT 10")
    ]
    # Productized uptime log: weekly "down N times, M total" summary plus
    # the full recent log with timestamps and durations.
    try:
        outage_week = dbm.outage_stats(7)
    except Exception:
        outage_week = None
    outage_log = [
        {"target": o["target"],
         "dur": _fmt_dur(o["gap_seconds"]) if o["gap_seconds"] else "ongoing",
         "start": _fmt_ts(o["start_ts"]),
         "end": _fmt_ts(o["end_ts"]) if o["end_ts"] else "now"}
        for o in dbm.list_outages(30)
    ]
    conn = {}
    if watchdog is not None:
        for label, st in watchdog.current().items():
            conn[label] = {"up": st["up"], "since": _fmt_ts(st["since"])}
    top = dbm.query(
        "SELECT dst_port, SUM(bytes) FROM flows WHERE ts > ?"
        " AND direction='outbound' GROUP BY dst_port"
        " ORDER BY SUM(bytes) DESC LIMIT 3", (now - 900,))
    n15 = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COUNT(*) FROM flows WHERE ts > ?",
        (now - 900,))[0]
    total_pkts = dbm.query("SELECT COALESCE(SUM(packets),0) FROM flows")[0][0]
    total_bytes = dbm.query("SELECT COALESCE(SUM(bytes),0) FROM flows")[0][0]
    try:
        device_names = dbm.ip_name_map()
    except Exception:
        device_names = {}
    whole_network = cfgm.whole_network_enabled()
    relay_active = relaym.relay_active()
    try:
        _cnt = dbm.query(
            "SELECT status, severity, COUNT(*) FROM alerts WHERE ts > ?"
            " GROUP BY status, severity", (now - 3600,))
        alert_counts = {}
        for _st, _sev, _n in _cnt:
            alert_counts.setdefault(_st or "new", {})[_sev or "Low"] = _n
    except Exception:
        alert_counts = {}
    return jsonify({
        "now": _fmt_ts(now),
        "whole_network": whole_network,
        "relay_active": relay_active,
        "throughput_mbps": mbps,
        "packets_1m": one_min[1],
        "packets_total": total_pkts or 0,
        "bytes_total": total_bytes or 0,
        "connectivity": conn,
        "summary": dbm.latest_summary(),
        "alerts": alerts,
        "alert_counts": alert_counts,
        "talkers": talkers,
        "normal_now": {
            "mb": round((n15[0] or 0) / 1e6, 1),
            "flows": n15[1] or 0,
            "top_words": "; ".join(
                f"port {p} ({expl._port_words(p)})" for p, _ in top),
        },
        "ongoing": ongoing,
        "outages": outages,
        "outage_week": outage_week,
        "outage_log": outage_log,
        "stale": stale,
        "last_flow_ts": last_flow_ts,
        "loop_down": _loop_down_state(),
        "auth_required": _auth_enabled(),
        "device_names": device_names,
    })


@app.route("/explain", methods=["POST"])
@_owner_required
def explain_now():
    from . import explainer as expl
    summary, origin = expl.summarize(save=True)
    return jsonify({"ok": True, "headline": summary["headline"],
                    "origin": origin})


@app.route("/pcap", methods=["GET", "POST"])
@_owner_required
def pcap():
    if request.method == "GET":
        return render_template_string(PCAP_HTML)
    f = request.files.get("pcap")
    if not f or not f.filename:
        return redirect("/pcap")
    from . import capture as capm
    from . import explainer as expl
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        f.save(tmp.name)
        path = tmp.name
    # B2: a diagnostic upload must never write production tables or send
    # real emails. Analyze against an isolated scratch DB with the notify
    # hook paused -- this thread only; the live monitor is unaffected.
    scratch = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    scratch.close()
    try:
        with dbm.isolated_db(scratch.name), dbm.notifications_paused():
            try:
                agg = capm.run_pcap(path)
            finally:
                os.unlink(path)
            # Anchor analysis windows at the newest packet, not wall-clock
            # time, so old captures analyze against their own timeline.
            anchor = agg.max_ts or time.time()
            from . import detect as detm
            detm.run_all(now=anchor)
            alerts = [
                {"severity": sev, "title": t, "detail": d, "meaning": m,
                 "is_normal": n, "what_to_do": w}
                for sev, t, d, m, n, w in dbm.query(
                    "SELECT severity, title, detail, meaning, is_normal,"
                    " what_to_do FROM alerts WHERE ts > ?"
                    " ORDER BY ts DESC LIMIT 20", (anchor - 86400,))
            ]
            summary, _origin = expl.summarize(save=False, now=anchor)
    finally:
        os.unlink(scratch.name)
    return render_template_string(PCAP_RESULT_HTML, filename=f.filename,
                                  packets=agg.packets_seen,
                                  summary=summary, alerts=alerts)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
