"""netmon/dashboard.py -- live Flask dashboard for the network monitor.

Pages:
  /        live dashboard (polls /api/stats every 5s)
  /pcap    upload a .pcap (e.g. from Wireshark) -> analyze -> AI explanation
  /explain POST -> regenerate the plain-English summary on demand

Run via netmon/run.py (starts capture + watchdog threads), or standalone
for viewing an existing database:  python -m netmon.dashboard
"""
import hmac
import os
import tempfile
import time

from flask import Flask, request, jsonify, render_template_string, redirect, \
    session

from . import db as dbm

app = Flask(__name__)
app.secret_key = os.environ.get("NETMON_SECRET_KEY", "") or os.urandom(24)


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

# Optional password gate for the dashboard. When NETMON_PASSWORD is set,
# every page except /login and /api/health requires a session login.
NETMON_PASSWORD = os.environ.get("NETMON_PASSWORD", "")
if not NETMON_PASSWORD:
    print("WARNING: dashboard has no password "
          "(set NETMON_PASSWORD to require a login).")


@app.before_request
def _password_gate():
    if not NETMON_PASSWORD:
        return None
    if request.path in ("/login", "/api/health"):
        return None
    if session.get("authed"):
        return None
    return redirect("/login")


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
input,textarea,select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;font-family:monospace;padding:.4em;border-radius:4px}
.banner-red{background:#3d1113;border:1px solid #f85149;color:#f85149;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
.banner-blue{background:#0d2137;border:1px solid #58a6ff;color:#58a6ff;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
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
"""

LOGIN_HTML = """<html><head><title>netmon -- sign in</title>
<style>""" + STYLE + """</style></head><body>
<h1>netmon sign in</h1>
<p class="note">This dashboard is password-protected. Enter the dashboard
password to continue.</p>
{% if error %}<p class="high">{{ error }}</p>{% endif %}
<form method="post">
<input type="password" name="password" autofocus autocomplete="current-password"><br><br>
<button type="submit">Sign in</button>
</form>
</body></html>"""


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "GET":
        return render_template_string(LOGIN_HTML, error=None)
    password = request.form.get("password", "")
    if NETMON_PASSWORD and hmac.compare_digest(password, NETMON_PASSWORD):
        session["authed"] = True
        return redirect("/")
    return render_template_string(
        LOGIN_HTML, error="Wrong password, try again.")


@app.route("/logout")
def logout():
    session.pop("authed", None)
    return redirect("/login" if NETMON_PASSWORD else "/")

INDEX_HTML = """<html><head><title>netmon -- your network, explained</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>""" + STYLE + """</style></head><body>
<nav class="top">
<a class="brand" href="/">netmon</a>
<span id="status-pill" class="pill ok">&#9679; LIVE</span>
<a class="nl" href="#overview">Overview</a>
<a class="nl" href="#alerts">Alerts <span id="nav-alert-badge"></span></a>
<a class="nl" href="#traffic">Traffic</a>
<a class="nl" href="#devices">Devices</a>
<a class="nl" href="#settings">Settings</a>
</nav>
<div id="stalebanner" class="banner-red" style="display:none"></div>
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
<p class="note">Triage queue &mdash; most urgent first. Show: <select id="alertstatusfilter" onchange="refresh()">
<option value="all" selected>All</option><option value="new">New</option>
<option value="acknowledged">Acknowledged</option>
<option value="dismissed">Dismissed</option></select>
Severity: <select id="alertsevfilter" onchange="refresh()">
<option value="all" selected>All</option><option value="Critical">Critical</option>
<option value="High">High</option><option value="Medium">Medium</option>
<option value="Low">Low</option></select></p>
<div id="alertslist"><p class="note">Loading...</p></div>
</section>

<section class="block" id="summary">
<h2>&#128172; Plain-English summary <button onclick="explain()">Explain now</button></h2>
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
<h2>&#128268; Internet drops</h2>
<div id="outages"><p class="note">Loading...</p></div>
</section>

<section class="block" id="devices">
<h2>&#128241; Your devices</h2>
<p class="note">Name your devices so alerts read like English instead of hardware addresses.</p>
<div id="devices"><p class="note">Loading...</p></div>
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
<button class="btn-sm" onclick="addQuietWindow()">Add</button></p>
</div></details>

<details class="settings"><summary>Rule health</summary><div class="inner">
<p class="note">How often each detection rule earns its keep, judged by your own Ack / Dismiss history over the last 30 days.</p>
<div id="rulehealth"><p class="note">Loading...</p></div>
</div></details>

<details class="settings"><summary>Allowlist</summary><div class="inner">
<p class="note">Patterns the monitor should never alert on again. A pattern matches when it appears anywhere in the alert's identifying text -- a MAC, an IP:port, a domain.</p>
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
<button class="btn-sm" onclick="addAllow()">Add</button></p>
</div></details>

<details class="settings"><summary>Email digest</summary><div class="inner">
<p><button class="btn-sm" onclick="sendDigest()">Send digest now</button> <span class="note" id="digestmsg"></span></p>
<p class="note">A digest email goes out automatically once a day (set NETMON_DIGEST_HOURS to change it, 0 to disable). It covers Medium alerts and up, skipping anything you dismissed.</p>
</div></details>

<details class="settings"><summary>Port guide &mdash; what the numbers mean</summary><div class="inner">
<p class="note">Apps talk on numbered "channels" called ports. Here are the
ones you'll actually see. Anything not on this list is an uncommon channel --
the monitor flags those for you automatically.</p>
%%PORT_GUIDE%%
</div></details>
</section>

<p><a href="/pcap">Analyze a pcap file</a> | <a href="/ask">Ask your network</a> | <a href="/logout" id="logoutlink" style="display:none">Logout</a></p>

<script>
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
  if (d.whole_network) {
    wb.style.display = "block";
    document.getElementById("pagesub").innerHTML =
      'This page watches <b>every device on your home network</b> and explains ' +
      'it in plain English. It never reads <i>what</i> anyone sends or receives -- only ' +
      '<i>who</i> each device talks to and <i>how much</i> data moves. ' +
      '<span id="clock"></span>';
    document.getElementById("clock").textContent = "updated " + d.now;
  } else {
    wb.style.display = "none";
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
    + (lead.meaning ? `<br><b>What this means:</b> ${esc(lead.meaning)}` : "")
    + (lead.is_normal ? `<br><b>Is this normal?</b> ${esc(lead.is_normal)}` : "")
    + (lead.what_to_do ? `<br><b>What to do:</b> ${esc(lead.what_to_do)}` : "")
    + (lead.note ? `<br><b>Your note:</b> ${esc(lead.note)}` : "")
    + `<br><span class="note">${esc(lead.ts)}${lead.detail ? " -- " + esc(lead.detail) : ""}</span>`
    + (n > 1 ? `<br><button class="btn-sm ghost" onclick="toggleGroup(${gi}, this)">show all ${n}</button>`
      + `<div id="group-${gi}" style="display:none">`
      + g.items.slice(1).map(a=>`<span class="note">${esc(a.ts)}${a.detail ? " -- " + esc(a.detail) : ""}</span><br>`).join("")
      + `</div>` : "")
    + `<br><button class="btn-sm" onclick="triageGroup(${gi},'ack')">Ack${n > 1 ? " all" : ""}</button>`
    + `<button class="btn-sm ghost" onclick="triageGroup(${gi},'dismiss')">Dismiss${n > 1 ? " all" : ""}</button>`
    + `<button class="btn-sm ghost" onclick="aiVerdict(${lead.id})">AI verdict</button>`
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
  let cards = `<div class="card kpi ${kpiCls}"><div class="v">${openN}</div><div class="l">open alerts &middot; ${critHighN} high/critical</div></div>`;
  cards += `<div class="card"><div class="v">${d.throughput_mbps.toFixed(2)}</div><div class="l">MB per second (last min)</div></div>`;
  if (DEV_COUNT !== null) cards += `<div class="card"><div class="v">${DEV_COUNT}</div><div class="l">devices seen</div></div>`;
  cards += `<div class="card graphcard"><div class="v"><span id="pktrate">&ndash;</span> MB</div><div class="l">traffic per tick, live &middot; <span id="pktrate2"></span> packets/tick</div><canvas id="pktgraph" width="280" height="72"></canvas></div>`;
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

  document.getElementById("outages").innerHTML =
    (d.ongoing.length ? d.ongoing.map(o=>`<p class="down">INTERNET DOWN: ${esc(o.target)} since ${esc(o.since)}</p>`).join("") : "")
    + (d.outages.length ? `<table><tr><th>What dropped</th><th>Down for</th><th>When</th></tr>` +
      d.outages.map(o=>`<tr><td>${esc(o.target)}</td><td>${o.gap_s.toFixed(0)}s</td><td class="note">${esc(o.when)}</td></tr>`).join("") + `</table>`
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
      return `<tr><td>${v.name?`<b>${esc(v.name)}</b><br>` :""}<span class="note">${esc(v.mac)}</span></td><td>${status}</td><td>${esc(v.last_ip)}</td><td>${traf}</td><td>${prof}</td><td class="note">${esc(v.first_seen)}</td><td class="note">${esc(v.last_seen)}</td><td><button class="btn-sm ghost" data-mac="${esc(v.mac)}" onclick="renameDevice(this.dataset.mac)">Rename</button></td></tr>`;
    }).join("") + `</table>`
    : '<p class="note">No devices seen yet.</p>');
  } catch(e) {
    document.getElementById("devices").innerHTML =
      '<p class="banner-red">Could not load devices: '
      + esc(String((e && e.message) || e)) + '</p>';
  }
}
async function renameDevice(mac){
  const name = prompt("Name for " + mac + " (blank clears it):", DEV_NAMES[mac] || "");
  if (name === null) return;
  await fetch("/api/devices/name", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({mac: mac, name: name})});
  loadDevices();
}
const DAY_NAMES = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"];
let QH_CACHE = [];
async function loadQuietHours(){
  const r = await fetch("/api/settings/quiet_hours");
  const d = await r.json();
  QH_CACHE = d.windows || [];
  document.getElementById("quiethours").innerHTML = QH_CACHE.length ?
    `<table><tr><th>Days</th><th>From</th><th>To</th><th>Applies to</th><th></th></tr>` +
    QH_CACHE.map((x,i)=>`<tr><td>${x.days.map(dd=>DAY_NAMES[dd]).join(", ")}</td><td>${esc(x.start)}</td><td>${esc(x.end)}</td><td>${esc((x.kinds||["all"]).join(", "))}</td><td><button class="btn-sm ghost" onclick="delQuietWindow(${i})">Remove</button></td></tr>`).join("") + `</table>`
    : '<p class="note">No quiet hours set -- emails send any time.</p>';
}
async function saveQuietWindows(wins){
  await fetch("/api/settings/quiet_hours", {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({windows: wins})});
  loadQuietHours();
}
async function addQuietWindow(){
  const days = [...document.querySelectorAll(".qh_day:checked")].map(c=>parseInt(c.value,10));
  saveQuietWindows(QH_CACHE.concat([{days: days,
    start: document.getElementById("qh_start").value || "22:00",
    end: document.getElementById("qh_end").value || "07:00",
    kinds: ["all"]}]));
}
async function delQuietWindow(i){
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
    d.entries.map(e=>`<tr><td>${esc(e.kind)}</td><td>${esc(e.pattern)}</td><td>${esc(e.note)}</td><td><button class="btn-sm ghost" onclick="delAllow(${e.id})">Remove</button></td></tr>`).join("") + `</table>`
    : '<p class="note">Allowlist is empty.</p>';
}
async function addAllow(){
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
  await fetch("/api/allowlist/" + id, {method:"DELETE"});
  loadAllowlist();
}
async function sendDigest(){
  const el = document.getElementById("digestmsg");
  el.textContent = "sending...";
  const r = await fetch("/api/digest/send", {method:"POST"});
  const d = await r.json();
  el.textContent = d.sent ? "Digest sent."
    : "Nothing to send (no recent alerts, or email isn't configured).";
}
refresh(); setInterval(refresh, 5000);
loadDevices(); loadQuietHours(); loadRuleHealth(); loadAllowlist();
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

_VALID_STATUS = ("new", "acknowledged", "dismissed")


def _alerts(status_filter="all"):
    """Alert dicts for the last hour, newest first, with optional triage
    status filter."""
    try:
        rows = dbm.query(
            f"SELECT {_ALERT_COLS_EXT} FROM alerts WHERE ts > ?"
            " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
        extended = True
    except Exception:
        rows = dbm.query(
            f"SELECT {_ALERT_COLS} FROM alerts WHERE ts > ?"
            " ORDER BY ts DESC LIMIT 20", (time.time() - 3600,))
        extended = False
    alerts = []
    for r in rows:
        if extended:
            aid, sev, t, d, m, n, w, ts, st, note = r
        else:
            aid, sev, t, d, m, n, w, ts = r
            st, note = "new", ""
        alerts.append({
            "id": aid, "severity": sev, "title": t, "detail": d,
            "meaning": m, "is_normal": n, "what_to_do": w,
            "ts": _fmt_ts(ts), "status": st or "new", "note": note or "",
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
def alert_ack(aid):
    note = _note_from_request()
    if not _set_alert_status(aid, "acknowledged", note):
        return jsonify({"ok": False,
                        "error": "triage is not available yet"}), 500
    return jsonify({"ok": True})


@app.route("/api/alerts/<int:aid>/dismiss", methods=["POST"])
def alert_dismiss(aid):
    note = _note_from_request()
    if not _set_alert_status(aid, "dismissed", note):
        return jsonify({"ok": False,
                        "error": "triage is not available yet"}), 500
    return jsonify({"ok": True})


# --- devices: friendly names ---------------------------------------------
# Name your hardware ("PS5", "Mom's iPhone") so alerts and tables read
# like English instead of MAC addresses.

PROBATION_HOURS = 24  # new devices stay on probation watch this long


@app.route("/api/devices")
def api_devices():
    now = time.time()
    devs = dbm.known_devices(limit=100)
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
def api_allowlist_del(eid):
    dbm.remove_allowlist(eid)
    return jsonify({"ok": True})


@app.route("/api/digest/send", methods=["POST"])
def api_digest_send():
    from . import notify as notifm
    sent = notifm.send_digest()
    return jsonify({"ok": True, "sent": bool(sent)})


# --- AI: ask-your-network + AI triage verdict -------------------------------
# A teammate builds netmon/ai_assist.py with answer_question(question) and
# triage_verdict(alert), each returning None when no API key is set. Guard
# everything so the dashboard works with no AI configured.

_AI_UNAVAILABLE = {"unavailable": True,
                   "message": "AI answers need an API key -- set OPENAI_API_KEY."}


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
    return render_template_string(ASK_HTML)


@app.route("/api/ask", methods=["POST"])
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
    return render_template_string(
        INDEX_HTML.replace("%%PORT_GUIDE%%", _port_guide_html()))


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
         "ts": a["ts"], "status": a["status"], "note": a["note"]}
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
    whole_network = os.environ.get(
        "NETMON_WHOLE_NETWORK", "").strip().lower() in ("1", "true", "yes")
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
        "stale": stale,
        "last_flow_ts": last_flow_ts,
        "auth_required": bool(NETMON_PASSWORD),
        "device_names": device_names,
    })


@app.route("/explain", methods=["POST"])
def explain_now():
    from . import explainer as expl
    summary, origin = expl.summarize(save=True)
    return jsonify({"ok": True, "headline": summary["headline"],
                    "origin": origin})


@app.route("/pcap", methods=["GET", "POST"])
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
    try:
        agg = capm.run_pcap(path)
    finally:
        os.unlink(path)
    # Anchor analysis windows at the newest packet, not wall-clock time,
    # so old captures analyze against their own timeline.
    anchor = agg.max_ts or time.time()
    from . import detect as detm
    detm.run_all(now=anchor)
    alerts = [
        {"severity": sev, "title": t, "detail": d, "meaning": m,
         "is_normal": n, "what_to_do": w}
        for sev, t, d, m, n, w in dbm.query(
            "SELECT severity, title, detail, meaning, is_normal, what_to_do"
            " FROM alerts WHERE ts > ?"
            " ORDER BY ts DESC LIMIT 20", (anchor - 86400,))
    ]
    summary, _origin = expl.summarize(save=False, now=anchor)
    return render_template_string(PCAP_RESULT_HTML, filename=f.filename,
                                  packets=agg.packets_seen,
                                  summary=summary, alerts=alerts)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
