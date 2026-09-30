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
.card .v{font-size:1.6em;color:#58a6ff} .card .l{color:#8b949e;font-size:.85em}
.up{color:#3fb950;font-weight:bold} .down{color:#f85149;font-weight:bold}
.high{color:#f85149;font-weight:bold} .medium{color:#d29922} .low{color:#8b949e} .critical{color:#f85149;font-weight:bold;background:#3d1113}
.bar{background:#30363d;border-radius:3px;height:1em;margin:.2em 0}
.bar>div{background:#58a6ff;height:1em;border-radius:3px}
a{color:#58a6ff} button{background:#238636;color:#fff;border:0;padding:.5em 1.2em;cursor:pointer;font-family:monospace;border-radius:4px}
.btn-sm{background:#238636;color:#fff;border:0;padding:.25em .8em;cursor:pointer;font-family:monospace;border-radius:4px;font-size:.85em;margin:.25em .2em 0 0}
.btn-sm.ghost{background:#21262d;border:1px solid #30363d}
input,textarea,select{background:#0d1117;color:#c9d1d9;border:1px solid #30363d;font-family:monospace;padding:.4em;border-radius:4px}
.banner-red{background:#3d1113;border:1px solid #f85149;color:#f85149;padding:.8em 1em;border-radius:6px;margin-bottom:1em}
pre{background:#161b22;padding:1em;white-space:pre-wrap;border:1px solid #30363d;border-radius:6px}
.alert{border-left:4px solid #d29922;background:#161b22;padding:.6em 1em;margin:.5em 0}
.alert.High{border-color:#f85149} .alert.Critical{border-color:#f85149;background:#2a1215}
.note{color:#8b949e;font-size:.85em}
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
<style>""" + STYLE + """</style></head><body>
<h1>netmon &mdash; your network, explained</h1>
<div id="stalebanner" class="banner-red" style="display:none"></div>
<p class="note">This page watches your computer's network traffic and explains
it in plain English. It never reads <i>what</i> you send or receive -- only
<i>who</i> your computer talks to and <i>how much</i> data moves.
<span id="clock"></span></p>

<h2>What needs your eyes</h2>
<p class="note">Show: <select id="alertstatusfilter" onchange="refresh()">
<option value="all" selected>All</option><option value="new">New</option>
<option value="acknowledged">Acknowledged</option>
<option value="dismissed">Dismissed</option></select></p>
<div id="alerts"><p class="note">Loading...</p></div>

<h2>Plain-English summary <button onclick="explain()">Explain now</button></h2>
<div id="summary"><p class="note">Loading...</p></div>

<h2>At a glance</h2>
<div id="cards"></div>

<h2>What's normal?</h2>
<p>On a normal day, almost everything your computer does online is one of a few
things: loading websites and apps (encrypted, port 443), looking up website
addresses (port 53), and quiet background chatter like checking the time. If
the alerts above are empty, everything is fine -- <b>a quiet network is a healthy network.</b></p>
<div id="normalnow"><p class="note">Loading...</p></div>

<h2>Biggest conversations (last 15 min)</h2>
<div id="talkers"></div>

<h2>Port guide &mdash; what the numbers mean</h2>
<p class="note">Apps talk on numbered "channels" called ports. Here are the
ones you'll actually see. Anything not on this list is an uncommon channel --
the monitor flags those for you automatically.</p>
%%PORT_GUIDE%%

<h2>Internet drops</h2>
<div id="outages"><p class="note">Loading...</p></div>

<p><a href="/pcap">Analyze a pcap file</a> | <a href="/ask">Ask your network</a> | <a href="/logout" id="logoutlink" style="display:none">Logout</a></p>

<script>
const SEV_WORDS = {Critical:"Act now", High:"Needs attention", Medium:"Worth a look", Low:"Heads up"};
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
async function refresh(){
  const sf = document.getElementById("alertstatusfilter");
  const r = await fetch("/api/stats?status=" + (sf ? sf.value : "all"));
  const d = await r.json();
  document.getElementById("clock").textContent = "updated " + d.now;

  const sb = document.getElementById("stalebanner");
  if (d.stale) {
    sb.style.display = "block";
    sb.textContent = "No fresh data \u2014 the monitor may have stopped. Check that netmon is still running.";
  } else {
    sb.style.display = "none";
  }
  document.getElementById("logoutlink").style.display = d.auth_required ? "inline" : "none";

  document.getElementById("alerts").innerHTML = d.alerts.length ? d.alerts.map(a=>
    `<div class="alert ${esc(a.severity)}"><b>[${SEV_WORDS[a.severity]||esc(a.severity)}] ${esc(a.title)}</b> <span class="note">[${esc(a.status)}]</span>`
    + (a.meaning ? `<br><b>What this means:</b> ${esc(a.meaning)}` : "")
    + (a.is_normal ? `<br><b>Is this normal?</b> ${esc(a.is_normal)}` : "")
    + (a.what_to_do ? `<br><b>What to do:</b> ${esc(a.what_to_do)}` : "")
    + (a.note ? `<br><b>Your note:</b> ${esc(a.note)}` : "")
    + `<br><span class="note">${esc(a.ts)}${a.detail ? " -- " + esc(a.detail) : ""}</span>`
    + `<br><button class="btn-sm" onclick="triage(${a.id},'ack')">Ack</button>`
    + `<button class="btn-sm ghost" onclick="triage(${a.id},'dismiss')">Dismiss</button>`
    + `<button class="btn-sm ghost" onclick="aiVerdict(${a.id})">AI verdict</button>`
    + ` <span class="note" id="verdict-${a.id}"></span></div>`
  ).join("") : '<p class="note">No alerts in the last hour. All quiet.</p>';

  const s = d.summary;
  if (s) document.getElementById("summary").innerHTML =
    `<p><b>${esc(s.headline)}</b> <span class="note">(${esc(s.origin)}, ${s.window_min} min window)</span></p>`
    + `<p>${esc(s.whats_happening)}</p>`
    + (s.stands_out.length ? "<b>Stands out:</b><ul>" + s.stands_out.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "")
    + (s.suggested_actions.length ? "<b>Suggested:</b><ul>" + s.suggested_actions.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "");

  let cards = `<div class="card"><div class="v">${d.throughput_mbps.toFixed(2)}</div><div class="l">MB per second (last min)</div></div>`;
  cards += `<div class="card"><div class="v">${d.packets_1m}</div><div class="l">data packets (last min)</div></div>`;
  for (const [label, st] of Object.entries(d.connectivity))
    cards += `<div class="card"><div class="v ${st.up?"up":"down"}">${st.up?"UP":"DOWN"}</div><div class="l">${esc(label)}</div></div>`;
  document.getElementById("cards").innerHTML = cards;

  document.getElementById("normalnow").innerHTML =
    `<p>In the last 15 minutes: <b>${d.normal_now.mb} MB</b> across ${d.normal_now.flows} conversations.`
    + (d.normal_now.top_words ? ` Mostly: ${esc(d.normal_now.top_words)}.` : " Nothing moving right now.")
    + `</p>`;

  const maxB = Math.max(1, ...d.talkers.map(t=>t.bytes));
  document.getElementById("talkers").innerHTML = d.talkers.length ?
    `<table><tr><th>From</th><th>To</th><th>Channel (port)</th><th>MB</th><th></th></tr>` +
    d.talkers.map(t=>`<tr><td>${esc(t.src)}</td><td>${esc(t.dst)}</td><td>${t.port} (${esc(t.port_words)})</td><td>${(t.bytes/1e6).toFixed(2)}</td><td><div class="bar"><div style="width:${(100*t.bytes/maxB).toFixed(0)}%"></div></div></td></tr>`).join("") + `</table>`
    : '<p class="note">No conversations yet.</p>';

  document.getElementById("outages").innerHTML =
    (d.ongoing.length ? d.ongoing.map(o=>`<p class="down">INTERNET DOWN: ${esc(o.target)} since ${esc(o.since)}</p>`).join("") : "")
    + (d.outages.length ? `<table><tr><th>What dropped</th><th>Down for</th><th>When</th></tr>` +
      d.outages.map(o=>`<tr><td>${esc(o.target)}</td><td>${o.gap_s.toFixed(0)}s</td><td class="note">${esc(o.when)}</td></tr>`).join("") + `</table>`
      : '<p class="note">No drops recorded. Your connection has been steady.</p>');
}
async function triage(aid, action){
  const note = prompt("Optional note (leave blank for none):", "");
  if (note === null) return;  // cancelled
  await fetch("/api/alerts/" + aid + "/" + action, {method:"POST",
    headers:{"Content-Type":"application/json"},
    body: JSON.stringify({note: note})});
  refresh();
}
async function aiVerdict(aid){
  const el = document.getElementById("verdict-" + aid);
  el.textContent = "thinking...";
  const r = await fetch("/api/triage/" + aid, {method:"POST"});
  const d = await r.json();
  el.textContent = d.unavailable ? d.message : (d.verdict + " \u2014 " + d.reasoning);
}
async function explain(){
  document.getElementById("summary").innerHTML = '<p class="note">Writing summary...</p>';
  await fetch("/explain", {method:"POST"});
  refresh();
}
refresh(); setInterval(refresh, 5000);
</script></body></html>"""


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
    return jsonify({
        "now": _fmt_ts(now),
        "throughput_mbps": mbps,
        "packets_1m": one_min[1],
        "connectivity": conn,
        "summary": dbm.latest_summary(),
        "alerts": alerts,
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
    })


@app.route("/explain", methods=["POST"])
def explain_now():
    from . import explainer as expl
    summary, _origin = expl.summarize(save=True)
    return jsonify({"ok": True, "headline": summary["headline"]})


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
