"""netmon/dashboard.py -- live Flask dashboard for the network monitor.

Pages:
  /        live dashboard (polls /api/stats every 5s)
  /pcap    upload a .pcap (e.g. from Wireshark) -> analyze -> AI explanation
  /explain POST -> regenerate the plain-English summary on demand

Run via netmon/run.py (starts capture + watchdog threads), or standalone
for viewing an existing database:  python -m netmon.dashboard
"""
import os
import tempfile
import time

from flask import Flask, request, jsonify, render_template_string, redirect

from . import db as dbm

app = Flask(__name__)
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

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
pre{background:#161b22;padding:1em;white-space:pre-wrap;border:1px solid #30363d;border-radius:6px}
.alert{border-left:4px solid #d29922;background:#161b22;padding:.6em 1em;margin:.5em 0}
.alert.High{border-color:#f85149} .alert.Critical{border-color:#f85149;background:#2a1215}
.note{color:#8b949e;font-size:.85em}
"""

INDEX_HTML = """<html><head><title>netmon -- your network, explained</title>
<style>""" + STYLE + """</style></head><body>
<h1>netmon &mdash; your network, explained</h1>
<p class="note">This page watches your computer's network traffic and explains
it in plain English. It never reads <i>what</i> you send or receive -- only
<i>who</i> your computer talks to and <i>how much</i> data moves.
<span id="clock"></span></p>

<h2>What needs your eyes</h2>
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

<p><a href="/pcap">Analyze a pcap file</a></p>

<script>
const SEV_WORDS = {Critical:"Act now", High:"Needs attention", Medium:"Worth a look", Low:"Heads up"};
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
async function refresh(){
  const r = await fetch("/api/stats"); const d = await r.json();
  document.getElementById("clock").textContent = "updated " + d.now;

  document.getElementById("alerts").innerHTML = d.alerts.length ? d.alerts.map(a=>
    `<div class="alert ${esc(a.severity)}"><b>[${SEV_WORDS[a.severity]||esc(a.severity)}] ${esc(a.title)}</b>`
    + (a.meaning ? `<br><b>What this means:</b> ${esc(a.meaning)}` : "")
    + (a.is_normal ? `<br><b>Is this normal?</b> ${esc(a.is_normal)}` : "")
    + (a.what_to_do ? `<br><b>What to do:</b> ${esc(a.what_to_do)}` : "")
    + `<br><span class="note">${esc(a.ts)}${a.detail ? " -- " + esc(a.detail) : ""}</span></div>`
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
        {"severity": sev, "title": t, "detail": d, "meaning": m,
         "is_normal": n, "what_to_do": w, "ts": _fmt_ts(ts)}
        for sev, t, d, m, n, w, ts in dbm.query(
            "SELECT severity, title, detail, meaning, is_normal, what_to_do,"
            " ts FROM alerts"
            " WHERE ts > ? ORDER BY ts DESC LIMIT 20", (now - 3600,))
    ]
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
