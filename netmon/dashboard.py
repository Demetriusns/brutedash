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

INDEX_HTML = """<html><head><title>netmon -- live network monitor</title>
<style>""" + STYLE + """</style></head><body>
<h1>netmon &mdash; live network monitor</h1>
<p class="note">Flow metadata only &mdash; who talked to who, how much. Never packet contents.
<span id="clock"></span></p>

<h2>Status</h2>
<div id="cards"></div>

<h2>AI summary <button onclick="explain()">Explain now</button></h2>
<div id="summary"><p class="note">Loading...</p></div>

<h2>Recent alerts</h2>
<div id="alerts"><p class="note">Loading...</p></div>

<h2>Top talkers (last 15 min)</h2>
<div id="talkers"></div>

<h2>Protocol mix (last 15 min)</h2>
<div id="protos"></div>

<h2>Outages</h2>
<div id="outages"><p class="note">Loading...</p></div>

<p><a href="/pcap">Analyze a pcap file</a></p>

<script>
function esc(s){return String(s).replace(/&/g,"&amp;").replace(/</g,"&lt;");}
async function refresh(){
  const r = await fetch("/api/stats"); const d = await r.json();
  document.getElementById("clock").textContent = "updated " + d.now;
  let cards = `<div class="card"><div class="v">${d.throughput_mbps.toFixed(2)}</div><div class="l">Mbps (last min)</div></div>`;
  cards += `<div class="card"><div class="v">${d.packets_1m}</div><div class="l">packets (last min)</div></div>`;
  for (const [label, st] of Object.entries(d.connectivity))
    cards += `<div class="card"><div class="v ${st.up?"up":"down"}">${st.up?"UP":"DOWN"}</div><div class="l">${esc(label)}</div></div>`;
  document.getElementById("cards").innerHTML = cards;

  const s = d.summary;
  if (s) document.getElementById("summary").innerHTML =
    `<p><b>${esc(s.headline)}</b> <span class="note">(${esc(s.origin)}, ${s.window_min} min window)</span></p>`
    + `<p>${esc(s.whats_happening)}</p>`
    + (s.stands_out.length ? "<b>Stands out:</b><ul>" + s.stands_out.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "")
    + (s.suggested_actions.length ? "<b>Suggested:</b><ul>" + s.suggested_actions.map(x=>`<li>${esc(x)}</li>`).join("") + "</ul>" : "");

  document.getElementById("alerts").innerHTML = d.alerts.length ? d.alerts.map(a=>
    `<div class="alert ${esc(a.severity)}"><b>[${esc(a.severity)}] ${esc(a.title)}</b><br><span class="note">${esc(a.ts)} -- ${esc(a.detail)}</span></div>`
  ).join("") : '<p class="note">No alerts in the last hour.</p>';

  const maxB = Math.max(1, ...d.talkers.map(t=>t.bytes));
  document.getElementById("talkers").innerHTML = d.talkers.length ?
    `<table><tr><th>Source</th><th>Destination</th><th>Port/Proto</th><th>MB</th><th></th></tr>` +
    d.talkers.map(t=>`<tr><td>${esc(t.src)}</td><td>${esc(t.dst)}</td><td>${t.port}/${esc(t.proto)}</td><td>${(t.bytes/1e6).toFixed(2)}</td><td><div class="bar"><div style="width:${(100*t.bytes/maxB).toFixed(0)}%"></div></div></td></tr>`).join("") + `</table>`
    : '<p class="note">No flows yet.</p>';

  const totP = d.protos.reduce((a,p)=>a+p.bytes,0) || 1;
  document.getElementById("protos").innerHTML = d.protos.map(p=>
    `<div>${esc(p.proto)} -- ${(100*p.bytes/totP).toFixed(0)}%<div class="bar"><div style="width:${(100*p.bytes/totP).toFixed(0)}%"></div></div></div>`
  ).join("") || '<p class="note">No traffic yet.</p>';

  document.getElementById("outages").innerHTML =
    (d.ongoing.length ? d.ongoing.map(o=>`<p class="down">OUTAGE IN PROGRESS: ${esc(o.target)} since ${esc(o.since)}</p>`).join("") : "")
    + (d.outages.length ? `<table><tr><th>Target</th><th>Down for</th><th>When</th></tr>` +
      d.outages.map(o=>`<tr><td>${esc(o.target)}</td><td>${o.gap_s.toFixed(0)}s</td><td class="note">${esc(o.when)}</td></tr>`).join("") + `</table>`
      : '<p class="note">No outages recorded.</p>');
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
<span class="note">{{ a.detail }}</span></div>
{% endfor %}{% else %}<p class="note">No alerts fired on this capture.</p>{% endif %}
<p><a href="/pcap">Analyze another</a> | <a href="/">Live dashboard</a></p>
</body></html>"""


def _fmt_ts(ts):
    return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))


# watchdog handle is attached by run.py; dashboard-only mode shows "unknown"
watchdog = None


@app.route("/")
def index():
    return render_template_string(INDEX_HTML)


@app.route("/api/stats")
def api_stats():
    now = time.time()
    one_min = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0)"
        " FROM flows WHERE ts > ?", (now - 60,))[0]
    mbps = one_min[0] * 8 / 60 / 1e6

    talkers = [
        {"src": s, "dst": d, "port": p, "proto": pr, "bytes": b}
        for s, d, p, pr, b in dbm.query(
            "SELECT src_ip, dst_ip, dst_port, proto, SUM(bytes) FROM flows"
            " WHERE ts > ? GROUP BY src_ip, dst_ip, dst_port, proto"
            " ORDER BY SUM(bytes) DESC LIMIT 10", (now - 900,))
    ]
    protos = [{"proto": pr, "bytes": b} for pr, b in dbm.query(
        "SELECT proto, SUM(bytes) FROM flows WHERE ts > ? GROUP BY proto",
        (now - 900,))]
    alerts = [
        {"severity": sev, "title": t, "detail": d, "ts": _fmt_ts(ts)}
        for sev, t, d, ts in dbm.query(
            "SELECT severity, title, detail, ts FROM alerts"
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
    return jsonify({
        "now": _fmt_ts(now),
        "throughput_mbps": mbps,
        "packets_1m": one_min[1],
        "connectivity": conn,
        "summary": dbm.latest_summary(),
        "alerts": alerts,
        "talkers": talkers,
        "protos": protos,
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
        {"severity": sev, "title": t, "detail": d}
        for sev, t, d in dbm.query(
            "SELECT severity, title, detail FROM alerts WHERE ts > ?"
            " ORDER BY ts DESC LIMIT 20", (anchor - 86400,))
    ]
    summary, _origin = expl.summarize(save=False, now=anchor)
    return render_template_string(PCAP_RESULT_HTML, filename=f.filename,
                                  packets=agg.packets_seen,
                                  summary=summary, alerts=alerts)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5001)
