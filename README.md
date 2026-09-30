# brutedash

A mini SOC analyst: parses SSH auth logs and writes technical briefs — now
with **netmon**, a Phase 2 home-network traffic monitor with a live
dashboard and plain-English explanations anyone can read.

## netmon — live network monitor (Phase 2)

Watches **this machine's** network interface, rolls packets into flow
metadata (who talked to who, on what port, how many bytes — **never packet
contents**), and answers three questions on a live dashboard:

- **What needs your eyes?** — alerts written for non-technical readers: every
  alert explains what it means, whether it's normal, and what to do
- **What's happening?** — a plain-English summary every 15 minutes (or on
  demand with the "Explain now" button): headline, what's happening, what
  stands out, suggested actions
- **What's normal?** — a live "right now" readout plus a port guide, so you
  learn what everyday traffic looks like

Detection rules: port scans, unusual outbound ports, traffic spikes, and
**beaconing** (steady clockwork check-ins with one outside address — how
malware "phones home"). A watchdog pings the gateway + internet hosts and
logs every outage with timestamps.

The explainer uses an LLM when `OPENAI_API_KEY` is set, otherwise a
narrative rule-based summary — output is JSON-schema validated before
display, same discipline as the brief writer.

It also **analyzes pcap files** (e.g. exported from Wireshark): upload one
on the `/pcap` page and it runs the same pipeline — flows, detection,
plain-English explanation.

### Run it

```bash
pip install -r requirements.txt

# Full monitor (live capture needs root for raw sockets):
sudo python -m netmon.run
# open http://127.0.0.1:5001

# Analyze a pcap and exit:
python -m netmon.run --pcap capture.pcap

# Dashboard only (no capture):
python -m netmon.run --dashboard-only
```

Optional, for AI-written summaries:

```bash
export OPENAI_API_KEY=<your key here>
```

If port 5001 is taken on your machine: `python -m netmon.run --port 8080`.

Windows notes: install [Npcap](https://npcap.com/) for live capture, run
PowerShell **as administrator**, and use the `py` launcher
(`py -m pip install -r requirements.txt`, `py -m netmon.run --port 8080`).

### netmon structure

| File | What it does |
|---|---|
| `netmon/run.py` | Entry point: wires up watchdog + capture + monitor threads + dashboard |
| `netmon/capture.py` | Packets → flow metadata (live sniff or pcap); inline SYN port-scan tracker |
| `netmon/detect.py` | Periodic rules: spikes, unusual ports, beaconing (with alert cooldowns); every alert carries plain-English meaning / is-this-normal / what-to-do |
| `netmon/watchdog.py` | Ping-based drop detection (Windows + Linux ping flags); logs outages with start/end/duration |
| `netmon/explainer.py` | Evidence builder + plain-English summaries (LLM or narrative rule-based, validated); shared port guide |
| `netmon/dashboard.py` | Flask live dashboard: `/`, `/api/stats`, `/explain`, `/pcap` — written for non-technical readers |
| `netmon/db.py` | SQLite storage: flows, alerts, outages, summaries (WAL mode); auto-migrates older DBs |

### Honest scope note

On a switched home network, one machine only sees **its own** traffic.
Whole-home visibility (every device) is Phase 3: a Raspberry Pi sensor by
the router. Phase 1 monitors the machine it runs on.

---

## brutedash — SSH log triage (original module)

## Pipeline

**parse → detect → persist → brief**

1. **Parse** — paste an SSH auth log into the dashboard form (or POST it to `/`). Malformed lines are skipped, not crashed on.
2. **Detect** — `detector.detect_brute_force()` counts `Failed password` events per source IP, flags IPs at or above the threshold (default: 3), and assigns severity (`Medium` ≤ 10 attempts, `High` > 10).
3. **Persist** — findings are saved to SQLite (`detections.db`); IPs seen in earlier scans are flagged as repeat attackers.
4. **Brief** — before writing, the analyst enriches the attacker IP with a threat-intel lookup (geolocation, hosting/proxy signals; cached 24h, best-effort — intel never blocks the brief). The per-IP "Generate brief" button then writes a technical brief as **structured JSON** (`severity`, `observed_pattern`, `recommended_actions`), validated against a schema before rendering. The LLM path uses JSON mode with a strict "do not invent facts" prompt; invalid shapes fall back to rule-based writing, so a malformed model response can never corrupt the page.

**Evals** — `eval_briefs.py` scores every brief on schema adherence, grounding (anti-hallucination heuristic: every claim traceable to the evidence), and completeness. Run it after any prompt or model change:

```bash
python eval_briefs.py
```

## Run it

```bash
pip install -r requirements.txt
python app.py
# open http://127.0.0.1:5000
```

Optional, for LLM-written briefs:

```bash
export OPENAI_API_KEY=...
```

Then open `/history` to see past scans.

## Project structure

| File | What it does |
|---|---|
| `app.py` | Flask dashboard: `/` parse & scan, `/history` past scans, `/brief` per-IP technical brief |
| `detector.py` | Log parsing + brute-force detection: parse → count → threshold → severity |
| `ipintel.py` | IP enrichment tool: geolocation + hosting/proxy lookup, 24h SQLite cache |
| `eval_briefs.py` | Brief quality evals: schema, grounding, completeness |
| `gen_log.py` | Generates `auth.log` test data (seeded, reproducible) |
| `auth.log` | Sample log, including a malformed line the parser skips |
