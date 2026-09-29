# brutedash

A mini SOC analyst: parses SSH auth logs and writes technical briefs.

Paste a raw log and brutedash parses it into structured findings, persists them to SQLite, enriches each attacker IP with threat intel, and writes an analyst-ready technical brief per attacker — via an LLM when `OPENAI_API_KEY` is set, or a rule-based fallback otherwise.

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
