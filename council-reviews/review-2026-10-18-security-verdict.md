# Council review 2026-10-18 — SECURITY seat verdict (brutedash / Project Orion)

Read-only review. Scope: app.py, detector.py, ipintel.py, netmon/*.py, dashboard/templates.
Prior-cycle de-duplication: the 2026-10-11 security findings are all confirmed FIXED in
source and are not re-flagged — app.py MAX_CONTENT_LENGTH (app.py:33, shipped 4c357a6),
/brief per-IP rate limit (app.py:198-251, shipped 8ec6547), esc() full entity escape
(netmon/dashboard.py, shipped 8ec6547). Also verified as already-shipped, not re-flagged:
CSP on both apps (88dd667), Origin/Sec-Fetch-Site mutation gate (f4947aa), security
headers + cookie hardening (652b433), /explain and /pcap AI rate limits (063a421, 8230f2f).

## Critical

None. No finding at this severity.

## High

None. No finding at this severity.

## Medium

### M1. app.py:169 — OpenAI client built with no timeout; the one construction the timeout fix missed
What is wrong: `client = OpenAI(api_key=...)` in `write_brief()` sets no `timeout`.
Both other client constructions in the codebase carry the council-mandated guard —
netmon/ai_assist.py:64 and netmon/explainer.py:316 use `timeout=30`, with comments
stating a stuck API call must never wedge the worker. app.py was missed. The OpenAI
SDK default is ~600s with retries, and render.yaml:11 runs the public demo as
`gunicorn app:app --workers 2` (sync workers). Scenario: two concurrent /brief POSTs
against a hung or slow upstream each hold a sync worker for minutes — with only 2
workers the entire public demo stops answering until gunicorn recycles them. The
/brief rate limiter (10/min) does not help; it limits call count, not hold time.
Concrete fix: `client = OpenAI(api_key=api_key, timeout=30)` at app.py:169, mirroring
netmon/explainer.py:316 exactly.

### M2. app.py:325-338 + app.py:345-350 — public demo index POST is un-rate-limited and grows detections.db without bound; /history renders the entire table
What is wrong: The `/` POST handler has no rate limit and no retention: every POST
appends one detections row per distinct IP in the pasted log (save_detections,
app.py:338), forever. The 10MB cap (app.py:33) bounds one request, not cumulative
growth. `history()` then runs `SELECT ip, count, severity, scanned_at FROM
detections ORDER BY ...` with no LIMIT and renders every row into one HTML page.
Scenario: anyone on the internet runs a loop of POSTs with 10MB synthetic logs
against the unauthenticated Render demo → unbounded SQLite growth on the ephemeral
disk plus a /history page that grows until rendering it exhausts memory — a slow
disk/memory DoS that the per-request cap does not address. /brief got a limiter in
the last cycle; the write path on `/` did not.
Concrete fix: (1) apply the existing `_brief_allowed()` sliding-window check (or an
equivalent per-IP limiter) to the POST branch of `index()` before `save_detections`;
(2) add `LIMIT 500` to the history query at app.py:347-349; (3) prune detections
older than a fixed window (e.g. delete rows with scanned_at older than 30 days
inside save_detections).

### M3. ipintel.py:21 + ipintel.py:35-39 — IP intel fetched over plaintext HTTP, with no response-size cap and no redirect re-check; the response text flows into the LLM prompt
What is wrong: `API_URL = "http://ip-api.com/json/{ip}?..."` (line 21) is the only
plaintext-HTTP external fetch in the codebase. `_fetch()` does
`resp.read().decode("utf-8")` with no byte cap (line 39), and urllib follows
redirects to any host with no re-validation. Every other fetcher in the project
does this correctly: netmon/threatintel.py `_fetch_url` enforces an https feed-host
allowlist before AND after redirects plus a 5MB cap. Three concrete harms:
(a) integrity — an on-path attacker (public Wi-Fi, compromised router, ISP) can
spoof the JSON; the returned `country`/`org` strings are interpolated into the
brief evidence at app.py write_brief() and from there into BRIEF_PROMPT and into
the rendered rule-based brief — spoofed intel becomes prompt text and page text
(output shape is constrained by _validate_brief, so impact is brief wording, not
code execution); (b) availability — a spoofed or broken endpoint returning a huge
body is read into memory whole; (c) confidentiality — the attacker IPs the user is
investigating are disclosed in cleartext to every on-path observer.
Concrete fix: change line 21 to `https://ip-api.com/json/{ip}?...`; in `_fetch()`,
read at most 65536 bytes (`resp.read(65536)`) before json.loads, mirroring the
cap discipline in netmon/threatintel.py.

## Low

### L1. app.py:73-74 + ipintel.py:25 — detections.db created world-readable (0644); the netmon.db permission self-heal was never applied to it
What is wrong: `get_db()` (app.py:73) and `_db()` (ipintel.py:25) both
`sqlite3.connect(DB_PATH)` with no chmod. Verified live on this machine:
detections.db is mode 0644 while netmon/netmon.db is 0600. The council fixed this
exact defect for netmon.db — netmon/db.py:537 chmods 0600 whenever group/other bits
are set, covering pre-existing files — and for the diagnostics bundle dir (0700),
but detections.db was missed. It holds scan history (which IPs were investigated,
when, with what counts) plus the ip_intel cache: readable by any other local
account on a shared box.
Concrete fix: after connect in app.py `get_db()` (and ipintel.py `_db()`), apply
the db.py pattern: `if os.stat(DB_PATH).st_mode & 0o077: os.chmod(DB_PATH, 0o600)`
inside try/except OSError.

### L2. netmon/config.py:315-323 + netmon/config.py:363 — an existing, user-created config.yaml never gets its permissions tightened, though it may hold the dashboard passwords
What is wrong: `ensure_bootstrap()` chmods 0600 only on the file it creates
(line 323). `load()` (line 363) reads an existing config.yaml as-is and never
tightens it. The shipped template (config.py:254-255) explicitly invites putting
auth.owner_password / auth.viewer_password in this file and warns the values are
"readable by anyone who can read this file" — a file the user creates or restores
with an editor/backup tool lands at the default 0644 and stays there, exposing the
owner password (full dashboard control, including quarantine and scan triggers)
to any local account. netmon.db already demonstrates the intended pattern:
self-heal permissions on open (netmon/db.py:537).
Concrete fix: in `load()`, when the file exists, apply the same self-heal before
reading: `if path.stat().st_mode & 0o077: os.chmod(path, 0o600)` in try/except
OSError — one block, mirroring db.py.

### L3. app.py:198 + render.yaml:11 — /brief rate-limit state is per-process; the deployed demo runs 2 gunicorn workers, so the configured cap is silently doubled
What is wrong: `_BRIEF_USAGE` is a module-level dict (app.py:198) guarded by a
threading lock — correct within one process, invisible across processes.
render.yaml:11 starts gunicorn with `--workers 2`, so the S2 limiter shipped last
cycle enforces ai.ask_per_min / ai.ask_per_hour per worker: the effective
LLM-spend ceiling on the public deployment is 2× the configured values, and each
worker's window resets independently. Same structural caveat applies to the
dashboard's in-memory limiters if it is ever served multi-worker (today
netmon/run.py serves it single-process threaded, so the dashboard is unaffected).
Concrete fix: set `--workers 1 --threads 4` in render.yaml (the demo is
I/O-bound; threads preserve concurrency), or document in app.py that the limiter
is per-process and set the config caps to half the intended budget. The
workers=1 change is the one-line correct fix for the demo.

### L4. netmon/dashboard.py:3902-3912 — /api/ask question length is unbounded (body cap is 100MB); the raw question is interpolated straight into the LLM prompt
What is wrong: `api_ask()` strips the question and rejects only the empty string;
there is no length cap before `ai_assist.answer_question()` interpolates it
verbatim via `QA_PROMPT.format(... question=question ...)` (netmon/ai_assist.py,
answer_question). The only ceiling is MAX_CONTENT_LENGTH = 100MB
(netmon/dashboard.py:35). The route is owner-only and rate-limited per call, so
this is not a budget bypass — but a multi-MB question is held in memory, formatted
into a prompt, and shipped to the API on every allowed call, for zero benefit.
Concrete fix: in `api_ask()`, after the strip, reject `len(q) > 2000` with 400
("question too long"); optionally also truncate defensively at the top of
ai_assist.answer_question().

### L5. netmon/ingest.py:306 — Windows event-log XML parsed with stdlib ElementTree and no entity-expansion guard
What is wrong: `parse_security_xml()` calls `ET.parse(path)` on files from the
ingest watch directory. Files are size-capped at 50MB (netmon/ingest.py:45,
enforced at ingest.py:100), but xml.etree.ElementTree has no billion-laughs /
quadratic-blowup protection (documented Python XML vulnerability): a crafted
50MB export with nested internal entities expands to GBs in memory and kills the
monitor process — the security tool DoSed by a log file. Boundary, stated
honestly: exploiting this needs write access to the ingest folder (the owner's
own export drop), so this is hardening, not an open hole.
Concrete fix: reject before parsing any XML file whose text contains
`<!ENTITY` (cheap pre-scan of the first bytes / full text — exports from Windows
Event Viewer never declare entities), or parse with defusedxml if a dependency
is ever acceptable.

## Non-findings (checked this cycle, clean)

- Auth/authz, dashboard: every mutating route carries @_owner_required (route
  table re-audited); login uses hmac.compare_digest, server-side session role,
  session.clear() before role set (fixation-safe), 5-failures/60s → 5-min block
  with a global sweep. The new cross-site gate (dashboard.py _cross_site_mutation
  _check) was read in full: POST/PUT/PATCH/DELETE blocked on Sec-Fetch-Site:
  cross-site or a non-matching/opaque Origin; the neither-header allowance is
  sound for the stated threat (a non-browser client cannot ride the owner's
  session) and is documented in code.
- CSP/headers: DEMO_CSP (script-src 'none') and DASHBOARD_CSP verified in source
  on both apps; the dashboard's script-src 'unsafe-inline' is a documented,
  deliberate posture (inline-script architecture), with connect/form/frame/object
  locked to 'self'/'none'. Session cookie HttpOnly + SameSite=Lax; Secure
  deliberately unset for the documented LAN-over-HTTP deployment.
- SQL injection: all runtime queries parameterized. The f-string SQL sites are
  constants-only (dashboard _ALERT_COLS* column lists; {ph} placeholder strings
  with bound parameters in api_device; db.py migration column names hardcoded;
  health.py table names from a hardcoded tuple literal). LIKE helpers take only
  ipaddress-validated IPs, regex-validated domains, or _MAC_RE-validated MACs —
  no %/_ wildcard injection path.
- Command injection: no shell=True / os.system / eval / exec / pickle anywhere in
  app code. All subprocess calls are argv lists with static arguments (watchdog
  ping, route/ipconfig, relay tasklist/pgrep, selfcheck, swaudit, amass, nuclei);
  scan targets remain config/inventory-only with the request body ignored.
- XSS: Flask render_template_string autoescape verified empirically on the venv
  Flask (a `<script>` payload renders as &lt;script&gt;) — app.py templates and
  the /pcap result page (user-supplied filename) are escaped. Dashboard JS sinks
  go through the now-complete esc(); playbook pages escape via html.escape;
  compliance CSV formula-prefixing from the 2026-10-04 batch is intact.
- SSRF / data leaving the machine: threat-intel feeds use an https host allowlist
  checked before and after redirects with a 5MB cap; AbuseIPDB is cached 24h
  and hard-capped at 50 lookups/day with the key in the header only; heartbeat
  URL is scheme-allowlisted (http/https) and never logged; SMTP credentials come
  from env only; escalate/notify strip CR/LF via _clean before headers.
  (ipintel.py is the exception — see M3.)
- detector.py: rotated-sibling reads are name-constructed (no glob), the 64MB
  decoded-byte cap bounds gzip expansion, and the primary is never skipped by
  the cap (2026-10-11 fix verified in source).

OVERALL VERDICT: NEEDS WORK — no Critical/High; 3 Medium (app.py LLM timeout, demo write-path DoS/retention, ipintel plaintext HTTP) and 5 Low, all in app.py/ipintel.py/config — the netmon core held.
