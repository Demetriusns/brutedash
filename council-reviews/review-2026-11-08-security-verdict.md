# Council review 2026-11-08 — SECURITY seat verdict (brutedash / Project Orion)

Read-only review at git HEAD `75ffce6` (main, up to date with origin/main).
Scope read in full or audited in source: app.py, detector.py, ipintel.py,
netmon/*.py (dashboard 4301 lines, db, tools, ai_assist, config, health,
notify, escalate, reporting, weekly, scan, nuclei, amass, threatintel,
capture, ingest, quarantine, relay, rewind, pdfgen, canary, selfcheck,
swaudit, watchdog, templates, explainer, run), render.yaml, .gitignore.

Overall verdict: **NEEDS WORK** — no Critical/High; the two staged Mediums
from 2026-11-01 are still open verbatim, plus two new Lows and the accepted
ip-api debt. No SQL injection, command injection, stored-XSS, or
auth-bypass path was found — see Non-findings.

Prior-cycle de-duplication — verified FIXED in source, not re-flagged:
health.py `_secret_res` quoted-string fix (netmon/health.py:191-194,
`(?:["'][^"']*["']|\S+)` — plain multi-word passphrases now redact whole,
reproduced clean this cycle); compliance downloads owner-gated
(netmon/dashboard.py:3755,3769 `@_owner_required` on both routes);
`/api/health` removed from the password-gate exemption
(netmon/dashboard.py:172 exempts only `"/login"`). Daily-build fixes since
2026-11-01 also verified in source: detector chunked reading
(detector.py `_iter_capped_lines`, 64 KB blocks, 1 MB per-line cap before
parsing), ingest XML streaming (netmon/ingest.py:349 `ET.iterparse` +
`_declares_entities` entity rejection at ingest.py:301,416), rewind caps
isolation + export streaming (netmon/dashboard.py:3813ff streams a temp
file in 64 KB chunks), app/ipintel sqlite timeout=30 (app.py get_db,
ipintel.py `_db`), ipintel DB close-on-every-path + 10-minute negative
cache (ipintel.py `lookup_ip` finally-close, `NEGATIVE_CACHE_TTL`),
demo sample-log 256 KB cap (app.py `SAMPLE_MAX_BYTES`).

## Critical

None.

## High

None.

## Medium

### S1. STILL OPEN (2026-11-01 M1; 2026-10-25 security M2) — LAN-derived alert text reaches the AI tool loop, which executes active scans on model say-so with no owner confirmation
- netmon/ai_assist.py:440 — the /api/ask context is built from alert rows
  whose text is LAN-controlled (DNS/DHCP/mDNS names, device names):
  `"SELECT severity, title, detail, meaning FROM alerts WHERE ts > ?"`.
- netmon/ai_assist.py:384-385 — model output is executed:
  `inv = toolsm.invoke(c["tool"], c["params"], requested_by="ai_analyst")`;
  netmon/ai_assist.py:275-276 — up to `MAX_TOOL_ROUNDS = 2` rounds ×
  `MAX_TOOL_CALLS = 3` calls per owner question.
- netmon/tools.py:855-875 — the reachable `scan` tool is an active action,
  not a read: `name="scan"`, `timeout_s=600, idempotent=False,
  handler=_tool_scan`; its nuclei branch (netmon/tools.py:764
  `_scan_nuclei`) runs template-based probing against the whole inventory,
  and `_scan_amass` (tools.py:795) runs external enumeration.
What is wrong: unchanged from 2026-11-01. Registry validation answers "is
this call well-formed" (inventory-only, RFC1918 re-checked in
nuclei.build_argv), not "did the owner ask for a scan". A prompt injection
planted in alert detail — a hostile LAN device controls the names that
land there — only needs the owner to ask any /api/ask question while the
poisoned alert is in the 24h context window; the model can then launch
port scans / a Nuclei run the owner never clicked. Every other active
action is approval-only by design (quarantine is click-only, dashboard
scan buttons are owner POSTs); model-initiated scans remain the one
exception.
Verified: source re-read at HEAD 75ffce6; the registry, the invoke call,
and the context query are byte-for-byte the shapes flagged last cycle. No
owner-confirmation step has been added.
Concrete fix: split the registry by effect. Read-only tools
(get_alerts/get_devices/get_scan_status/lookup_threat_intel/
get_pipeline_health/get_incidents) may auto-run; `scan` must return a
pending proposal that executes only after an owner POST from the
dashboard (the quarantine pattern). At minimum drop `nuclei` and `amass`
from the model-reachable scanner enum and leave the model the read-only
set plus the passive self port scan.

### S2. STILL OPEN (2026-11-01 M2; 2026-10-25 security M3) — owner password and session cookie cross the LAN in cleartext HTTP on a non-loopback bind; no warning is ever printed
- netmon/dashboard.py:42-46: `"Secure is deliberately NOT set: the
  dashboard binds LAN/localhost over plain HTTP"`;
  `SESSION_COOKIE_HTTPONLY`/`SAMESITE` are set at dashboard.py:45-46,
  Secure is not.
- netmon/run.py:223-231 `_bind_allowed`: any non-loopback bind is allowed
  with any dashboard password set; netmon/run.py:433-434 serves plain
  HTTP: `dash.app.run(host=args.host, port=args.port, use_reloader=False,
  threaded=True)`; netmon/run.py:404 prints only
  `Dashboard: http://{args.host}:{args.port}` — no cleartext warning at
  startup, none on the login page (LOGIN_HTML, dashboard.py:401ff).
What is wrong: unchanged from 2026-11-01. The password check itself is
strong (hmac.compare_digest, dashboard.py login; rate-limited,
dashboard.py `_login_allowed`), but on a `0.0.0.0` bind the login POST and
every subsequent owner session cookie travel unencrypted. The product's
own threat model is a hostile LAN — it exists to detect ARP spoofing —
and any on-path device (the exact attacker brutedash alerts on) can
harvest the owner password or steal the live session and take full
control: quarantine/release, scan triggers, settings, AI spend.
Verified: source re-read at HEAD; no warning text and no TLS option have
been added since 2026-11-01.
Concrete fix: (1) minimum, this cycle — when the bind host is
non-loopback, print a loud startup warning ("password and session cross
this network unencrypted — prefer 127.0.0.1 + SSH tunnel, or enable TLS")
and show the same line on /login. (2) proper fix — optional TLS serving
(operator self-signed cert paths in config, `ssl_context` on app.run)
with SESSION_COOKIE_SECURE flipped on when TLS is enabled.

## Low

### S3. NEW (residual of the 2026-11-01 L1 fix) — netmon/health.py:191-194 — diagnostics `_scrub()` still leaks a quoted passphrase that contains the *other* quote character
The 2026-11-01 fix made the KV value pattern consume a quoted string
whole — `(?:["'][^"']*["']|\S+)` — but the character class `[^"']`
excludes BOTH quote characters, so a value quoted with one quote and
containing the other terminates early at the embedded quote. A passphrase
like `don't tell anyone` — apostrophes are common in passphrases — leaks
everything after the apostrophe into `config.redacted.yaml`
(health.py:265-266) and the scrubbed log tail (health.py:279) in a bundle
whose contract is "never includes secrets" and which is designed to be
emailed to support.
Verified experimentally against the shipped function at HEAD:
`_scrub('owner_password: "don\'t tell anyone"')` leaves `tell` and
`anyone` in the output; same leak for the JSON shape
`{"password": "don't tell anyone"}` and for a single-quoted YAML value
containing a double quote (`'say "hi" loudly now'` leaks `loudly now`).
The plain multi-word shapes fixed last cycle (`"alpha bravo charlie"`)
re-test clean, and every test in tests/test_redaction.py still uses
values with no embedded opposite quote, so the suite is green while this
shape leaks. Preconditions are the same narrow ones as L1 (secret in
config.yaml as a quoted passphrase containing the opposite quote, owner
then shares a bundle) — hence Low.
Concrete fix: make the quoted alternative quote-specific so the closing
quote must match the opening one: `(?:\"[^\"]*\"|'[^']*'|\S+)` in
`_SECRET_KV_RE`. Add regression tests to tests/test_redaction.py for an
apostrophe inside a double-quoted value and a double quote inside a
single-quoted value, asserting no word after the embedded quote survives.

### S4. NEW — netmon/nuclei.py:105,295 and netmon/amass.py:114,251 — third-party scanner subprocesses inherit the monitor's full secret environment
Neither scanner module passes `env=` to `subprocess.run`, so every
invocation of the nuclei and amass binaries — the version probes
(nuclei.py:105, amass.py:114) and the scans themselves (nuclei.py:295,
amass.py:251) — inherits the whole process environment: `OPENAI_API_KEY`,
`ABUSEIPDB_API_KEY`, `NETMON_SMTP_PASS`, and the dashboard passwords when
they are set via `BRUTEDASH_AUTH_*` env vars (the recommended setup in
netmon/config.py). Amass states the passthrough as a choice
(netmon/amass.py:249-251 comment: "Env passes through untouched"), but
Amass reads its data-source keys from its own config file, not from
brutedash's variables — nothing in either tool needs brutedash's secrets.
What is wrong: these are internet-downloaded third-party binaries (and,
for nuclei, a binary that loads template metadata and phones home for
version checks unless told otherwise). A compromised or merely
over-curious scanner build — or anything it spawns — can read every
secret the monitor holds straight out of its own environ. The OS-binary
subprocesses (dpkg-query, netstat, tasklist, git) carry the same
inheritance but are platform-trusted; the downloaded scanners are the
exposure worth closing.
Verified: grep at HEAD shows no `env=` argument anywhere in nuclei.py or
amass.py; all four call sites are plain `subprocess.run(argv, ...)`.
Concrete fix: build a scrubbed environment for both modules' subprocess
calls — copy `os.environ` minus any name matching
`*KEY*|*TOKEN*|*SECRET*|*PASSWORD*|*PASS*` (keep PATH/HOME/SystemRoot so
the binaries still run) — and pass it as `env=` at all four call sites.
Add a test asserting a sentinel secret env var is absent from the child
environment for both version probes.

### S5. STILL OPEN, previously accepted debt — ipintel.py:29,61-63 — IP intel is still fetched over plaintext HTTP and the response still feeds the LLM prompt
`API_URL = "http://ip-api.com/json/{ip}?fields=..."` (ipintel.py:29),
fetched with `urllib.request.urlopen(req, timeout=5)` (ipintel.py:63).
The returned country/org string is interpolated into brief evidence in
app.py and into the rendered rule-based brief.
Status, honestly: unchanged known constraint documented in ipintel.py's
own header (the free endpoint refuses HTTPS), partially mitigated —
64 KB response cap, brief output schema-validated in app.py, rendering
Jinja-escaped (verified, see Non-findings), and this cycle's negative
cache means a spoofed/down endpoint is retried at most once per IP per
10 minutes. Remaining exposure is (a) confidentiality: every investigated
IP is disclosed in cleartext to ip-api.com and any on-path observer, and
(b) integrity: a spoofed response can still steer brief *wording* via the
prompt, though it cannot escape the validated brief shape. Not new;
flagged so the cycle record shows the debt is still carried.
Concrete fix: unchanged from the staged Tier 2 proposal — move enrichment
to a keyed HTTPS provider (or a local GeoIP database) and retire the
plaintext endpoint; until then, no further mitigation is available in
this file.

## Non-findings (checked this cycle, clean)

- SQL injection — CLEAN. Every query in app.py, ipintel.py and netmon/ is
  parameterized. The only f-string SQL is netmon/db.py:546,576
  (`ALTER TABLE alerts ADD COLUMN {col}`) where `col` iterates fixed
  literal tuples in the same function; the dashboard's dynamic SQL builds
  only `?`-placeholder strings from a list length (api_device) or fixed
  column-name constants (_ALERT_COLS*). db.query() callers pass fixed
  strings.
- Command injection — CLEAN. No `shell=True`, `os.system`, `os.popen`,
  `eval` or `exec` in production code (grep-verified). All subprocess
  calls are argv lists against fixed binaries: nuclei re-validates every
  target as RFC1918/loopback in build_argv and passes targets via a `-l`
  file; amass re-validates with valid_domain(); scan._ok_target accepts
  only loopback + explicit RFC1918 (IPv6 refused); selfcheck/swaudit/
  watchdog/relay use constant argv against OS binaries. (The environment
  those argv calls inherit is S4 — a secrets issue, not injection.)
- XSS — CLEAN. Flask `render_template_string` autoescape covers app.py's
  brief/history output and the dashboard's PCAP result page (the
  attacker-controlled pcap filename renders through `{{ filename }}`).
  Dashboard JS routes LAN-derived strings through `esc()`
  (netmon/dashboard.py) — full re-audit this cycle of every `${}`
  interpolation in the 4301-line file: every unescaped interpolation is
  a numeric id/count/port/byte value or a server-side enum; alert text,
  device names, hostnames, intel fields, escalation addresses, and AI
  verdict text (cached verdicts are re-escaped at render) are all
  esc()'d. Server-side generators escape independently: reporting
  compliance_html (html.escape throughout) and compliance_csv
  neutralizes spreadsheet formula injection (`_csv_safe`,
  reporting.py:939), pdfgen escapes PDF literal strings (`_pdf_escape`),
  the playbook route html.escapes all guide text and validates the slug
  before use.
- Auth / authz (dashboard) — CLEAN apart from S1/S2. Full route-table
  re-audit at HEAD: every POST/DELETE mutating route carries
  @_owner_required; the only bulk downloads (compliance HTML/CSV, weekly
  and incident PDFs, rewind .pcap export) are all owner-gated now;
  /api/intel/ip gates its off-box enrichment (AbuseIPDB + reverse DNS)
  to the owner while viewers keep the local rap sheet; /ask page and
  /pcap are owner-gated. Login uses hmac.compare_digest,
  session.clear() before the role is set (fixation-safe), the role comes
  only from the server-side password check, and the login limiter's
  5-minute block is real. app.py demo has no auth by design (public
  Render demo, ephemeral DB, no key configured in render.yaml) and binds
  loopback when run directly.
- CSRF — CLEAN. Server-side cross-site mutation gate
  (netmon/dashboard.py `_cross_site_mutation_check`: Sec-Fetch-Site
  cross-site or non-matching/opaque Origin → 403 on POST/PUT/PATCH/
  DELETE) in front of SameSite=Lax + HttpOnly session cookies; logout is
  POST-only.
- Secrets handling — CLEAN apart from S3/S4. No hardcoded credentials in
  tracked source. All keys come from the environment only:
  OPENAI_API_KEY, ABUSEIPDB_API_KEY (netmon/threatintel.py
  `_abuseipdb_key`, sent only in an HTTPS request header, never
  logged/stored), NETMON_SMTP_PASS (netmon/notify.py `_smtp_config`).
  SMTP sends use starttls() (notify.py, weekly.py, escalate via notify).
  Email header injection is handled: LAN-derived titles/details pass
  notify._clean (CR/LF stripping, netmon/notify.py:127) before reaching
  subjects/bodies in notify, escalate and reporting.
- File permissions — CLEAN. Verified live on this machine: netmon.db,
  detections.db and ~/.config/brutedash/config.yaml are all 0600; the
  self-heal chmod runs on open in netmon/db.py, app.py get_db(),
  ipintel.py _db(), and netmon/config.py load(); diagnostics bundle dir
  is chmod 0700 (netmon/health.py:234); rewind dir/segments 0700/0600;
  canary bait file 0600. .gitignore excludes *.db/.env/venv and the
  generated caplet; `git ls-files` contains no database, .env, or
  credential file.
- SSRF / feed fetching — CLEAN. threatintel._fetch_url enforces the feed
  host allowlist before the fetch AND on the post-redirect final URL,
  with a 5 MB cap; the heartbeat URL is scheme-allowlisted to http/https
  (netmon/health.py `_heartbeat_url_ok`) and never logged; relay's UDP
  connect to 8.8.8.8 sends no payload (local-address discovery only);
  ingest reads only allowlisted-extension regular files directly inside
  the configured watch dir and refuses symlinks escaping it
  (ingest.py `_safe_files`). ipintel is the sole plaintext exception —
  that is S5.
- Path traversal — CLEAN. Report/re­wind filenames are built only from
  validated ints/whitelisted periods and passed through an
  alnum/`-_.` filter; the pcap upload and rewind export use
  NamedTemporaryFile paths chosen by the OS; templates.load_templates
  reads only `*.yaml` names from os.listdir of its own directory;
  detector rotated-sibling names are constructed (`<base>.<n>[.gz]`),
  never globbed from input.
- LLM sinks other than S1 — CLEAN. No model output reaches SQL, a shell,
  a file path, or an email address. Tool-server validation rejects
  unknown tools, unknown parameters, and out-of-scope targets before
  execution (netmon/tools.py invoke/_validate_params/_scope_check), and
  lookup_threat_intel is local-only by construction (never spends the
  AbuseIPDB key on a model request). Prompts are fixed templates; the
  /api/ask question is capped at 2000 chars at the route and truncated
  again in ai_assist.answer_question; every LLM response is
  schema-validated before use (app.py _validate_brief, explainer
  _validate, ai_assist _validate_verdict / _validate_qa_response). AI
  spend is rate-limited per IP on /api/ask, /api/triage, /explain, /pcap
  and demo /brief, with X-Forwarded-For deliberately not honored on
  these direct-bind servers.
- XML / log ingestion — CLEAN. netmon/ingest.py `_declares_entities`
  rejects any Windows event-log XML declaring `<!ENTITY` before
  ElementTree parses it, and the parser is now streaming iterparse with
  per-Event clear; firewall-log parsing is field-validated; config
  loading uses yaml.safe_load only (netmon/config.py load()); the
  templates/ YAML-subset parser rejects anchors/tags/flow syntax by
  construction and templates are data-only (matcher engine is fixed
  code).
- Quarantine safety — CLEAN. request_quarantine enforces the blocklist
  server-side (never the gateway, never this box, never the browsing
  viewer's device — netmon/quarantine.py safety_check), requires an
  owner dashboard POST, and audit-logs granted/refused/released alike.
  No autonomous quarantine path exists.
- Data leaving the machine (inventory, no new finding beyond S1/S5) —
  OpenAI API (only when the owner sets OPENAI_API_KEY; payloads are the
  aggregated evidence blocks in explainer/ai_assist/app.py — traffic
  metadata and alert text, no packet contents), AbuseIPDB (owner-gated,
  HTTPS, 50/day budget), the three allowlisted threat feeds + CISA KEV
  (GET-only downloads), ip-api (S5), healthchecks.io heartbeat (URL only,
  no payload data), owner-configured SMTP (alerts/digests/escalations to
  owner/admin addresses only), Fontshare font CSS on dashboard page
  loads (documented in the CSP comment, netmon/dashboard.py
  DASHBOARD_CSP). swaudit's software inventory is local-only as claimed.
- Dependencies — pinned in requirements.txt; the only change since last
  cycle is openai 3.42.0 → 3.46.0 (2026-11-06, additive per its
  changelog). No version is claimed vulnerable here: no advisory was
  verified in this review, so none is asserted.
