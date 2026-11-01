# Council review 2026-11-01 — SECURITY seat verdict (brutedash / Project Orion)

Read-only review at git HEAD `af51f64`. Scope read in full or audited in source:
app.py, detector.py, ipintel.py, netmon/*.py (dashboard, config, db, tools,
ai_assist, explainer, threatintel, health, notify, escalate, reporting,
weekly, scan, nuclei, amass, selfcheck, swaudit, watchdog, relay, quarantine,
ingest, learn, pdfgen, run), scripts/audit_llm_sinks.py, install.py,
requirements.txt, render.yaml, .gitignore, .gitleaks.toml.

Prior-cycle de-duplication — verified FIXED in source, not re-flagged:
login 5-minute block now real (f2efaad, cluster logic at
netmon/dashboard.py:489 `_login_allowed`); viewer AbuseIPDB/reverse-DNS burn
closed (ee2b42b, netmon/dashboard.py api_intel_ip owner gate); demo /brief
count clamp + detector IP validation + app.py handle/unlink guards (c2efb18);
`load_cached()` env-fingerprint cache poisoning closed (69a65c3,
netmon/config.py `_env_fingerprint`). The two still-open 2026-10-25 items
(security M2, M3) are re-flagged below as M1/M2 and marked STILL OPEN —
everything else is new this cycle or a clean non-finding.

## Critical

None. No finding at this severity. No SQL injection, command injection,
stored-XSS, or auth-bypass path was found — see Non-findings for the
verified evidence behind that statement.

## High

None. No finding at this severity.

## Medium

### M1. STILL OPEN (2026-10-25 security M2) — LAN-derived alert text reaches the AI tool loop, which executes active scans on model say-so with no owner confirmation
- netmon/ai_assist.py:440-448 — the /api/ask context is built from alert rows whose text is LAN-controlled (DNS/DHCP/mDNS names, device names):
  `"SELECT severity, title, detail, meaning FROM alerts WHERE ts > ?"` → `line = f"  [{sev}] {title}: {detail}"`
- netmon/ai_assist.py:364,384 — model output is executed: `inv = toolsm.invoke(c["tool"], c["params"], requested_by="ai_analyst")`; netmon/ai_assist.py:275-276,498 — up to `MAX_TOOL_ROUNDS = 2` rounds × `MAX_TOOL_CALLS = 3` calls per owner question.
- netmon/tools.py:854-875 — the reachable `scan` tool is an active action, not a read: `name="scan"`, `timeout_s=600, idempotent=False, handler=_tool_scan`; its nuclei branch (netmon/tools.py:764 `_scan_nuclei`) runs template-based probing against the whole inventory.
What is wrong: the registry's schema/scope validation is sound (targets are
inventory-only, RFC1918-checked again in nuclei.build_argv), but validation
answers "is this call well-formed", not "did the owner ask for a scan". A
prompt injection planted in alert detail — a hostile device on the LAN
controls the names that land there — only needs the owner to ask any
/api/ask question while the poisoned alert is in the 24h context window.
The model can then launch port scans / a Nuclei run the owner never
clicked. Every other active action in this product is approval-only by
design (quarantine is click-only, dashboard scan buttons are owner POSTs);
model-initiated scans are the one exception, and netmon/tools.py's own
attack-surface map documents the gain as accepted without an owner
confirmation step ever being added.
Concrete fix: split the registry by effect. Read-only tools
(get_alerts/get_devices/get_scan_status/lookup_threat_intel/
get_pipeline_health/get_incidents) may auto-run; `scan` must return a
pending proposal that executes only after an owner POST from the
dashboard (the quarantine pattern). At minimum drop `nuclei` and `amass`
from the model-reachable scanner enum and leave the model the read-only
set plus the passive self port scan.

### M2. STILL OPEN (2026-10-25 security M3) — owner password and session cookie cross the LAN in cleartext HTTP on a non-loopback bind; no warning is ever printed
- netmon/dashboard.py:42-46: `"Secure is deliberately NOT set: the dashboard binds LAN/localhost over plain HTTP"`; `app.config["SESSION_COOKIE_SAMESITE"] = "Lax"` (HttpOnly is set, Secure is not).
- netmon/run.py:223-231 `_bind_allowed`: any non-loopback bind is allowed with any dashboard password set; netmon/run.py:433 serves it as plain HTTP: `dash.app.run(host=args.host, port=args.port, use_reloader=False, threaded=True)`; netmon/run.py:404 prints only `Dashboard: http://{args.host}:{args.port}` — no cleartext warning at startup, none on the login page.
What is wrong: the password check itself is strong (hmac.compare_digest,
netmon/dashboard.py:444,446; rate-limited login, dashboard.py:489), but on
a `0.0.0.0` bind the login POST and every subsequent owner session cookie
travel unencrypted. The product's own threat model is a hostile LAN — it
exists to detect ARP spoofing — and any device that can ARP-spoof or
otherwise sit on-path (the exact attacker brutedash alerts on) can harvest
the owner password or steal the live session cookie and take full control:
quarantine/release, scan triggers, settings, AI spend. Fail-closed bind
(H1) stopped the *unauthenticated* LAN panel; it did nothing for the
*credential in cleartext* problem, and the deferred-TLS decision has never
been surfaced to the operator at runtime.
Concrete fix: (1) minimum, this cycle — when the bind host is non-loopback,
print a loud startup warning ("password and session cross this network
unencrypted — prefer 127.0.0.1 + SSH tunnel, or enable TLS") and show the
same line on /login. (2) proper fix — optional TLS serving (operator
self-signed cert paths in config, `ssl_context` on app.run) with
SESSION_COOKIE_SECURE flipped on when TLS is enabled.

## Low

### L1. NEW — netmon/health.py:191-194,202-208 — diagnostics `_scrub()` redacts only the first whitespace-delimited token of a secret value; a quoted multi-word password leaks the rest into the bundle
The KV pattern ends in `\S+`:
`r"[\"']?\s*[:=]\s*[\"']?\S+"` (netmon/health.py:191-194), applied as
`text = kv_re.sub(r"\1=***", text)` in `_scrub()` (netmon/health.py:202-208).
The scrubbed output is written to `config.redacted.yaml`
(netmon/health.py:265-266) and to the scrubbed log tail (health.py:279) in
a bundle whose contract is "Never includes secrets" (health.py module
docstring) and which tests/test_redaction.py describes as "designed to be
safe to email to support".
Verified experimentally against the shipped function:
`_scrub('owner_password: "alpha bravo charlie"')` redacts only `"alpha`
and leaves `bravo charlie"` in the output. Every existing redaction test
uses a single-token value (e.g. `'{"password": "VALUE9"}'`), so the suite
is green while the passphrase shape leaks. Preconditions are narrow —
password stored in config.yaml (the template invites it, env vars are
preferred) as a quoted multi-word passphrase, and the owner then shares a
bundle — hence Low, but the leaked remainder is most of the credential.
Concrete fix: make the value alternative consume a quoted string whole:
`(?:[\"'][^\"']*[\"']|\S+)` in _SECRET_KV_RE (and the same shape for the
Authorization pattern is unnecessary — tokens have no spaces). Add a
regression test to tests/test_redaction.py with a multi-word passphrase
asserting no word after the first survives.

### L2. NEW — netmon/dashboard.py:3754,3767 — compliance report downloads are not owner-gated, unlike every other report download; the export policy is inconsistent
`@app.route("/reports/compliance.html")` (3754) and
`@app.route("/reports/compliance.csv")` (3767) carry no decorator, while
`@app.route("/reports/weekly.pdf")` at 3780-3781 and
`@app.route("/reports/incident/<int:iid>.pdf")` at 3793-3794 both carry
`@_owner_required`, and /api/rewind/export was owner-gated in the
2026-10-25 batch for being a bulk download of sensitive data. The
compliance payload is the same class: incident titles and device keys
(netmon/reporting.py:704-726) plus quarantine/escalation actions with
actor and free-text note (netmon/reporting.py:732-737:
`"SELECT mac, ip, state, created_ts, updated_ts, actor, note FROM quarantines ..."`).
What is wrong: bounded, stated honestly — the password gate still
requires *a* signed-in role when auth is on, and the viewer role is by
design "read-only dashboard (sees everything, changes nothing)"
(netmon/dashboard.py:96). The defect is the inconsistency: a read-only
viewer credential can bulk-export compliance HTML/CSV off the box while
the equivalent PDF exports 403, with no comment anywhere explaining why
compliance was exempted. Bulk export is the exfiltration-shaped action
even when the same rows are screen-visible one page at a time.
Concrete fix: add `@_owner_required` to both compliance routes so all
report downloads follow one policy (no-op in no-password mode, like every
other owner gate); if viewer export is genuinely intended, write that
decision in a comment on both routes instead of leaving it silent.

### L3. NEW — netmon/dashboard.py:172,2432-2440 — `/api/health` bypasses the password gate and discloses monitor liveness to any unauthenticated LAN host
The gate exemption: `if request.path in ("/login", "/api/health"): return None`
(netmon/dashboard.py:172). The response is more than a liveness bit:
`{"ok": True, "now": ..., "last_flow_ts": last, "stale": stale}`
(netmon/dashboard.py:2432-2440).
What is wrong: with auth enabled, this is the only data route besides
/login reachable with no credential. Anyone on the LAN learns the
monitor's clock, when traffic last flowed, and — the operationally useful
part for an attacker — whether the sensor is currently stale/blind, i.e.
when it is safe to act unobserved. Nothing inside the product needs an
unauthenticated inbound health route: the external heartbeat is outbound
(netmon/health.py Heartbeat, scheme-allowlisted at health.py:110).
Concrete fix: remove "/api/health" from the gate exemption; if an
unauthenticated probe is ever needed for deployment tooling, return only
`{"ok": True}` with no `last_flow_ts`/`stale` fields.

### L4. STILL OPEN, previously accepted — ipintel.py:28,52-54 — IP intel is still fetched over plaintext HTTP and the response still feeds the LLM prompt
`API_URL = "http://ip-api.com/json/{ip}?fields=status,country,org,proxy,hosting,query"` (ipintel.py:28), fetched with `urllib.request.urlopen(req, timeout=5)` (ipintel.py:54). The returned country/org string is interpolated into brief evidence at app.py:196 (`evidence += f" IP intel: {describe_intel(intel)}."`) and into the rendered rule-based brief at app.py:221.
Status, honestly: this is the known constraint documented in ipintel.py's
own header (free endpoint refuses HTTPS), partially mitigated in
2026-10-20 — 64 KB response cap, brief output schema-validated in app.py,
rendering Jinja-escaped (verified, see Non-findings) — so the remaining
exposure is (a) confidentiality: every investigated IP is disclosed in
cleartext to ip-api.com and to any on-path observer, and (b) integrity: a
spoofed response can still steer brief *wording* via the prompt, though
it cannot escape the validated brief shape. Not a new finding; flagged so
the cycle record shows the debt is still carried.
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
  `eval` or `exec` in production code (grep-verified; matches appear only
  in comments, the release-gate auditor, and test fixtures). All
  subprocess calls are argv lists against fixed binaries: nuclei
  re-validates every target as RFC1918/loopback in build_argv and passes
  targets via a `-l` file; amass re-validates with valid_domain();
  selfcheck's PowerShell calls use constant command strings
  (netmon/selfcheck.py check_services / check_defender_rtp); watchdog's
  ping target comes from the local routing table and travels as one argv
  element (netmon/watchdog.py ping_once).
- XSS — CLEAN. Flask 3.1.3 `render_template_string` autoescape verified
  empirically this cycle (`select_jinja_autoescape(None)` is True; a
  `<script>` payload renders escaped), covering app.py's brief/history
  output (LLM- and intel-derived text included). Dashboard JS routes
  LAN-derived strings through `esc()` (netmon/dashboard.py:919) —
  spot-audited alerts, summary, devices, assets, attack surface, intel,
  scan/nuclei findings, host events, topology SVG: every unescaped `${}`
  interpolation is a numeric id/count/port or a server-side enum.
  Server-side generators also escape independently: reporting
  compliance_html (html.escape throughout) and compliance_csv
  neutralizes spreadsheet formula injection (netmon/reporting.py
  `_csv_safe`), pdfgen escapes PDF literal strings, the playbook route
  html.escapes all guide text.
- Auth / authz (dashboard) — CLEAN apart from L2/L3. Full route-table
  re-audit: every POST/DELETE mutating route carries @_owner_required;
  login uses hmac.compare_digest (dashboard.py:444,446),
  session.clear() before the role is set (fixation-safe), the role comes
  only from the server-side password check, and the login limiter's
  5-minute block is now real (dashboard.py:489). app.py demo has no auth
  by design (public Render demo, ephemeral DB, no key configured in
  render.yaml) and binds loopback when run directly.
- CSRF — CLEAN. Server-side cross-site mutation gate
  (netmon/dashboard.py:151 `_cross_site_mutation_check`: Sec-Fetch-Site
  cross-site or non-matching/opaque Origin → 403 on POST/PUT/PATCH/
  DELETE) in front of SameSite=Lax + HttpOnly session cookies; logout is
  POST-only.
- Secrets handling — CLEAN apart from L1. No hardcoded credentials in
  tracked source (pattern scan clean; the one fixture key is narrowly
  allowlisted in .gitleaks.toml as a release-gate test value). All keys
  come from the environment only: OPENAI_API_KEY, ABUSEIPDB_API_KEY
  (netmon/threatintel.py `_abuseipdb_key`, sent only in an HTTPS request
  header, never logged/stored), NETMON_SMTP_PASS (netmon/notify.py
  `_smtp_config`). SMTP sends use starttls() (notify.py, weekly.py,
  escalate via notify). Email header injection is handled: LAN-derived
  titles/details pass notify._clean (CR/LF stripping, netmon/notify.py:127)
  before reaching subjects/bodies in notify, escalate and reporting.
- File permissions — CLEAN. Verified live on this machine: netmon.db and
  detections.db are 0600, ~/.config/brutedash/config.yaml is 0600; the
  self-heal chmod runs on open in netmon/db.py, app.py get_db(),
  ipintel.py _db(), and netmon/config.py load(); diagnostics bundle dir
  is chmod 0700 (netmon/health.py:234); rewind segments/dir 0600/0700
  (2026-10-25 fix, still in source). SQLite WAL sidecars were tested
  experimentally and inherit 0600 from the main file — no sidecar leak.
  .gitignore excludes *.db/.env/venv; `git ls-files` contains no database,
  .env, or credential file.
- SSRF / feed fetching — CLEAN. threatintel._fetch_url enforces the feed
  host allowlist before the fetch AND on the post-redirect final URL,
  with a 5 MB cap (netmon/threatintel.py _fetch_url); the heartbeat URL
  is scheme-allowlisted to http/https (netmon/health.py:110
  `_heartbeat_url_ok`); relay._default_ip's UDP connect to 8.8.8.8 sends
  no payload (local-address discovery only). ipintel is the sole
  plaintext exception — that is L4.
- LLM sinks other than M1 — CLEAN. No model output reaches SQL, a shell,
  a file path, or an email address. Tool-server validation rejects
  unknown tools, unknown parameters, and out-of-scope targets before
  execution (netmon/tools.py invoke/_validate_params/_scope_check).
  Prompts are fixed templates; the /api/ask question is capped at 2000
  chars at the route and truncated again in ai_assist.answer_question;
  every LLM response is schema-validated before use (app.py
  _validate_brief, explainer _validate, ai_assist _validate_verdict /
  _validate_qa_response). AI spend is rate-limited per IP on /api/ask,
  /api/triage, /explain, /pcap and demo /brief, with X-Forwarded-For
  deliberately not honored on these direct-bind servers.
- Demo app (app.py) hardening — CLEAN. 10 MB body cap, per-IP rate limits
  on both the POST / write path (30/min, 600/h) and /brief, /brief input
  validation (IP parses, count clamped 1..1,000,000, severity enum),
  30-day detections retention + /history LIMIT 500, CSP
  `script-src 'none'` plus nosniff/DENY/no-referrer headers on every
  response, `app.run()` with no debug flag.
- XML / log ingestion — CLEAN. The 2026-10-18 L5 item is closed:
  netmon/ingest.py `_declares_entities` rejects any Windows event-log XML
  declaring `<!ENTITY` before ElementTree parses it; firewall-log parsing
  is field-validated; config loading uses yaml.safe_load only
  (netmon/config.py load()).
- Data leaving the machine (inventory, no new finding beyond L4/M1) —
  OpenAI API (only when the owner sets OPENAI_API_KEY; payloads are the
  aggregated evidence blocks in explainer/ai_assist/app.py — traffic
  metadata and alert text, no packet contents), AbuseIPDB (owner-gated,
  HTTPS, 50/day budget), the three allowlisted threat feeds + CISA KEV
  (GET-only downloads), ip-api (L4), healthchecks.io heartbeat (URL only,
  no payload data), owner-configured SMTP (alerts/digests/escalations to
  owner/admin addresses only), Fontshare font CSS on dashboard page loads
  (documented in the CSP comment, netmon/dashboard.py DASHBOARD_CSP).
  swaudit's software inventory is local-only as claimed (its only network
  input is the CISA KEV download above).
- Dependencies — pinned in requirements.txt (Flask 3.1.3, Werkzeug 3.1.9,
  scapy 2.8.0, openai 3.42.0, PyYAML 6.0.3, gunicorn 23.0.0). No version
  is claimed vulnerable here: no advisory was verified in this review, so
  none is asserted.
