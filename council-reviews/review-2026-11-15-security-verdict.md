# Council review 2026-11-15 — SECURITY seat verdict (brutedash, HEAD 481b417)

Overall: **NEEDS WORK** — no Critical/High. S3/S4 (2026-11-08) verified FIXED; S1/S2 still open verbatim; two new Low residuals; S5 accepted debt unchanged.

## Medium

### S1. STILL OPEN — AI tool loop executes active scans on model say-so, no owner confirmation
- Severity: Medium | Verified: source re-read at 481b417, unchanged
- `netmon/ai_assist.py:440` QA context built from LAN-controlled alert text (`SELECT severity, title, detail, meaning FROM alerts…` — DNS/DHCP/mDNS/device names); `ai_assist.py:384-385` executes model output: `toolsm.invoke(c["tool"], c["params"], requested_by="ai_analyst")`; `ai_assist.py:275-276` `MAX_TOOL_ROUNDS=2 × MAX_TOOL_CALLS=3`.
- `netmon/tools.py:831-875` reachable `scan` tool (`timeout_s=600, idempotent=False, handler=_tool_scan`) dispatches nuclei (inventory-wide probing) and amass (external enumeration). Registry validates shape/scope, not owner intent. Prompt injection in a poisoned alert + any owner `/api/ask` question in the 24h window can launch a scan the owner never clicked. All other active actions (quarantine, dashboard scan POSTs) are owner-only.
- Fix: split registry by effect — read-only tools auto-run; `scan` returns a pending proposal executed only after owner dashboard POST (quarantine pattern). Minimum: remove `nuclei`/`amass` from the model-reachable enum.

### S2. STILL OPEN — Owner password/session cross LAN in cleartext HTTP, no warning, no TLS
- Severity: Medium | Verified: source re-read at 481b417, unchanged
- `netmon/dashboard.py:42-46` `SESSION_COOKIE_SECURE` deliberately unset (HttpOnly/SameSite=Lax set); `netmon/run.py:223-231,279` any non-loopback bind allowed with any password; `netmon/run.py:433-434` `dash.app.run(...)` plain HTTP, no `ssl_context`; `netmon/run.py:404` prints only `Dashboard: http://…`; `dashboard.py:404ff` LOGIN_HTML has no cleartext warning.
- What is wrong: login POST + session cookie unencrypted on a hostile-LAN threat model (the product detects ARP spoofing); on-path attacker harvests password/session → full owner control. Password check itself is strong (`hmac.compare_digest`, rate-limited).
- Fix: (1) loud startup + `/login` warning on non-loopback binds; (2) optional TLS (`ssl_context`, cert paths in config) with `SESSION_COOKIE_SECURE` when TLS enabled.

## Low

### S3-RESIDUAL. NEW — `netmon/health.py:199-205` — `_scrub()` leaks trailing words of an *unquoted* multi-word secret
- Severity: Low | Verified: reproduced at HEAD
- Quoted case is fixed (see Fixed below), but the fallback alternative is still `\S+`: `_scrub("password: don't tell")` leaks `tell`; `_scrub("password: hunter two words")` leaks `two words`. A YAML plain (unquoted) passphrase with spaces in config/log tail therefore partially leaks into the shareable diagnostics bundle (`health.py:276,289`).
- Fix: for known secret keys in config context, redact to end-of-line/value; at minimum document/test that unquoted multi-word values are unsupported, and add regression tests for this shape.

### S4-RESIDUAL. NEW — `netmon/envscrub.py:21` — scrubbed scanner env still passes the heartbeat capability URL (and `AUTH`/`CREDENTIAL`/`WEBHOOK` names)
- Severity: Low | Verified: reproduced at HEAD (`is_secret_name("BRUTEDASH_MONITOR_HEARTBEAT_URL") == False`)
- Markers are only `KEY|TOKEN|SECRET|PASSWORD|PASS`. `BRUTEDASH_MONITOR_HEARTBEAT_URL` (`netmon/run.py:408`) — treated as a secret by `health.py`'s scrub keyword list — passes untouched to nuclei/amass at `nuclei.py:108,299` / `amass.py:117,254`. Anyone holding it can ping/`/fail` the health check and spoof monitor health. Same gap for future `*_AUTH`, `*_CREDENTIAL`, `*_WEBHOOK_URL` vars.
- Fix: add `HEARTBEAT`, `WEBHOOK`, `AUTH`, `CREDENTIAL`, `PRIVATE` to `_SECRET_MARKERS` in `envscrub.py:21`, with a test asserting the heartbeat var is stripped.

### S5. STILL OPEN, accepted debt — `ipintel.py:29,63` — plaintext HTTP to ip-api
- Severity: Low | Verified: unchanged
- `API_URL = "http://ip-api.com/json/{ip}…"`, `urlopen(timeout=5)`. Investigated IPs disclosed in cleartext; spoofed response can steer brief wording (output schema-validated, Jinja-escaped; 64KB cap; 10-min negative cache). Fix unchanged: keyed HTTPS provider or local GeoIP DB.

## Verified FIXED since 2026-11-08 (not re-flagged)

- **S3 quoted-passphrase leak — FIXED** (`e754871`, `health.py:199-205`): quote-specific, escape-aware pattern. Reproduced clean at HEAD for: apostrophe in double quotes, double-quote in single quotes, escaped `\"`, doubled `''`, curly quotes, Bearer header, URL userinfo. `tests.test_redaction` passes.
- **S4 scanner env inheritance (main) — FIXED** (`e754871`): new `netmon/envscrub.py:scrubbed_env()` passed as `env=` at all 4 sites (`nuclei.py:108,299`; `amass.py:117,254`), stripping `OPENAI_API_KEY`, `ABUSEIPDB_API_KEY`, `NETMON_SMTP_PASS`, `BRUTEDASH_AUTH_*`, `NETMON_SECRET_KEY`. `tests.test_scanner_env` passes. Residual is S4-RESIDUAL above only.

## Non-findings (checked at 481b417, clean)

- **SQL injection — CLEAN.** All queries parameterized. Only f-string SQL: `db.py:546,576` `ALTER TABLE … {col}` over fixed literal tuples; `db.py:2925ff` fixed two-string `ORDER BY` chosen by bool; `dashboard.py:3405ff,3429` placeholder-count/`detail LIKE ?` strings only, values bound.
- **Command injection — CLEAN.** No `shell=True`/`os.system`/`os.popen`/`eval`/`exec` in production code (grep-verified). All subprocesses are argv lists to fixed binaries; nuclei/amass/scan targets re-validated (RFC1918/loopback/domain shape).
- **XSS — CLEAN.** Dashboard diff since 75ffce6 is 3 lines (retention label, static string). Flask autoescape + JS `esc()` posture unchanged; no new unescaped LAN-derived interpolation.
- **Auth/CSRF — CLEAN apart from S1/S2.** Re-enumerated all 65 routes: every mutating POST/PUT/DELETE carries `@_owner_required` except `/login` and `/logout` (correct); `_password_gate` exempts only `/login` (`/api/health` gated); cross-site mutation check, SameSite=Lax+HttpOnly, login rate limit, `session.clear()` on login all intact.
- **Secrets in code/git — CLEAN.** No hardcoded credentials; `git ls-files` contains no `.db`/`.env`/key files; keys env-only, AbuseIPDB key sent only over HTTPS header, never logged. Config/DB files on disk are `0600`.
- **SSRF/traversal/file permissions — CLEAN.** `threatintel.py:105ff` feed host allowlist checked pre-fetch and on final redirect URL, 5MB cap; heartbeat scheme-allowlisted (`health.py:110ff,146ff`); ingest symlink/extension guards, rewind/report filename validation unchanged.
- **Data leaving machine — no new paths.** OpenAI (owner key only; traffic metadata/alert text, no packets), AbuseIPDB (owner-gated, HTTPS, capped), allowlisted feeds/CISA KEV, ip-api (S5), heartbeat URL-only, owner SMTP, Fontshare CSS. Dependencies: only `openai 3.46.0→3.51.0` since last cycle; no advisory verified, none asserted.
