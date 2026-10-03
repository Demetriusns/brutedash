# Project Orion (brutedash) — Security Review 2026-10-03

Reviewer: subagent, using the agency-agents security division as checklist
source (`security-appsec-engineer`, `security-ai-generated-code-auditor`;
workflow: scan at rest → triage worst-first → line + exploit + fix).
Findings only — no code changed, nothing committed.

Threat model: single-owner home-LAN security monitor. Attackers of
interest: anyone else on the LAN (guests, compromised IoT), plus
malicious network input (crafted DNS, hostile pcaps). Ranked for that
model, not for internet-facing SaaS.

## HIGH

### H1. Dashboard is fail-open: no auth by default, LAN binding unenforced
- `netmon/dashboard.py:41,48` — `NETMON_PASSWORD` unset → `_password_gate`
  returns None → every page and every state-changing API (alert
  ack/dismiss, allowlist add/delete, quiet hours, device rename, digest
  send, pcap upload) is unauthenticated.
- `netmon/run.py:77-82` — `--host` help text *advises* "set
  NETMON_PASSWORD first" before `0.0.0.0`, but nothing enforces it.
  `dashboard.host` in config.yaml / `NETMON_HOST` can bind the LAN with
  zero auth.
- Exploit: anyone on the LAN opens the dashboard, dismisses real alerts,
  allowlists attacker infrastructure, renames devices.
- Fix: fail closed — refuse non-loopback bind unless `NETMON_PASSWORD`
  is set (exit with an error, don't just warn).
- Note: already on the roadmap ("fail-closed LAN binding unless
  NETMON_PASSWORD is set", remaining work #1). This review confirms it
  is the #1 item.

### H2. /login has no rate limiting or lockout
- `netmon/dashboard.py:150-158` — password check uses
  `hmac.compare_digest` (good), but unlimited attempts, no delay, no
  lockout, no attempt logging.
- Exploit: once the dashboard is LAN-reachable, offline-speed online
  brute force of a human-chosen `NETMON_PASSWORD`.
- Fix: per-IP attempt counter with exponential backoff + temporary
  lockout; log failures. (Reduces to Low once H1 is fixed and bind
  stays localhost, but the Tailscale/Phase-5 plan makes this matter.)

## MEDIUM

### M1. `app.py` ships with the Werkzeug debugger enabled
- `app.py:257` — `app.run(debug=True)`. Debug mode = interactive console
  on unhandled tracebacks (PIN-protected in modern Werkzeug, but still
  verbose tracebacks + reloader).
- Current blast radius is small (localhost demo tool), but this is the
  exact pattern that must never be copied into `netmon/run.py` or the
  Phase-5 cloud console. `run.py:184` correctly omits it — keep it that
  way and delete it here.
- Fix: `app.run()` with no debug flag.

### M2. Session cookie travels over plaintext HTTP on the LAN
- `netmon/dashboard.py:25` — no `SESSION_COOKIE_SECURE`,
  `SESSION_COOKIE_SAMESITE`, or `PERMANENT_SESSION_LIFETIME` set.
  Flask defaults: HttpOnly on (good), Secure off, SameSite unset
  (browsers fall back to Lax).
- Exploit: with H1's LAN binding (or Tailscale later), anyone able to
  sniff the LAN (ARP spoofing — literally in this product's threat
  model) steals the session cookie and walks in as the owner.
- Fix: set `SESSION_COOKIE_SAMESITE="Lax"`, short
  `PERMANENT_SESSION_LIFETIME`, and document "TLS via reverse proxy
  before any non-loopback bind" (already planned for Phase 5 —
  gunicorn behind a reverse proxy).

### M3. Unpinned dependencies — supply-chain risk for a security tool
- `requirements.txt` — `Flask>=3.0`, `scapy>=2.5`, `openai>=1.0`,
  `pyyaml>=6.0`. `install.py` runs `pip install -r requirements.txt`
  with no pins or hashes: every fresh install can pull different
  (possibly vulnerable or yanked) versions; builds aren't reproducible.
- Fix: commit a pinned `requirements.txt` (or `pip-compile` output);
  keep the `>=` file as `requirements.in` if desired.

### M4. /pcap upload: no size cap, and it pollutes the production DB
- `netmon/dashboard.py:1245-1272` — `f.save(tmp.name)` with no
  `MAX_CONTENT_LENGTH`; `capm.run_pcap` (`capture.py:315`) parses it
  with scapy. A multi-GB upload = disk/memory exhaustion DoS.
  (Authenticated only when a password is set — see H1.)
- Same route calls `detm.run_all(now=anchor)`, writing pcap-derived
  alerts into the **production** alerts table and firing the notify
  hook — a test capture can page the owner and corrupt baselines.
- Fix: `app.config["MAX_CONTENT_LENGTH"]` (e.g. 100 MB); analyze pcaps
  against a scratch DB.
- Note: scratch-DB isolation is already roadmap item #2 — confirmed.

## LOW

### L1. No CSRF tokens on state-changing APIs
`dashboard.py` POST/DELETE routes (`/api/alerts/<id>/ack|dismiss`,
`/api/allowlist`, `/api/settings/quiet_hours`, `/api/devices/name`,
`/api/digest/send`, `/explain`) rely on the session cookie with no
CSRF token. Browser SameSite=Lax default blunts classic cross-site
CSRF, but explicit `SESSION_COOKIE_SAMESITE="Lax"` + tokens is the
proper fix. Low while single-user/localhost.

### L2. LIKE-wildcard injection in alert cooldown — fail-silent direction
- `netmon/db.py:847` — `recent_alert_kind` builds
  `f"%{key}%"` where `key` can contain `%`/`_` from attacker-influenced
  strings (DNS names, e.g. `check_dns_anomalies`). A crafted name acts
  as a LIKE wildcard → cooldown matches more broadly → **alerts get
  suppressed** (wrong direction for a security monitor).
- Fix: escape `%`, `_`, `\` in the key before building the LIKE pattern.

### L3. Crafted newline in alert titles silently drops notification emails
- Alert titles embed raw LAN strings (DNS names, MACs). DNS labels can
  legally contain `\n`. `notify.py:build_email` →
  `msg["Subject"] = f"[netmon] Needs attention: {title}"`.
- Verified empirically: `EmailMessage` **rejects** the header
  (`ValueError: Header values may not contain linefeed…`) — so no
  header injection occurs — but `_send` raises inside
  `_maybe_send_alert`'s try/except → returns False → **that alert's
  email is silently dropped**. A hostile LAN device can suppress its
  own alert notifications with a crafted DNS name.
- Fix: strip `\r`/`\n` in `build_email`, `build_digest`,
  `build_escalation_email` (one-line sanitize at the boundary).

### L4. Indirect prompt injection via LAN-crafted strings into LLM prompts
- `netmon/ai_assist.py` (`triage_verdict`, `answer_question`) and
  `netmon/explainer.py` embed alert titles/details/DNS names (all
  LAN-influenced) into prompts. A device named
  "Ignore previous instructions…" can steer the narration.
- Bounding factors (verified): outputs are JSON-schema validated
  (`_validate_verdict`, `_validate`, `app.py:_validate_brief`) with
  enum-constrained verdicts — impact is limited to prose, and "AI
  narrates, code decides" means no detection/response decision changes.
  Still worth a sanitizer on network-derived strings before prompt
  assembly.

### L5. `_scrub` misses the heartbeat URL; log tail is unscrubbed
- `netmon/health.py:144-148` — regex only matches
  `key|token|password|secret` followed by `:`/`=`. `heartbeat_url:`
  (a real config key, `config.py:90`, documented as "anyone with the
  URL can fake heartbeats") is **not** redacted from
  `config.redacted.yaml` in diagnostics bundles.
- `orion.log.tail.txt` is written with no scrubbing at all (config
  gets `_scrub`, logs don't) — inconsistent safety net.
- Fix: add `heartbeat|webhook|url` patterns carefully (avoid
  over-redacting), or explicitly redact `heartbeat_url`; run the log
  tail through `_scrub` too. `tests/test_redaction.py` covers the
  current regex — extend it.

### L6. `config.yaml` created with default umask, not 0600
- `netmon/config.py:ensure_bootstrap` writes the config world-readable
  by default on multi-user systems. By design it holds no secrets —
  except `monitor.heartbeat_url` may live there (see L5).
- Fix: `os.chmod(path, 0o600)` after bootstrap.

### L7. app.py `/brief`: unvalidated attacker-controlled fields → LLM prompt
- `app.py:231-237` — `ip`, `count`, `severity` come straight from POST
  form fields (the "Generate brief" buttons post hidden inputs, but
  anyone can POST arbitrary values) into `write_brief` →
  `BRIEF_PROMPT.format(evidence=evidence)`. Prompt injection possible;
  `_validate_brief` constrains the output shape (severity enum,
  non-empty strings), so impact is brief-text only.
- Fix: validate `ip` with the `ipaddress` module, coerce `count` to
  int, check `severity` against `VALID_SEVERITIES` before use.

## Checked and clean

- **SQL injection**: every query in `netmon/db.py`, `dashboard.py`,
  `detect.py`, `app.py`, `ipintel.py` is parameterized. `dbm.query()`
  takes raw SQL but all call sites pass literals. Verified by grep.
- **Command injection**: `relay.py` (`tasklist`/`pgrep`/`ps`) and
  `health.py` (`git rev-parse`) use list-form `subprocess` — no
  `shell=True` anywhere in the repo. `install.py` likewise.
- **Hardcoded secrets**: grep over tracked source found none (only
  test fixtures in `tests/test_redaction.py` and a redacted placeholder
  in `install.py`). Env-var discipline (`OPENAI_API_KEY`,
  `NETMON_PASSWORD`, SMTP creds) is followed; `.gitignore` covers
  `*.db`, `venv/`, `wifimon.local.cap`.
- **Server-side XSS**: `render_template_string` autoescape verified
  empirically ON (Flask). Client-side `esc()` in dashboard JS escapes
  `&` and `<` — sufficient for the text contexts used; the one
  attribute context (`data-mac`) is fed hex-formatted MACs from scapy.
- **Deserialization**: `yaml.safe_load` only; no `pickle`/`eval`/`exec`
  anywhere.
- **Auth compare**: `hmac.compare_digest` on the dashboard password —
  no timing leak.
- **Allowlist writes**: human Apply-click only (`decide_suggestion`);
  learning loop can never silence alerts by itself. Substring-match
  breadth is disclosed in the UI.
- **Temp files**: `NamedTemporaryFile(delete=False)` + `finally:
  os.unlink` in both upload paths; default 0600 perms.
- **Dependencies installed**: Flask 3.1.3, Werkzeug 3.1.9, scapy 2.7.0,
  PyYAML 6.0.3 — current; no known-critical CVE asserted for these
  versions (pin them per M3 so this stays true).

## Not in scope / not checked

- Live DAST (no running instance was attacked); Windows-specific paths
  (bettercap caplet, Npcap) were read, not executed; the Phase-5 cloud
  console doesn't exist yet — re-run this review before it faces the
  internet (it will need the full treatment: TLS, gunicorn, per-site
  API keys, rate limiting).
- `netmon/weekly.py`, `eval_briefs.py`, `gen_log.py` are
  reporting/test-data helpers; skimmed, no network-facing input.

## Suggested fix order

1. H1 (fail-closed bind) + H2 (login rate limit) — one batch, both are
   the LAN-exposure story.
2. M1 (drop `debug=True`), M3 (pin deps), M4 (upload cap + scratch DB).
3. M2 (cookie flags; TLS story rides with Phase 5).
4. L2, L3, L7 (input sanitization at the three boundaries), then
   L4–L6 hardening.
