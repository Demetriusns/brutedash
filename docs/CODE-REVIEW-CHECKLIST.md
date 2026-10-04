# brutedash code-review checklist (Dev-QA loop review sheet)

Adapted from `~/workspace/skills/review-checklists/` (ai-code-audit,
code-review, detection-rule) and tailored to this repo. Referenced from
PHASE4-NOTES.md's continuous-testing & council-review section.

Severity: 🔴 blocker (must fix before commit) · 🟡 suggestion (should fix) ·
💭 nit (nice to have). Default stance: **NEEDS WORK unless the evidence
proves otherwise**. Every finding needs file:line, the exploit or failure
mode, and the concrete fix. Hallucinated findings get refuted against
source, never fixed blindly. One complete pass, no drip-feed.

## 🔴 Blockers

**Injection & XSS**
- [ ] No f-string / `+` / `%` interpolation into SQL -- every `dbm.query` /
      `execute` call uses `?` placeholders. (The one exception: ALL_CAPS
      module constants like `_ALERT_COLS` in the query string are fine.)
- [ ] Every dynamic value interpolated into dashboard HTML goes through
      `_html.escape()` / `esc()` -- device names, hostnames, alert titles,
      DHCP strings, mDNS names are all attacker-influenced.
- [ ] No `subprocess` with `shell=True`, no `os.system()` -- argv lists
      only (see `netmon/amass.py build_argv` for the pattern).
- [ ] No `eval()` / `exec()` on alert, network, or config data.
- [ ] No hardcoded secrets (API keys, tokens, DB URLs) anywhere --
      environment variables only. Gitleaks is the enforcer; the review is
      the backup. Every leaked-secret finding names the ROTATION step.

**Prompt-injection sinks (AI narrates, code decides)**
- [ ] Untrusted text (alert fields, hostnames, domains, DNS strings) NEVER
      reaches the model as instructions -- only as delimited user-role
      content (see `ai_assist.TRIAGE_PROMPT`'s ALERT:/EVIDENCE: blocks).
- [ ] Every NEW prompt template / LLM call path has an output-contract
      validator (JSON-schema check like `_validate_verdict`) -- the model
      never decides what's malicious, and its output is never trusted raw.
- [ ] Only alert metadata and flow summaries leave the site -- never packet
      contents, never PII (free tiers may train on prompts).

**Auth & approval-only response**
- [ ] Every new dashboard route is behind the login gate (fail-closed LAN
      binding and the 429 rate limiter still hold).
- [ ] Response stays approval-only: no autonomous quarantine/block/scan
      without his explicit click. A new auto-action is a blocker by his
      standing rule, not a feature.

**Data safety & concurrency**
- [ ] No data-loss risk: migrations are additive/guarded, no destructive
      overwrite, no unbounded DELETE. Rollback on failure for multi-step
      writes (see `learn.py`'s savepoint discipline).
- [ ] Shared state goes through the DB lock in a consistent order --
      no lock-order inversions, no unlocked mutation, no silent
      `except: pass` on critical paths.

**Contracts**
- [ ] No broken API contracts: unchanged route shapes, unchanged function
      signatures consumed elsewhere, dashboard JS still matches the JSON
      the endpoints send.

## 🟡 Suggestions

**Detection-rule review (per rule touched)**
- [ ] Targets attacker BEHAVIOR, not just expiring IOCs.
- [ ] Mapped to a MITRE ATT&CK technique in `netmon/mitre.py` (new kinds
      extend the map; backfill considered for old rows).
- [ ] False-positive profile documented: what benign activity triggers it?
- [ ] Thresholds justified -- why N in M minutes? No magic numbers.
- [ ] Kill-chain coverage considered vs. existing rules (overlap / gaps).
- [ ] Evasion considered: "how would I evade this?" -- then detect the
      evasion too.
- [ ] Alert text is plain English first, technique ID second (his voice
      rule -- also: no medical/doctor language in UI copy, ever).
- [ ] New rule has a validation test proving it fires (Strix pattern:
      detection rules prove they fire, not just exist).

**Quiet is a feature**
- [ ] Does this change make tomorrow quieter? New alerts wire into the
      dismissal-learning hook; noisy rules get tuned or retired, not
      shipped. Cooldowns / per-entity caps on anything that can re-fire.

**Boundaries**
- [ ] Input validation on every external boundary (routes, config, feeds,
      file ingestion, Amass JSONL).
- [ ] Tests run against scratch DBs only -- `netmon.db` (his live data)
      is never touched by the suite or the smoke boot.
- [ ] Served JS passes `node --check` (endpoint-only smoke tests miss
      template-string syntax errors -- the 2026-10-03 lesson).
- [ ] No new pip dependencies without his call (stdlib + pinned
      requirements only).
- [ ] Performance: no N+1 queries, no unbounded loops, feed refreshes keep
      their backoff instead of hammering a dead network.

## 💭 Nits

- [ ] Naming and logic clarity -- will this read clean in 6 months?
- [ ] Duplication that should be extracted.
- [ ] UI copy: brief, natural, plain-spoken -- nothing that sounds
      AI-written; no compliance percentages, no "% secure".

## Rules of the review

- Be specific: "SQL injection on line 42 via f-string" not "security issue".
- Explain why, suggest don't demand, praise good code.
- Scan → fix → rescan: the rescan proves resolved / still-present /
      newly-introduced.
- Report what was checked and what wasn't.
- Read-only by default: the reviewer reports; the builder applies fixes.
