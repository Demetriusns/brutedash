# Council review 2026-11-15 — head synthesis

Weekly standing session. 3 independent reviewer subagents convened in
parallel (security, plain-language UX, robustness), each returning
structured, source-verified verdicts at HEAD 481b417. Verdict files:
review-2026-11-15-security-verdict.md, review-2026-11-15-ux-verdict.md,
review-2026-11-15-robust-verdict.md (same directory).

All three seats: NEEDS WORK. No Critical findings this cycle.

## What changed since 2026-11-08

The daily builds shipped every staged code item from the last cycle:
S3+S4 (e754871, 2026-11-09), R2 (03116a4, 2026-11-10), R6 (e0d52f0,
2026-11-12), R7 (530ef60, 2026-11-14) — all verified FIXED by the
seats at HEAD. Two of those fixes introduced regressions (below).
No user-facing copy changed except one retention label (UX U10).

## Top findings by seat

- Security: no Critical/High. S1 (Medium: AI tool loop can execute
  active scans on model say-so, no owner confirmation) and S2
  (Medium: cleartext HTTP on a LAN bind, no warning, no TLS) still
  open verbatim — both feature-sized, staged since 2026-11-01. New
  Lows, both reproduced: S3-residual — `_scrub()` still leaks the
  trailing words of an UNQUOTED multi-word secret (`\S+` fallback);
  S4-residual — `envscrub` markers miss HEARTBEAT/WEBHOOK/AUTH/
  CREDENTIAL, so the heartbeat capability URL reaches scanner
  subprocesses. S5 (ip-api plaintext) remains accepted debt.
  Everything else audited clean (SQLi, command injection, XSS, CSRF,
  SSRF, file permissions, secrets in git).
- Robustness: High — N1, a regression from the R2 fix: `_new_events`
  pages the WHOLE backlog into one list per rule and filters in
  Python; a no-match rule never advances its watermark and re-scans
  all history every 5 minutes, synchronously in the monitor loop
  (reproduced: 12,000 non-matching events fetched in full, twice;
  plus O(n²) burst scan and 3 correlation queries per event in
  check_failed_logons). Mediums: N2 — retention holds the global DB
  lock across an entire table prune (regression risk from R7's new
  tables); R9 (carried) — quiet-hours wrap windows check the wrong
  weekday after midnight. Lows: R10 (carried) — nuclei/amass JSONL
  parsing reads the whole file into memory twice; L3 (new) — notify
  worker thread is never restarted if it dies (the pre-fix canary
  pattern).
- UX: no Critical. U1 (High, config.yaml dead-ends) and U2 (High,
  technician-only demo front door) still present, as are U3–U9
  Mediums — all feature/copy work staged since 2026-11-01. New U10
  (Low): the R7 retention rows added jargon labels ("DNS/ARP/hostname
  observations", "Windows host events").

## Quorum mapping

Lenses are disjoint by design, so no finding had literal 2-of-3
overlap and none was rated Critical — the same posture as prior
cycles: the head verified every candidate against source and adopted
the batch on head agreement. Cross-seat corroboration: the scanner
subsystem is flagged by all three seats again (S1/S4-residual,
R10, U4). The shipped batch is the robustness seat's recommended
set — the cycle's only High (N1, reproduced by its seat and
re-verified by the head) plus the four findings that share its
failure shape: one pass, lock, thread, window, or file must not
stall or silently kill the monitor. Every shipped item was
independently re-verified by the head against current source
before implementation.

## SHIPPED (this batch) — "the monitor must keep moving"

1. **Robustness N1 (High)** — netmon/db.py + netmon/ingest.py +
   netmon/run.py: `host_events_since` takes optional source/event_id
   filters applied in SQL with bound parameters (idx_host_events_ts
   serves them); `_new_events` passes the filters through and stops
   at a 20,000-row per-pass ceiling with carry-over — the watermark
   still advances only to the newest event actually processed (R2
   semantics preserved), and the ceiling never strands a row: when
   it lands inside a same-ts group the pass keeps paging until the
   group ends. check_failed_logons correlates once per distinct IP
   (was 3 queries per event) and its burst scan is two-pointer
   (was O(n²)). The monitor loop's ingest step now carries
   `timeout=DETECT_INTERVAL`, like the scanner steps, so an overrun
   detaches instead of wedging the loop. HEAD ADAPT vs the seat's
   fix list: the watermark is NOT advanced to the newest *scanned*
   ts on a no-match pass — with SQL-side filtering a no-match pass
   fetches zero rows into Python, so the wedge is gone without
   re-opening R2's skip hazard for late-stored older events.
2. **Robustness N2 (Medium)** — netmon/retention.py `_prune_table`:
   the shared DB lock is acquired per batch (both the alerts branch
   and the plain branch), never across the whole prune loop.
3. **Robustness R9 (Medium, carried from 2026-11-08)** —
   netmon/notify.py `in_quiet_hours`: a wrapping window's
   before-midnight half is tested against today's weekday and its
   after-midnight half against yesterday's. The start==end
   zero-length case keeps its pre-fix whole-day meaning.
4. **Robustness R10 (Low, carried)** — netmon/nuclei.py +
   netmon/amass.py: `parse_jsonl_file` streams line by line through
   a shared `_parse_jsonl_lines` core under a 256 MB total cap
   (partial findings kept); `parse_jsonl_text` keeps its API for
   tests/callers. No more whole-file read + splitlines copy.
5. **Robustness L3 (Low)** — netmon/notify.py: the worker thread is
   retained (`_worker_thread`); `_ensure_worker` treats "started
   but not alive" as stopped and restarts it, mirroring canary R4;
   `_worker_loop` clears the recorded state in a finally, only when
   it is still the recorded thread.

Tests: tests/test_council_20261115.py (19 tests) — SQL filtering
returns only matches and a 12,000-row no-match backlog fetches zero
rows twice; ceiling carry-over across passes; same-ts group never
stranded; burst fires at the exact 600s edge and stays quiet at
601s; retention acquires the lock per batch (counting-lock wrapper)
and still deletes all 250 rows; quiet-hours Fri 22:00–06:00 covers
Sat 03:00 but not Sun 03:00, Monday windows don't reach back, non-
wrap and no-days windows unchanged; streamed file parse equals text
parse for both scanners, byte cap keeps partial findings, missing
file is []; dead notify worker restarts, live worker is not
replaced.

## STAGED for next cycle (verified, not this batch)

- Security S1: split the AI tool registry by effect — read-only
  auto-run, `scan` becomes an owner-confirmed proposal (feature).
- Security S2: loud startup + login-page warning on non-loopback
  binds (minimum); optional TLS (proper fix).
- Security S3-residual: `_scrub` unquoted fallback redacts to
  end-of-line for known secret keys + regression tests.
  S4-residual: add HEARTBEAT/WEBHOOK/AUTH/CREDENTIAL/PRIVATE to
  envscrub markers + test (one-line fix; daily-build sized).
- UX U1: Settings UI controls (admin-email field + feature toggles)
  — feature work. U2: app.py plain-language copy. U9: Devices Status
  cell shows isolation ahead of Trusted/Probation (small; head
  verified at dashboard.py:1217-1219 — the row already carries
  `v.quarantined`). U10: plain labels for the retention table rows.
  U3–U8 copy items as listed in the UX verdict.

## Verification

- py_compile on all touched files: clean.
- Full suite: 1,042/1,042 green on venv python (1,023 baseline + 19
  new). One pre-existing wiring test (test_robustness_20261025)
  asserted exactly 3 `timeout=DETECT_INTERVAL` call sites in run.py;
  updated to 4 with the N1 rationale — the ingest deadline is the
  deliberate change that test now guards.
- Smoke boot on a scratch tree (tar copy, scratch XDG_CONFIG_HOME,
  fresh DB, port 5001): /api/stats 200, / 200; scratch removed.
- Staged-diff audit: scripts/audit_llm_sinks.py --staged PASS
  (0 blockers / 0 suggestions / 0 nits). gitleaks binary not
  installed on this box; manual staged-diff grep found no secret
  values (one hit is an env-var name in a verdict doc).
