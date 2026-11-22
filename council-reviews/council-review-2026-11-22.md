# Council review 2026-11-22 — head synthesis

Weekly standing session. 3 independent reviewer subagents convened in
parallel (security, plain-language UX, robustness), each returning
structured, source-verified verdicts at HEAD 37f9339. Verdict files:
review-2026-11-22-security-verdict.md, review-2026-11-22-ux-verdict.md,
review-2026-11-22-robust-verdict.md (same directory).

All three seats: NEEDS WORK. No Critical findings this cycle.

## What changed since 2026-11-15

Only the ARTEX batch (552da16, 2026-11-17: detect_cadence +
detect_key_events in detector.py, llm_egress in netmon/detect.py),
dependency bumps (openai, PyYAML 6.0.4), and UX U9 (c6fa73c, verified
FIXED by both the UX and security seats). Every new High/Medium this
cycle lives in the ARTEX code. Prior-cycle items verified FIXED:
robustness N1/N2/R9/R10/L3, security S3/S4 residuals.

## Top findings by seat

- Security: no Critical/High. S1 (AI tool loop scans on model say-so)
  and S2 (cleartext HTTP on LAN bind) still open verbatim — both
  feature-sized, staged since 2026-11-01. NEW Medium S6: the
  unauthenticated demo scan in app.py persisted first-seen SSH key
  state (state_path=KEY_STATE_PATH), so anyone reaching the public
  demo could pre-seed a fingerprint and suppress its first-seen
  alert, or evict legitimate history. NEW Low S7: key-state tmp file
  briefly world-readable before chmod.
- Robustness: 2 High, both reproduced, both ARTEX — H1:
  username-enumeration scan is O(n^2) (20k failures/one IP = 11.75s;
  ~2-3 min at the 10MB demo cap). H2: _collect_events reads
  oldest-first, so the 64MB cap can starve the primary (freshest)
  log entirely (reproduced: 61 sibling events, 0 primary, burst
  missed). Mediums M1 (type-wrong key-state JSON crashes the pass),
  M2 (an empty rotated sibling counts as key history — first-seen
  storm after rotation), M3 (llm_egress baseline too weak/permanent),
  M4 (key-state saves race on one fixed tmp path, no lock).
- UX: no Critical. U1/U2 Highs still open (feature-sized). NEW High
  U11: the ARTEX "SSH key visibility" coverage section orders the
  user to edit sshd_config. NEW Medium U12: the demo results header
  "Failed attempts" mislabels the new kinds' counts. U10 (Low,
  retention labels) still open.

## Quorum mapping

The key-state surface is flagged by 2 of 3 seats (security S6/S7 +
robustness M1/M2/M4) — literal quorum. H1/H2 are single-seat Highs,
reproduced by the seat and re-verified by the head against source
and the seat's repro numbers, adopted on head agreement per the
standing pattern for disjoint lenses. The shipped batch is one
coherent surface: the ARTEX passes in detector.py plus the demo
call site in app.py. UX U11/U12 touch the same demo surface but are
copy changes in strings that existing tests pin verbatim
("plant-a-key", "CANNOT see new keys"); they are staged for the
daily-build queue rather than mixed into this correctness batch.

## SHIPPED (this batch) — "the ARTEX passes must survive real logs"

1. **Robustness H1 (High)** — detector.py detect_cadence: username
   enumeration is now a sliding window with incremental per-user
   counts; the best window's user set is snapshotted only when the
   distinct count improves. Same findings, linear time.
2. **Robustness H2 (High)** — detector.py _collect_events: the
   primary log is read first into its own list under the cap;
   siblings are read oldest-first under the remaining cap; the
   merged result stays chronological, and the primary's syslog
   events are year-shifted when the cross-source New-Year wrap
   applies (the 2026-11-17 year-wrap test still passes).
3. **Robustness M1 (Medium)** — _load_key_state drops entries whose
   value is not a dict with a numeric-or-None first_seen;
   _save_key_state sorts through a coercing key and swallows
   TypeError/AttributeError/ValueError as well as OSError.
4. **Robustness M2 (Medium)** — has_history now means key history:
   non-empty persisted state, or a sibling that actually contributed
   a fingerprinted key event. An empty/unreadable sibling no longer
   defeats the baseline run.
5. **Robustness M4 (Medium) + Security S7 (Low)** — a module-level
   lock serialises the whole state-dependent pass in
   detect_key_events; saves use a per-writer unique tmp name created
   with mode 0600 from the start.
6. **Security S6 (Medium)** — app.py: the unauthenticated demo scan
   no longer persists key state (KEY_STATE_PATH removed;
   detect_key_events called with no state_path, in-log sibling
   history only).

Tests: tests/test_council_20261122.py (7 tests) — best enumeration
window after the first expires; 20k-failure log scans in <4s (was
~12s); a .gz sibling inflating past a shrunken cap cannot starve
the primary's burst; type-wrong state entries are dropped without
crashing; a 0-byte sibling is a baseline run; 8 concurrent threaded
passes all land their keys in one valid 0600 state file; app.py
source carries no state_path for the demo scan.

## STAGED for next cycle (verified, not this batch)

- Security S1: split the AI tool registry by effect (owner-confirmed
  scan proposals). Security S2 minimum: loud cleartext warning on
  non-loopback bind + login page.
- Robustness M3: llm_egress established-user baseline needs sustained
  use / expiry. Lows L1 (syslog timestamp range validation), L2
  (same-ts ceiling escape), L3 (scanner single-line materialisation),
  L4 (llm_egress correlation scope/time), L5 (triple log re-read).
- UX U11 + U12 (seat-recommended batch, one demo surface), U10,
  then U1/U2 as feature work; U3-U8 as listed in the UX verdict.

## Verification

- py_compile on touched files: clean.
- Full suite: 1,099/1,099 green on venv python (1,092 baseline + 7
  new), three consecutive runs; clean HEAD baseline in a separate
  worktree also green (1,092). One earlier run in this session
  reported 1,107 tests with failures — it collected 8 tests that do
  not exist in the tree (a reviewer scratch file present in tests/
  at that moment); no subsequent run reproduces it.
- Smoke boot on a scratch tree copy (port 5087, fresh HOME/DB):
  /api/stats 200, / 200; scratch removed, server confirmed stopped.
- Staged-diff secret scan + audit_llm_sinks + release gate: see
  DEVLOG entry for this date.
