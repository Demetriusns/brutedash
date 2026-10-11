# Council review 2026-10-11 — head synthesis

Weekly standing session. 3 independent seats convened (security, plain-language UX,
robustness); all returned source-verified structured verdicts (raw files alongside).

Quorum rule: a finding ships on 2-of-3 seat agreement, or on 1 Critical + head agreement.
**No finding reached 2-seat quorum.** The head (Orion) independently verified the
following in source and agreed they are real bugs or standing-rule violations; they
form this cycle's single focused batch. Everything else is staged below for the next
cycle, with rationale.

## SHIPPED (head-verified, agreed batch)

1. detector.py — primary auth.log could be silently skipped (robustness High).
   `sources = siblings + [primary]` with the 64MB cap consumed oldest-first meant a
   live campaign in auth.log scored silent — a regression from commit 620c2ea.
   Fixed: primary scanned first, never pre-skipped by the getsize cap; byte cap
   applies to siblings only. Verified in source; regression test added
   (`test_primary_never_skipped_by_byte_cap`).
2. detector.py — IndexError on a log line ending with "from " (robustness High,
   empirically reproduced by the seat). The line loop's `except OSError` didn't
   catch it; app.py's paste flow had no guard either -> Flask 500. Fixed with a
   guarded extraction; regression test added (`test_truncated_from_line_no_crash`).
3. netmon/watchdog.py — unguarded dbm.start_outage/end_outage could kill the
   watchdog thread permanently while the dashboard kept rendering the last status
   as live (robustness High). Fixed: try/except around both calls, one stderr
   line, keep pinging, retry bookkeeping next pass. Two resilience tests added.
4. netmon/dashboard.py — "healthy network/device/box" copy in 8 spots (UX High,
   x2 more found by the head). Violates the standing voice rule (doctor metaphor
   internal-only, 2026-10-03). Replaced with plain phrasing.
5. netmon/dashboard.py — raw snake_case alert kind rendered in two detail views
   (UX High), contradicting detection_catalog.py's UI contract. Now kindLabel().
6. app.py — no MAX_CONTENT_LENGTH on the public Render demo (security Medium).
   One-line 10MB cap mirroring the dashboard's M4 pattern.
7. netmon/run.py + netmon/pipeline.py — note_loop_tick docstring/comment honesty
   (robustness Medium): the "stamped even when the disk is full" claim was false
   (full disk -> silent no-write -> watermark "unknown"). Comment corrected.

## STAGED for next cycle (not this batch)

- R5 weekly.py crashes on DB hiccup (robustness Medium): real, but needs a
  broader graceful-degradation pass on the report generator -- own batch.
- S2 app.py /brief unauthenticated LLM spend (security Medium): real hole, but
  only for keyed deployments; the public demo runs keyless by design. Needs the
  per-IP sliding-window gate (dashboard pattern) -- own small batch.
- S3 esc() under-escape (security Low): seat traced every current sink safe;
  future-proofing, cheap -- bundle with the next security touch.
- UX3 MITRE badges (Medium), UX4 "Warden's hit list" (Medium), UX5 "Amass"
  (Medium), UX7 "Nuclei" (Medium), UX8 "Forensic rewind" (Low): all real copy
  issues, kept out to keep this batch focused; UX6 config.yaml dead-ends is
  feature work (Settings-panel fields), not a fix-batch item.
- Watchdog liveness self-alert (robustness seat's second half): the thread can
  no longer die silently from DB errors, but there is still no monitor-loop
  liveness check on the watchdog thread itself -- proposal for the roadmap.

## Verification
- py_compile on all touched files: clean.
- Full suite: 759/759 green on venv python AND plain python3 (99 dashboard skips, no Flask).
- New tests: 2 detector + 2 watchdog resilience, all passing (old code fails them).
- Smoke boot on scratch working-tree copy + fresh DB: /api/stats 200, / 200;
  served page has the new copy, no "healthy" copy remains, node --check on the
  served script PASS.
- Staged-diff secret scan: clean (see commit).
- Pre-push release gate: PASS (S-PROMPTFMT/B-EVAL analyzer lines remain the
  documented pre-existing noise -- no literal eval() in detect.py).
