# Council review 2026-10-18 — head synthesis

Weekly standing session. 3 independent seats convened in parallel
(security, plain-language UX, robustness); all returned structured,
source-verified verdicts (raw files alongside this one).

IMPORTANT PROCESS NOTE: the seat summaries delivered back through the
subagent channel were garbled paraphrases in two cases (invented
routes, tools, and line numbers that do not exist in this tree). The
head discarded those summaries and worked from the verdict FILES the
seats wrote to this directory, verifying every shipped finding in
source personally. Nothing below rests on a delivered summary.

Quorum rule: a finding ships on 2-of-3 seat agreement, or on 1 seat +
head agreement (verified in source / standing-rule violation).

## SHIPPED (this batch)

1. app.py — OpenAI client with no timeout (security M1 + robustness
   R4 — the cycle's only literal 2-seat quorum; rated High by
   robustness). `write_brief()` built `OpenAI(api_key=...)` with no
   timeout, the one call site the 2026-10-04 timeout fix missed
   (ai_assist.py:64 and explainer.py:316 both use timeout=30). A hung
   API call could wedge a sync gunicorn worker (~10 min SDK default;
   the demo runs 2 workers) per /brief request. Fixed: timeout=30.
   Regression test: tests/test_council_20261018.py.
2. netmon/weekly.py — generate_weekly_report crashed on any DB
   hiccup (robustness R9, Medium; staged since 2026-10-11 as R5, now
   scheduled and done). Every query except first_seen was unguarded;
   run.py's --weekly-report path died with a traceback and the owner
   got no report, contradicting the module's own "degrades
   gracefully" docstring. Fixed: each query falls back to an empty
   result via a _q() helper, the report is flagged "degraded", the
   headline and plain-text body say in plain words that some records
   couldn't be read, the busiest-day date parse is guarded, and
   run.py's weekly-report block is wrapped so formatting/polish
   failures print a one-line error instead of a traceback.
   Plain-language part (head-verified in source): the email text
   rendered "{packets:,} packets ({flows:,} separate connections)"
   and talker lines said "Mainly port 443 (tcp): ..." — both now
   plain ("in N separate connections"; "Mostly encrypted web
   browsing..."). The weekly PDF (reporting.py _weekly_pdf) dropped
   its "(N packets)" bullet the same way and gains the degraded note.
   Tests: tests/test_weekly.py (6 tests, new file — weekly had none).
3. "A quiet network is a healthy network" in 3 user-facing spots
   (UX finding 1, High; standing voice rule 2026-10-03 — doctor
   metaphor is internal-only). The 2026-10-11 cycle fixed 8
   dashboard.py spots; the sentence survived in reporting.py:340
   (score explanation — whose own docstring says "never
   medical/doctor language"), reporting.py:524 (morning briefing
   email), and attacksurface.py:832 (attack-surface summary). All
   three now use the approved phrasing: "A quiet network is a good
   sign -- nothing suspicious is going on." Regression tests in
   tests/test_council_20261018.py (the Oct 11 test only covered
   dashboard.py).

## STAGED for next cycle (verified or credible, not this batch)

- Robustness R1-R3 (all High, capture.py): DB I/O on the packet path
  under ScanTracker.lock can kill live capture; sniff() with no
  timeout can hang shutdown / defeat restart on an idle or stalled
  interface; flush() detaches all buffers before writing so one
  failed insert silently discards the rest, with a bare except in
  _flush_loop. These are the next cycle's top priority — they need
  their own focused capture batch with packet-path tests, not a
  drive-by in a mixed batch.
- Security M2 (app.py demo write path: no rate limit / retention on
  POST /, /history renders the whole table), M3 (ipintel.py plaintext
  HTTP + uncapped read — head verified: API_URL is http:// and
  _fetch reads unbounded; fix is https + 64KB cap), L1 (detections.db
  0644 vs netmon.db 0600 — verified live on this machine), L2
  (config.yaml load() never self-heals 0600), L3-L5.
- Robustness R5 (detector.py: truncated/corrupt .gz sibling raises
  EOFError/zlib.error past the except OSError — seat reproduced it),
  R6 (db.py _db() lazy-init race), R7 (ingest per-file stat aborts
  the whole pass), R8 (safe_step bounds exceptions, not hangs),
  R10-R13.
- UX findings 2-14: config.yaml dead-ends (13+ spots; the Settings
  admin-email field is feature work, not a fix batch), MITRE badges,
  Amass/Nuclei brand names + install-command notes, "escalate to
  admin", pcap/Wireshark copy, severity-vocabulary consistency,
  "Forensic rewind", "Warden's hit list", error banners, "Prune now",
  "Follow-up ID", status-code badges, notify/README jargon slips.

## Verification
- py_compile on all touched files: clean.
- Full suite: 817/817 green on venv python (807 baseline + 10 new).
- New tests: 6 weekly + 4 council-batch, all passing.
- Smoke boot on scratch copy + fresh DB: /api/stats 200, / 200;
  --weekly-report CLI printed a full plain-language report and
  exited cleanly; scratch removed.
- Staged-diff secret scan: clean (see commit).
