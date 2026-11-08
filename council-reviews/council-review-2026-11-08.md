# Council review 2026-11-08 — head synthesis

Weekly standing session. 3 independent reviewer subagents convened in
parallel (security, plain-language UX, robustness), each returning
structured, source-verified verdicts at HEAD 75ffce6. Verdict files:
review-2026-11-08-security-verdict.md, review-2026-11-08-ux-verdict.md,
review-2026-11-08-robust-verdict.md (same directory); robustness
reproductions: repro-2026-11-08-robust.py.

All three seats: NEEDS WORK. No Critical findings this cycle.

## Top findings by seat

- Security: no Critical/High. Two Mediums still open verbatim from
  2026-11-01 — M1/S1 the AI tool loop can execute active scans
  (nuclei/amass) on model say-so with no owner confirmation; M2/S2
  owner password/session cross the LAN in cleartext HTTP on a
  non-loopback bind with no warning ever printed. New Lows: S3
  diagnostics _scrub() leaks a quoted passphrase containing the OTHER
  quote character (residual of the 2026-11-01 L1 fix, reproduced);
  S4 nuclei/amass subprocesses inherit the monitor's full secret
  environment (no env= scrubbing at 4 call sites). S5 ip-api plaintext
  HTTP remains accepted debt. Everything else audited clean (SQLi,
  command injection, XSS, CSRF, file permissions, SSRF, traversal).
- Robustness: High — R1 run_live sets the caller's SHARED stop_event
  in its finally when sniff() raises: one transient Npcap/driver
  error permanently kills capture AND the monitor loop and defeats
  the capture-restart watchdog (reproduced). Mediums, all
  reproduced: R2 ingest rules skip the oldest events of any backlog
  over 5,000 and advance the watermark past them forever; R3
  nuclei/amass stamp "last run" at launch (staged leftover — one
  failed scan eats the weekly slot); R4 canary dead listener thread
  never restarts (start() trusts the running flag); R5 selfcheck
  learns an EMPTY listening-port baseline on Windows when netstat
  fails, then flags every real port as drift; R6 rewind
  enforce_caps can unlink the actively-written segment when
  rewind_minutes < 5. Lows: R7 host_events/device_hostnames never
  pruned (staged leftover, still present); R8 reverse_dns caches a
  failed/timed-out lookup as a definitive empty answer for 7 days;
  R9 quiet-hours wrapping windows check the wrong weekday after
  midnight; R10 nuclei/amass JSONL parsing reads the whole file
  into memory twice.
- UX: no Critical. Zero user-facing copy changed since 2026-11-01,
  so every prior item is STILL PRESENT: U1 (High) 15 "edit
  config.yaml" dead-ends (count grew), incl. the Escalate
  admin-email flow; U2 (High) app.py demo front door technician-only.
  Mediums: U3 MITRE badges, U4 Amass/Nuclei names + install commands,
  U5 "escalate to admin", U6 pcap/Wireshark/forensic wording +
  garbage file presented as a clean 0-packet result, U7 severity/
  state vocabulary split (widened: filter labels, sevBadge, Nuclei
  table, digest email), U8 unexplained "Probation" badge. NEW U9
  (Medium): a quarantined device still shows "Trusted" in the
  Devices table — isolation state invisible in the Status column.

## Quorum mapping

Lenses are disjoint by design, so no finding had literal 2-of-3
overlap and none was rated Critical — the same posture as the
2026-10-04 and 2026-11-01 syntheses: the head verified every
candidate against source and adopted the batch on head agreement.
Cross-seat corroboration exists at the subsystem level: all three
seats flag the nuclei/amass scanner subsystem (S1/S4, R3/R10, U4).
The shipped batch is the cycle's highest-severity finding (R1,
High, reproduced by its seat and re-verified by the head) plus the
four reproduced Medium/Low findings that share its exact failure
shape — a transient failure becoming a permanent outage. Every
shipped item was independently re-verified by the head against
current source and by experiment before implementation.

## SHIPPED (this batch) — "a transient failure must not become a permanent outage"

1. **Robustness R1 (High)** — netmon/capture.py run_live: the
   flusher thread now runs on its own private `flush_stop` event;
   the finally sets only that, never the caller's shared event. A
   sniff() failure still propagates (so the pipeline watchdog sees
   the dead thread and restarts it), and the restart now actually
   captures — the shared event is still clear.
2. **Robustness R4** — netmon/canary.py: start() treats "running
   flag set but thread dead" as stopped — clears the stale state,
   closes any stale socket, and rebinds. _serve clears the running
   flag in a finally when it is still the recorded listener (and
   settimeout moved inside the guarded block).
3. **Robustness R5** — netmon/selfcheck.py check_listening_ports:
   an empty enumeration on Windows returns ("error", "could not
   read listening ports") and never learns a baseline, mirroring
   check_services.
4. **Robustness R3** — netmon/nuclei.py + netmon/amass.py:
   maybe_weekly_* no longer stamp the last-run meta at launch.
   Nuclei's success stamp in run_full_nuclei_scan was already the
   only other writer; amass now stamps amass_last_ts on the success
   path in run_domain_scan. Matches the built-in scan's pattern; a
   failed attempt is retried next monitor pass, with the
   already-running guard preventing overlap.
5. **Robustness R8** — netmon/threatintel.py reverse_dns: a lookup
   that raises or times out is cached with a "neg" marker and a
   10-minute TTL (_RDNS_NEG_CACHE_S, mirroring ipintel); only a
   completed lookup gets the 7-day cache. Pre-existing cache rows
   without the marker keep the long TTL.

Tests: tests/test_council_20261108.py (15 tests) — shared event
stays clear on sniff failure, restart really sniffs again, clean
shutdown guard; canary rebinds on dead thread, idempotent when
alive, _serve exit clears the flag; failed netstat learns no
baseline and recovery learns the real one; both scanners retry
after a failed launch and still skip after a recent success;
failed rdns is neg-marked, expires on the short TTL, recovers, and
successful lookups keep the long cache.

## STAGED for next cycle (verified, not this batch)

- Security S1 (= M1): split the AI tool registry by effect —
  read-only auto-run, `scan` becomes an owner-confirmed proposal.
- Security S2 (= M2): loud startup + login-page warning on
  non-loopback binds (minimum); optional TLS (proper fix).
- Security S3: health.py _scrub quoted pattern becomes
  quote-specific (`\"[^\"]*\"|'[^']*'`) + regression tests for
  embedded opposite quotes. S4: scrubbed env= for the nuclei/amass
  subprocess calls. Both verified Lows — next cycle's headliners
  alongside S1/S2 scoping.
- Robustness R2: ingest paging/cursor fix (watermark advances only
  to the newest ts actually processed). R6: exclude the active
  rewind segment from enforce_caps (and/or clamp rewind_minutes to
  >= SEGMENT_SECONDS/60). R7: retention for host_events (90d) and
  device_hostnames (30d). R9: quiet-hours wrap weekday attribution.
  R10: stream nuclei/amass JSONL parsing.
- UX U1: Settings UI controls (admin-email field + feature toggles)
  — feature work, not a fix batch. U2: app.py plain-language copy.
  U9: Devices Status cell shows isolation ahead of Trusted/
  Probation (small, pairs with U7's vocabulary pass). U3–U8,
  U10–U15 copy items as listed in the UX verdict.

## Verification

- py_compile on all touched files: clean.
- Full suite: 991/991 green on venv python (976 baseline + 15 new).
- Fixes re-verified by experiment post-implementation (canary
  rebind, weekly retry, selfcheck error-not-baseline, rdns negative
  TTL + recovery; the robustness repro's R1 block now shows the
  shared event clear after failure and its unguarded restart call
  raises the simulated sniff error again — i.e. the restart really
  re-enters capture).
- Smoke boot on scratch tree (git archive + wip patch, port 5001,
  fresh DB): /api/stats 200, / 200; scratch removed.
- Staged-diff secret scan + release gate: see commit.
