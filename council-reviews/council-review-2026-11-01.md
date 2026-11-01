# Council review 2026-11-01 — head synthesis

Weekly standing session. 3 independent reviewer subagents convened in
parallel (security, plain-language UX, robustness), each returning
structured, source-verified verdicts at HEAD af51f64. Verdict files:
review-2026-11-01-security-verdict.md, review-2026-11-01-ux-verdict.md,
review-2026-11-01-robust-verdict.md (same directory).

All three seats: NEEDS WORK. No Critical findings this cycle.

## Top findings by seat

- Security: no Critical/High. Two Mediums still open from 2026-10-25 —
  M1 the AI tool loop can execute active scans (nuclei/amass) on model
  say-so with no owner confirmation; M2 owner password/session cross
  the LAN in cleartext HTTP on a non-loopback bind with no warning ever
  printed. New Lows: L1 diagnostics _scrub() leaks all but the first
  word of a quoted multi-word passphrase; L2 compliance HTML/CSV
  downloads not owner-gated (unlike the PDF reports); L3 /api/health
  bypasses the password gate and discloses last-flow/stale to any LAN
  host. L4 (accepted debt): ip-api plaintext HTTP.
- Robustness: High — rewind export still builds up to 512 MB in RAM
  then copies it (residual half of the 2026-10-25 quorum item; the
  read side was streamed, the output side was not). Mediums: M2 pcap
  analysis has no per-file/per-packet guard (reproduced: a text file
  renamed .pcap raises straight out of run_pcap; staged since
  2026-10-25); M3 selfcheck canary-port exclusion compares the
  protocol string to the port number and never excludes anything
  (reproduced); M4 detector 64 MB cap is per-line, after the line is
  in memory (reproduced, 90 MB single line); M5 ingest parses a whole
  50 MB XML export into a DOM + full event list.
- UX: High — 13+ "edit config.yaml" dead-ends unchanged (incl. the
  Escalate admin-email flow, unusable end-to-end for a non-technical
  owner); app.py demo front door still technician-only. Mediums are
  carried copy items (MITRE badges, Amass/Nuclei names + install
  commands, "escalate to admin", pcap/Wireshark/forensic wording,
  three severity/state vocabularies, unexplained "Probation" badge).

## SHIPPED (this batch)

One focused batch: the reproduced / policy-consistency defects. Each
was verified in source by the head before implementing; L1, M2, M3
were reproduced experimentally by their seats; L2/L3 extend the
owner-gating policy the 2026-10-25 quorum batch set for downloads.

1. **Security L1** — netmon/health.py `_secret_res()`: the KV value
   pattern now consumes a quoted string whole
   (`(?:["'][^"']*["']|\S+)`), so a multi-word passphrase no longer
   leaks into the diagnostics bundle.
2. **Security L2** — netmon/dashboard.py: `@_owner_required` on
   /reports/compliance.html and /reports/compliance.csv (no-op in
   no-password mode, like every other owner gate).
3. **Security L3** — netmon/dashboard.py: "/api/health" removed from
   the password-gate exemption; it returns last_flow_ts/stale only to
   a signed-in role now.
4. **Robustness M3** — netmon/selfcheck.py: canary exclusion filters
   on the port element (`n != trap_port`), not the protocol string.
5. **Robustness M2 (partial)** — netmon/capture.py run_pcap: reader
   loop and per-packet handle() are guarded; a corrupt/wrong-format
   file stops the run early and keeps what was aggregated instead of
   raising. Dashboard /pcap unlinks are OSError-guarded (Windows
   locked-file class). The route still renders the results page with
   0 packets for a garbage file rather than a plain "couldn't read
   that" message — that copy is staged with UX M6.

Tests: tests/test_council_20261101.py (8 tests) — multi-word scrub
(YAML + JSON shapes) + single-token guard, canary port excluded from
the current set with the real (proto, port) tuple shape, garbage
pcap returns an empty aggregator, /api/health redirects to /login
when auth is on and still 200s for the owner, viewer 403 on both
compliance downloads.

## STAGED for next cycle (verified, not this batch)

- Robustness H1: stream the rewind export to a temp file + send_file
  (or lower EXPORT_MAX_BYTES to a RAM-safe value with documented
  truncation) — the cycle's highest single-seat finding; it is the
  residual of a prior quorum item and should be next cycle's batch
  headliner, paired with UX M6 pcap/rewind copy.
- Security M1: split the AI tool registry by effect — read-only tools
  auto-run, `scan` becomes a pending proposal needing an owner POST
  (quarantine pattern).
- Security M2: loud startup + login-page warning on non-loopback
  binds (minimum), optional TLS serving (proper fix).
- Robustness M4 (detector chunked reading), M5 (ingest iterparse
  streaming), L6–L10 (rewind prune stat race, app.py sample-read cap
  + DB timeout=30, ipintel negative cache + close-on-error,
  host_events/device_hostnames retention, weekly-scan last-run stamp
  on failure).
- UX H1: Settings UI controls (admin-email field + feature toggles)
  — feature work, not a fix batch. H2: app.py plain-language copy
  (pairs with robustness L7 on the same file). M3–M8, L9–L14 copy
  items as listed in the UX verdict.

## Verification

- py_compile on all touched files: clean.
- Full suite: 936/936 green on venv python (928 baseline + 8 new).
- Smoke boot on scratch copy + fresh DB (port 5001): /api/stats 200,
  / 200, /api/health 200 in open (no-password) mode; scratch removed.
- Staged-diff secret scan + release gate: see commit.
