# Council review 2026-10-25 — head synthesis

Weekly standing session. 3 independent seats convened in parallel
(security, plain-language UX, robustness); all returned structured,
source-verified verdicts. The head verified every shipped finding in
source personally before implementing.

Quorum rule (per the standing brief): a finding ships on 2-of-3 seat
agreement, or on 1 seat rating it Critical with head agreement.

## SHIPPED (this batch)

1. **Capture memory bounds — robustness C1 (Critical, head-verified).**
   `FlowAggregator.flows` had no cap, `dns_buf` appended
   unconditionally, and `ScanTracker.history` pruned a source's list
   only when that source was seen again — so a port scan or
   spoofed-source flood (exactly the traffic the sensor exists to
   watch) grew memory without bound between 15s flushes / for the
   capture's lifetime. Neighbouring buffers were already capped
   (hostname 1000, ttl_map 2048, _mac_seen 5000); these three were
   missed. Fixed in capture.py: MAX_FLOWS=100_000 (new flows dropped
   and counted at the cap; tracked flows keep aggregating),
   MAX_DNS_BUF=10_000, ScanTracker global stale-source sweep at most
   once per SCAN_WINDOW plus SCAN_MAX_SOURCES=10_000 with
   oldest-first eviction (counted). Drops are logged once per flush,
   never silent.

2. **Rewind export: lock + memory + raw-payload access — security H2
   (High) + robustness H1 (High), the cycle's 2-seat quorum.**
   (a) `export_window()` held rewind `_lock` for the whole scan while
   `_iter_segment_packets` read each 64 MB segment fully into RAM and
   `out` grew toward the 512 MB cap — a dashboard export stalled
   `record_packet()` (capture hot path) for seconds and risked OOM on
   a small sensor. Fixed: segment list is snapshotted under the lock,
   the build runs without it, and records stream one packet at a time
   (truncated/concurrent tails stop cleanly). (b) The read-only
   viewer role could download raw packet payloads via
   `/api/rewind/export` — full payloads, a different data class from
   dashboard summaries — plus `/reports/weekly.pdf` and
   `/reports/incident/<id>.pdf`, none of which had `@_owner_required`.
   All three routes are owner-only now (no-op when no passwords are
   configured, as before). Segment files are created 0600 and the
   rewind directory 0700, self-healing like db.py/config.py.

Tests: tests/test_council_20261025.py (9 tests) — ScanTracker sweep
and source cap, flow cap + flush drop logging, rewind streaming with
a truncated tail, export builds without holding the lock, segment
permission bits, viewer 403 on all three download routes + owner 200
on the rewind export.

Test-writing find (head, staged as its own item below): the new role
tests initially poisoned later test modules — `config.load()` folds
BRUTEDASH_* env vars into the config dict (`_apply_env`) and
`load_cached()` caches it by file mtime, so env-set passwords outlive
the env vars for the rest of the process. The new tests clear
`cfgm._CACHE` in setUp/tearDown (test_config.py pattern); the product
quirk itself is staged, not fixed here.

## STAGED for next cycle (verified or credible, not this batch)

- **Security H1 (High, head-verified): the login "5-minute block"
  does not exist.** dashboard.py `_login_allowed()` denies only when
  ≥5 failures fall inside the 60s window; `_LOGIN_BLOCK=300` only
  retains stamps. At t+61s five more guesses are allowed — ~7,200/day
  indefinitely against the single shared owner password. The login
  comment claims a block that never happens. Top priority next cycle.
- Security M1: viewer-reachable `/api/intel/ip/<ip>` burns the 50/day
  AbuseIPDB budget on arbitrary IPs and proxies lookups off-box.
- Security M2: LAN-derived alert text (DNS/DHCP/mDNS names) reaches the
  AI tool loop, which can execute active `scan` tool calls on model
  say-so — proposals should need an owner click, like quarantine.
- Security M3: owner password/session cross the LAN in cleartext HTTP
  on a 0.0.0.0 bind (deferred TLS phase; needs a loud startup warning
  at minimum). L1: demo `/brief` count unclamped + detector stores
  unvalidated "IP" tokens (pairs with UX H2 / robustness M4 on app.py).
- Robustness H2: detect.py query amplification — arp_spoof shape-2
  N+1 plus `_device_label()` re-running full `ip_to_mac_map()` /
  `device_name_map()` scans per alert candidate (4 scans per alert).
  M1: `_LOCAL_IPS_CACHE` never expires; a transient failure caches an
  empty set for the process lifetime. M2: pcap path lacks the live
  path's per-packet guards (one malformed packet loses the whole run).
  M3: health.py — RotatingFileHandler built outside its guard (and
  leaked on repeat calls), one bundle-section write failure aborts the
  rest, diagnostics sqlite handle leaks on error. M4: app.py demo —
  unguarded sample read, DB connections leaked on error, unguarded
  Windows unlink (with security L1 + UX H2, app.py is a 3-seat locus
  for a focused demo-hardening batch). L1–L4: ingest whole-file parse
  memory, detector per-line byte-cap blindness, db.device_hostname_map
  full-history scan, rewind size-cap stat race.
- UX H1 (carried since 2026-10-18): 13+ "edit config.yaml" dead-ends,
  incl. escalate.py's admin-email flow — needs a Settings field
  (feature work, not a fix batch). H2: app.py Phase-1 text is
  technician-only (pairs above). M1–M7 (carried + new): MITRE badges,
  Amass/Nuclei brand+install text, "escalate to admin" vocabulary,
  pcap/Wireshark/"forensic" wording, three severity/state
  vocabularies, unexplained headings ("Forensic rewind", "Warden's
  hit list"), unexplained "Probation" device badge. L1–L5: raw error
  banners, "Prune now" without confirmation, "Follow-up ID" hex,
  status-code badges, small jargon slips.
- Head find (from this cycle's test work): `load_cached()` +
  `_apply_env` cache poisoning — env-derived secrets persist in the
  cached config dict after the env vars are gone (mtime-keyed). Fix
  candidate: don't cache env-derived values, or key the cache on an
  env fingerprint for the auth/monitor sections.

## Verification
- py_compile on all touched files: clean.
- Full suite: 880/880 green on venv python AND plain python3
  (871 baseline + 9 new; plain python skips Flask/scapy tests).
- Smoke boot on scratch copy + fresh DB (port 5055,
  BRUTEDASH_DASHBOARD_PORT): /api/stats → 200, / → 200,
  /api/rewind/export?hours=1 → 200 in open (no-password) mode;
  scratch removed.
- Staged-diff secret scan + pre-push release gate: see commit.
