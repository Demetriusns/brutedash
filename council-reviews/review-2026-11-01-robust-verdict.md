# Council review 2026-11-01 — ROBUSTNESS verdict (brutedash / Project Orion)

Read-only review at git HEAD `af51f64` ("DEVLOG: 2026-11-01 daily build
notes (load_cached env fingerprint, 69a65c3)"). Scope: detector.py,
app.py, ipintel.py, netmon/capture.py, pipeline.py, run.py, ingest.py,
detect.py, db.py, rewind.py, health.py, weekly.py, watchdog.py,
selfcheck.py, canary.py, notify.py, retention.py, threatintel.py,
quarantine.py, scan.py, nuclei.py, amass.py, tools.py, config.py,
dashboard.py (pcap/export routes), tests/.

Prior-fix verification (not re-flagged): HEAD fix `69a65c3` verified in
source — `netmon/config.py` `_env_fingerprint()` + `load_cached()` now
require mtime AND BRUTEDASH_* fingerprint to match; no caller mutates
the returned cached dict (grep-verified). The whole post-2026-10-25
staged cascade is also verified landed: login block (f2efaad), intel
owner-gating (ee2b42b), detect pass-scoped maps + single-query
arp_spoof + 300s local-IP TTL (a722229), health handler/bundle guards
(689170e), app.py demo hardening (c2efb18). Findings 2, 4, 5, 7 below
are the *residual halves* of staged items those fixes only partly
closed, plus two new finds (3, 6, 8–10 split out). Three findings were
empirically reproduced during this review (2, 3, 4).

## FINDINGS

### Critical
None. The capture hot path, pipeline watermarks/watchdog, and DB
layer all held up under re-reading (see Non-findings).

### High

1. [High] netmon/rewind.py:336,358-365 + netmon/dashboard.py:3860-3862 — rewind export still builds up to 512 MB in RAM, then copies it
   What is wrong: `export_window()` accumulates into memory —
   `out = bytearray(_GLOBAL_HDR)` (line 336) — appending until
   `len(out) + need > EXPORT_MAX_BYTES` (line 358), where
   `EXPORT_MAX_BYTES = 512 * 1024 * 1024` (line 44), and finishes with
   `return bytes(out), count` (line 365), which makes a *second* full
   copy. The dashboard route then wraps the blob in a download
   response. The 2026-10-25 H1 fix streamed the segment *reads* one
   packet at a time and released the lock, but the export *output*
   was never streamed.
   Failure scenario: owner clicks "download the last 24 hours" on a
   busy buffer (the route allows `hours` up to 24 and arbitrary
   24h windows). Peak RSS for one export is ~1 GB (bytearray + bytes
   copy) on top of capture + dashboard, which live in the same
   process under `netmon/run.py`. On the Pi-class / small-box target
   in the roadmap that is an OOM kill of the whole monitor —
   capture, detection, and dashboard die together, mid-incident,
   exactly when the owner is exporting evidence.
   Concrete fix: stream the export to a temp file (write header +
   records incrementally, counting bytes against the cap), return
   the path/count, and have the dashboard serve it with Flask's
   `send_file`; delete the temp file after the response. If the
   bytes-returning API must stay for tests, lower EXPORT_MAX_BYTES
   to a RAM-safe value (e.g. 64 MB) and document the truncation.

### Medium

2. [Medium] netmon/capture.py:669-672 + 405-423; netmon/dashboard.py:4227-4247; netmon/run.py:324 — pcap analysis still has no per-file/per-packet guard (staged 2026-10-25 M2, still present; reproduced)
   What is wrong: `run_pcap()` is
   `with PcapReader(path) as reader: for pkt in reader: agg.handle(pkt)`
   with no try around either the iteration or the call. `handle()`'s
   head (lines 405-423: `pkt.getlayer(...)`, `float(getattr(pkt,
   "time", ...))`, `pkt[TCP]` / `pkt[UDP]` field access) is likewise
   unguarded — the sub-parsers below it are guarded, the dissection
   head is not. The live path wraps `handle()` twice (`_prn` in
   capture.py, plus `observe()`'s own guard); the pcap path wraps it
   zero times. Neither caller recovers: dashboard `/pcap`
   (lines 4227-4244) has only finally-blocks, and run.py:324 calls
   `capm.run_pcap(args.pcap)` bare.
   Reproduced: a text file renamed `.pcap` raises
   `Scapy_Exception: Not a supported capture file` straight out of
   `run_pcap` (a truncated *record* is handled gracefully by scapy —
   0 packets, warning only — so the vector is a bad/unsupported/
   corrupt-header file, a routine Wireshark-export mistake).
   Failure scenario: owner uploads a corrupt, truncated-header, or
   wrong-format capture → Flask 500 with no explanation, the whole
   analysis (including every valid packet's flows and the summary)
   is lost; the `--pcap` CLI dies with a traceback. Secondary: both
   dashboard unlinks are unguarded — `os.unlink(path)` (line 4231)
   and `os.unlink(scratch.name)` (line 4247) — so on Windows a
   locked temp/scratch file (antivirus, indexer) raises out of the
   finally and masks the real outcome, the exact bug class c2efb18
   fixed in app.py but not here.
   Concrete fix: in `run_pcap`, wrap the reader loop — catch
   iteration-level scapy/EOF errors and stop with the packets
   already aggregated (log one line, still `agg.flush()`); wrap each
   `agg.handle(pkt)` in the same try/except `_prn` uses. In the
   dashboard route, catch the analysis block and render the pcap
   page with "that file couldn't be read as a capture" instead of
   500ing; guard both unlinks with `try/except OSError` (app.py
   pattern). Add a regression test with a garbage `.pcap`.

3. [Medium] netmon/selfcheck.py:109-110 — canary-port exclusion compares the protocol string to the port number; it never excludes anything (new; reproduced)
   What is wrong:
   `current = {(p, n) for p, n in current if p != trap_port}`.
   `current` holds `(proto, port)` tuples — `_linux_listening_ports`
   and `_windows_listening_ports` both build sets like
   `("TCP", 23231)` — so `p` is the string `"TCP"` and the test
   `"TCP" != 23231` is always true. Reproduced with the exact
   comprehension: `{("TCP",23231),("TCP",5001)}` filtered by
   `trap_port=23231` returns both entries unchanged.
   Failure scenario: the exclusion is the documented guarantee in
   canary.py ("The self-check's listening-port baseline excludes the
   canary port, so the trap never trips the 'new listener'
   self-alert"). With it dead: if the baseline is learned while the
   canary is disabled, unbound, or on a different port (config
   change), the next selfcheck (every 6h) fires a Medium
   "Something new is listening on this box" self_drift alert for
   brutedash's own trap — a false alarm that trains the owner to
   ignore the real drift alert. Conversely a baseline learned with
   the trap included bakes the trap port in as "normal" forever.
   Concrete fix: filter on the port element:
   `current = {(proto, n) for proto, n in current if n != trap_port}`,
   and add a unit test that seeds `current` with the canary port
   and asserts it is gone before the baseline compare.

4. [Medium] detector.py:136-139 — the 64 MB cap is checked per *line*, after the line is fully in memory (staged detector L-item, still present; reproduced)
   What is wrong:
   `for line in f: _count_line(line); bytes_read += len(line.encode("utf-8", "replace")); if bytes_read > MAX_TOTAL_BYTES: break`.
   Text-mode iteration materialises a whole line before the body
   runs, so a single newline-free line is read, held, counted, and
   re-encoded at full size no matter what the cap says; the cap
   only bounds *multi-line* totals, overshooting by up to one line
   per source.
   Reproduced: a 90 MB single-line auth.log (cap is 64 MB) ran to
   completion with peak RSS ~354 MB in the test process (line str +
   encode copy + parser overhead) — the cap never engaged early.
   The same shape arrives via a rotated `.gz` sibling: a small
   gzip that decompresses to one huge line inflates in memory the
   same way, past the sibling size pre-check at line ~128, which
   stats the *compressed* file.
   Failure scenario: a damaged/rotated log with wrapped or
   newline-stripped content (or a hostile log planted for the demo
   to scan) spikes memory on the scan request; on a small box the
   app.py POST / worker is the casualty.
   Concrete fix: read in bounded chunks (e.g. `f.read(1 << 16)`
   blocks, split on newlines keeping the tail) or check the running
   total against a per-line length first and truncate any line at,
   say, 1 MB before `_count_line` — a real auth line is a few
   hundred bytes. Count `len(line)` on the decoded str is also
   wrong for non-ASCII (encode is the expensive way to be right);
   chunked byte reading fixes both.

5. [Medium] netmon/ingest.py:342-368 — XML ingest still parses the whole export into a DOM and a full event list (staged L1, still present)
   What is wrong: `tree = ET.parse(path)` (line 342) loads the
   entire document tree for files `_safe_files` allows up to
   `MAX_FILE_BYTES = 50 * 1024 * 1024` (line 46), then
   `parse_security_xml` accumulates every matching event into a
   Python list (each with a `json.dumps(detail)[:2000]` string)
   before `run_ingest` inserts anything. ElementTree's in-memory
   expansion of a 50 MB export is several times the file size, and
   the events list adds a second full copy of the content.
   Failure scenario: a full Security-log export from a busy Windows
   box (the documented INGEST.md workflow produces exactly these)
   spikes the monitor process by hundreds of MB every 5-minute
   poll until the file's mtime state is recorded — competing with
   capture on the same small box. The entity-expansion guard
   (L5 fix) stops the malicious case; this is the *legitimate*
   large file.
   Concrete fix: stream with `ET.iterparse(path, events=("end",))`,
   processing and clearing each `Event` element, and insert events
   in bounded batches (e.g. 1000) from inside the parse instead of
   returning one list. Keep the `_declares_entities` pre-scan and
   the `([], 1)` failure shape.

### Low

6. [Low] netmon/rewind.py:276-289 — one bad stat disables the size cap for the pass; one failed unlink can evict the whole buffer
   What is wrong: (a) `total = sum(p.stat().st_size for _, p in fresh)`
   is wrapped in a single try — `except OSError: total = 0`
   (lines 276-279) — so one segment vanishing mid-pass (rotation,
   a concurrent export cleanup, a user deleting a file) silently
   zeroes the total and the size cap is not enforced at all that
   pass. (b) In the eviction loop (lines 281-289) the segment is
   popped from `kept` *before* the try, and on `OSError` the code
   does `pass` without decrementing `total` — so a single locked/
   undeletable segment (on Windows, an AV-scanned or still-open
   closed segment is routine) keeps `total > max_bytes` true and
   the loop pops and deletes *every remaining segment* chasing a
   target it can never reach. Minor companion: the time-cap loop
   (lines 268-272) adds `path.stat().st_size` to `freed` before
   `path.unlink()` runs, so a failed unlink over-reports freed
   bytes (accounting only).
   Concrete fix: stat per-file inside the sum (skip-and-continue
   on OSError, keeping the partial total); in the eviction loop,
   only pop on success — on failure, remove that path from
   consideration for this pass and break if no progress was made.

7. [Low] app.py:391,74 — demo residuals c2efb18 did not close: unbounded sample read, 5s DB timeout
   What is wrong: `sample_log()` now survives a vanished file
   (the M4 guard landed) but still does
   `return "".join(f.readlines())` (line 391) — the entire
   auth.log into memory on *every* GET /. And `get_db()` still
   uses `sqlite3.connect(DB_PATH)` (line 74) with the default
   5-second busy timeout, where netmon/db.py uses `timeout=30`;
   under concurrent demo traffic + ipintel writing the same
   detections.db, a >5s lock turns GET /history or a scan POST
   into a 500 where netmon would have waited it out.
   Concrete fix: cap the sample read (first 256 KB is more than
   the form needs) and pass `timeout=30` in `get_db()` — and in
   ipintel.py:34, which has the same default-timeout connect.

8. [Low] ipintel.py:76-97,54 — failed lookups close nothing and cache nothing
   What is wrong: in `lookup_ip()`, `conn.close()` appears only on
   the cache-hit path and the success path; the bare
   `except Exception: return {}` exits without closing the
   connection `_db()` opened (the handle's cleanup is left to
   interpreter refcounting instead of the code). Failures are also
   never cached: a down ip-api (or no network) costs a fresh
   `urlopen(..., timeout=5)` (line 54) on *every* brief for that
   IP, so each /brief request thread sits blocked up to 5s,
   repeatedly, for as long as the outage lasts.
   Concrete fix: wrap the connection in try/finally (or
   `contextlib.closing`), and write a short-TTL negative cache row
   (e.g. 10 minutes, empty intel) so an outage is one stall per
   IP per window, not one per click.

9. [Low] netmon/retention.py:72-82 + netmon/db.py:2358-2366 — host_events and device_hostnames are never pruned; the hostname map scans the full history every sync
   What is wrong: `_TABLES` prunes flows, dns_queries,
   arp_observations, summaries, outages, score_snapshots, and
   alerts — and nothing anywhere issues a DELETE for
   `host_events` or `device_hostnames` (grep-verified). Meanwhile
   `device_hostname_map()` does
   `SELECT ts, mac, hostname, source FROM device_hostnames WHERE mac != '' ORDER BY ts`
   over the whole table and folds it in Python; it is called on
   every asset sync (netmon/assets.py:102). Capture appends
   hostname rows on every flush (up to 1000 per 15s flush from
   DHCP/mDNS chatter), so both the table and this scan grow
   without bound for the life of the install.
   Concrete fix: add `device_hostnames` (observations_days) and
   `host_events` (a new `host_events_days`, default e.g. 90) to
   the retention tables, and/or push the latest-per-MAC fold into
   SQL. Same treatment is worth a look for `first_seen`, which
   also only grows (one row per distinct key — slower, noted not
   ranked).

10. [Low] netmon/nuclei.py:564 + netmon/amass.py:557 — weekly scans stamp "last run" at *launch*, so a failed scan consumes the week's slot
    What is wrong: `maybe_weekly_nuclei()` does
    `dbm.set_meta("nuclei_scan_last_ts", str(time.time()))`
    *before* `start_nuclei_async()` (amass is identical with
    `amass_last_ts`). `run_full_nuclei_scan` records the failure
    as a run row but never clears that stamp (it only re-stamps
    on success), so one transient failure — binary crash, the
    subprocess timeout at `timeout_min * 60 + 300`, a DB hiccup —
    suppresses any retry for a full `WEEK_SECONDS`. The built-in
    LAN scan does it the other way (its last-run stamp comes from
    the completed run row), so the three weekly jobs behave
    inconsistently.
    Concrete fix: stamp at launch only as an in-flight marker
    under a different key, and have the failure paths in
    `run_full_nuclei_scan` / `run_domain_scan` reset
    `*_last_ts` to the previous successful run (or delete the
    launch stamp), so the next monitor pass retries.

## NON-FINDINGS (checked and clean)
- capture.py hot path: ScanTracker DB calls fire after the lock is
  released and are guarded (R1); `sniff()` loops on
  `timeout=SNIFF_TIMEOUT` so stop is observed on idle/Npcap-stalled
  interfaces (R2); flush writes each buffer in its own guard with
  drop counts logged, final flush guarded (R3); C1 caps on flows /
  DNS buffer / scan sources all present with counted drops.
- pipeline.py: every public helper is exception-contained;
  watermarks treat missing as unknown-never-stale; disk pressure
  suppresses the loop-down double-alert; `ensure_capture` restart
  budget (3/hour) intact; `safe_step` timed detach + in-flight
  registry works as documented (the weekly steps it guards return
  in milliseconds — they launch async workers — so the 60s
  deadline is a backstop, not the mechanism).
- run.py monitor loop: detection runs even under disk pressure,
  steps are safe_step-isolated, loop tick + pid file lifecycle
  correct, non-loopback bind fails closed without a password.
- db.py: `_db()` double-checked locking (R6) intact;
  _ReconnectingConnection retries only dead-connection errors and
  stays closed after explicit close (isolated_db teardown);
  `_write_with_retry` is strictly bounded (5 attempts, lock errors
  only); `writability_probe` persists nothing.
- detect.py: H2/M1 fixes verified — pass-scoped `_DeviceMaps`,
  arp_spoof is one grouped query for both shapes (the remaining
  per-IP `get_first_seen` calls are one row lookup each, not full
  scans), `_local_ips` has the 300s TTL with loopback floor;
  `run_all` isolates each rule. check_behavior_deviation's own
  map loads are once-per-pass, not per-alert.
- ingest.py per-file OSError skip (R7) verified — one vanished/
  rotated file no longer aborts the pass or blocks the
  `ingest_last_run_ts` stamp; pfirewall resumed-read header fix and
  inode-rotation reset intact; `_declares_entities` chunked scan
  handles the chunk-boundary marker.
- weekly.py: every query goes through the `_q` fallback with the
  degraded flag (the 2026-10-18 R9 carryover is fixed); health.py
  M3 fixes verified (handler built inside the guard and not
  rebuilt per call, bundle sections isolated, bundle sqlite handle
  closed in finally).
- watchdog.py: concurrent pings via pool, start/end_outage failures
  are logged and retried next pass without killing the thread;
  localized gateway labels + numeric `route print` fallback.
- notify.py: bounded queue (100, oldest shed + counter), worker
  loop catches per-job, SMTP timeout=30. threatintel.py: fetch
  timeout + 5 MB cap + chunked read; AbuseIPDB read capped at
  64 KB with timeout=15; `reverse_dns` hard-caps the wait at 3s
  on a daemon thread. quarantine.py worker: per-device poison
  failures isolated, worker restarts via is_alive check.
  canary.py serve loop: 1s accept timeout, touch handling guarded.
  tools.py `_invoke_once`: daemon-thread timeout with honest
  "abandoned, not killed" semantics and idempotent-only retry.
  scan.py: single-scan claim lock released in finally on every
  path in `run_full_scan`.
- config.py at 69a65c3: env fingerprint fix verified, including
  the removed-variable direction; `auth_passwords()` also reads
  the password env vars fresh, so it was never cache-dependent.
- detector.py other than finding 4: primary-first order,
  validated-IP counting (security L1), and the
  `(OSError, EOFError, zlib.error)` sibling split (R5) all
  verified in source.

## TEST BASELINE
`./venv/bin/python -m unittest discover -s tests` — 1029 tests, OK
(~25s, venv python). No failures. No existing test covers findings
2 (garbage pcap), 3 (canary-port exclusion), or 4 (single-line cap)
— all three were reproduced by hand during this review instead.

VERDICT: NEEDS WORK
