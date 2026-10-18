# Council review 2026-10-18 — ROBUSTNESS verdict (brutedash / Project Orion)

Read-only review. Scope: netmon/pipeline.py, capture.py, watchdog.py, health.py,
db.py, detect.py, ingest.py, run.py, weekly.py, rewind.py, notify.py, app.py,
detector.py. Prior cycle read first (council-review-2026-10-11.md +
review-2026-10-11-robust-verdict.md): all five 2026-10-11 robustness findings
verified FIXED in source (detector primary-first + truncated-"from " guard,
watchdog start/end_outage guards, note_loop_tick docstring honesty) and not
re-flagged, except R9 below, which was staged-not-fixed and is still present.
One finding below (R5) was empirically reproduced during this review.

## FINDINGS

### Critical
None.

### High

1. [High] netmon/capture.py:106-141,394,500-510 — a DB hiccup on the packet path kills live capture
   What is wrong: `FlowAggregator.handle()` (line 394) calls
   `ScanTracker.observe()` with no guard, and `observe()` performs database
   I/O — `dbm.recent_alert_kind()` and `dbm.add_alert()` (lines ~119-141) —
   while holding `ScanTracker.lock`. `run_live`'s `_prn` callback (lines
   500-506) guards only the rewind call; `agg.handle(pkt)` is unguarded, and
   scapy propagates a `prn` exception out of `sniff()` (lines 509-510).
   Failure scenario: a port-scan burst coincides with SQLite lock contention
   that outlasts the busy timeout + `_write_with_retry` budget (or a disk
   I/O error on commit): `add_alert` raises, the exception escapes
   `handle` → `_prn` → `sniff`, and the capture thread dies mid-run. Short
   of death, every threshold-crossing SYN stalls packet processing for the
   full DB wait because the DB calls sit on the hot path under a lock.
   `pipeline.ensure_capture` restarts a dead thread (max 3/hour), then
   gives up — a recurring DB fault burns the restart budget and capture
   stays dead.
   Concrete fix: wrap the `observe()` call in `handle()` (and `agg.handle`
   in `_prn`) in try/except that logs one stderr line and drops that
   packet's scan tracking; move the `recent_alert_kind`/`add_alert` calls
   in `observe()` outside `ScanTracker.lock` (collect the alert decision
   under the lock, fire it after release).

2. [High] netmon/capture.py:509-513 — sniff() has no timeout; an idle or stalled capture can never be stopped or restarted
   What is wrong: `sniff(iface=..., prn=_prn, store=False,
   stop_filter=lambda _p: stop_event.is_set())` passes no `timeout=`.
   `stop_filter` is only evaluated when a packet arrives. On an idle
   interface, or when Npcap/libpcap stalls on Windows (interface sleep,
   driver hiccup), `sniff()` blocks indefinitely in the native read:
   `stop_event` is never observed, the `finally` block's
   `flusher.join(timeout=FLUSH_INTERVAL + 5)` expires, and shutdown hangs.
   Worse, the capture thread still reports `is_alive() == True`, so
   `pipeline.ensure_capture` never restarts it — capture is silently dead
   while every liveness check says alive (only the stale-capture watermark
   notices, 5 minutes later).
   Concrete fix: pass `timeout=5` (or similar) to `sniff()` so the read
   loop wakes periodically and re-checks `stop_filter` even with zero
   traffic; optionally track last-packet time in `FlowAggregator` and let
   `ensure_capture`'s `is_alive` callable treat "alive but no packet and
   no flush for N minutes on a non-idle interface" as suspect.

3. [High] netmon/capture.py:434-467,470-476 — flush() detaches all buffers before writing; the first failed insert silently discards the rest
   What is wrong: `flush()` swaps `flows`, `dns_buf`, `arp_buf`,
   `hostname_buf`, and `ttl_map` out under the lock (lines 434-445), then
   writes them sequentially (lines 446-466). If `insert_dns_queries`
   raises (locked/corrupt DB, disk error), the already-detached ARP,
   hostname, TTL, and flow rows are never attempted and are lost — the
   data no longer exists anywhere. `_flush_loop` (lines 470-475) catches
   the exception with a bare `except Exception: pass` — no log line, so
   the loss is invisible — and its final shutdown flush (line 476,
   `agg.flush()`) is outside any try, so a failing final flush raises out
   of the flusher thread.
   Failure scenario: one 15-second window of DB contention during a
   port-scan burst permanently loses that window's flows and DNS/ARP
   observations; detection rules then run over a gap that looks exactly
   like a quiet network.
   Concrete fix: write each buffer in its own try/except (log one line per
   failed buffer, continue with the rest), and re-queue or at minimum
   count-and-log dropped rows; wrap the final flush in `_flush_loop` the
   same way as the periodic one.

4. [High] app.py:169 — OpenAI client built with no timeout (the one call site the earlier fix missed)
   What is wrong: `write_brief()` does `client = OpenAI(api_key=api_key)`
   with no `timeout=`. This is the exact bug class fixed in
   netmon/ai_assist.py:64 and netmon/explainer.py:316 (both `timeout=30`)
   after the 2026-10-04 council rated it High: the OpenAI SDK default is
   ~10 minutes, so a hung API call wedges the Flask worker handling
   POST /brief for up to ~10 minutes per request; a handful of brief
   clicks exhausts the demo's workers.
   Concrete fix: `OpenAI(api_key=api_key, timeout=30)` — one line, matching
   the two already-fixed call sites.

### Medium

5. [Medium] detector.py:123-136 — corrupt/truncated .gz sibling crashes detect_brute_force (empirically reproduced)
   What is wrong: the sibling-read block catches only `OSError`. A
   truncated gzip raises `EOFError` and a corrupt deflate stream raises
   `zlib.error`; neither is an `OSError` subclass (verified in this
   environment), so both escape the `except OSError` at line 133.
   Reproduced during this review: primary auth.log + auth.log.1.gz
   truncated mid-stream → `detect_brute_force` raised
   `EOFError: Compressed file ended before the end-of-stream marker was
   reached` instead of returning the primary's findings.
   Failure scenario: logrotate compresses while a scan runs (or an old
   .gz is damaged); app.py:331-334 wraps the call in try/finally only
   (unlink, no except), so the POST / handler returns Flask 500 and the
   whole scan — including the healthy primary log — is lost.
   Concrete fix: catch `(OSError, EOFError, zlib.error)` around the stream
   read (import zlib), keeping the primary-raises / sibling-skips split;
   add a regression test with a truncated .gz sibling.

6. [Medium] netmon/db.py:694-702 — shared-connection lazy init is unsynchronized; first-call race leaks a connection and races migrations
   What is wrong: `_db()` does `if _conn is None: _conn = _connect()` with
   no lock. run.py starts watchdog, capture, monitor, and the threaded
   Flask dashboard back-to-back; two threads taking their first `_db()`
   concurrently both see None and both run `_connect()` — the full schema
   + migration sequence in `_connect_raw`, including DDL and chmod — on
   two separate connections to the same file. One connection wins the
   assignment; the other is leaked (never closed, holds WAL handles for
   the process lifetime), and the concurrent DDL can surface as
   "database is locked" / duplicate-schema errors during startup.
   Concrete fix: guard the init with a dedicated lock (double-checked
   locking) or create `_conn` eagerly at import of the first entry point;
   close the losing connection if a race is detected.

7. [Medium] netmon/ingest.py:770,784,766-807 — one file vanishing mid-pass aborts ingestion for every remaining file
   What is wrong: inside `run_ingest()`'s per-file loop,
   `os.path.getmtime(path)` (line 770) and `os.path.getsize(path)`
   (line 784) are unguarded. The only per-file stat that is guarded is
   `st_ino` (lines 771-774). A file deleted/rotated between `_safe_files`
   listing and the stat — routine on Windows, where the firewall log is
   rotated and exported files are replaced — raises `OSError`, which
   propagates to the single outer try (lines 766/805): the pass aborts,
   all later files are skipped, and `ingest_last_run_ts` (line 804) is
   never stamped, so the failure repeats identically every 5 minutes
   until the offending file state changes.
   Concrete fix: wrap the per-file body in try/except OSError (log/count
   as skipped, continue to the next file); keep the outer try only for
   pass-level failures.

8. [Medium] netmon/pipeline.py:765-772 + netmon/run.py:132-216 — safe_step bounds exceptions, not hangs; one long step wedges the whole monitor loop
   What is wrong: `safe_step` is a try/except wrapper with no timeout, and
   `_monitor_loop` runs every step sequentially on one thread. A step that
   blocks — e.g. the Nuclei step, whose subprocess timeout is
   `timeout_min * 60 + 300` with `timeout_min` allowed up to 240
   (netmon/nuclei.py build/run path) — blocks the loop for hours. The
   loop tick is only stamped at the top of a pass (run.py:134), so during
   the block: no detection pass runs, no capture watchdog runs, no
   staleness check runs. The loop-down self-alert fires from the
   dashboard side, but nothing recovers the loop; it stays wedged until
   the subprocess timeout expires.
   Concrete fix: run the long subprocess-backed steps (nuclei, amass,
   weekly scan) on worker threads the loop only polls (the notify.py
   async pattern), or give `safe_step` an optional deadline for those
   steps and log a step as overrunning when it exceeds one interval.

9. [Medium] netmon/weekly.py:45-194 — CARRYOVER (staged R5, 2026-10-11, still present): generate_weekly_report still crashes on any DB hiccup
   What is wrong: unchanged since the last cycle. Every `dbm.query(...)`
   in `generate_weekly_report` is unguarded except the `first_seen` block;
   a locked/corrupt DB raises straight out, and run.py's `--weekly-report`
   path prints a traceback and produces no report, contradicting the
   module docstring's "degrades gracefully" promise. Not new — flagged so
   the head can either schedule the staged fix or explicitly re-defer it,
   not rediscover it next cycle.
   Concrete fix: as staged — wrap the query blocks and fall back to
   empty/unknown sections with a "couldn't read the database" note.

10. [Medium] netmon/rewind.py:315-334,284-285 — export_window holds the recording lock for a full disk scan and builds up to 512 MB in RAM
    What is wrong: `export_window()` holds `_lock` for its entire scan
    (line 315). `record_packet` needs the same lock, so live capture's
    forensic recording stalls for the whole export. Inside the scan,
    `_iter_segment_packets` reads each segment file wholesale
    (`blob = f.read()`, line 285; segments run to 64 MB) and the export
    accumulates into an in-memory `bytearray` capped only at
    EXPORT_MAX_BYTES (512 MB). On the Pi-class hardware in the roadmap,
    one case export can stall recording for seconds and spike memory by
    ~0.5 GB.
    Concrete fix: snapshot the segment list under the lock, release it,
    then read/filter outside the lock (segments are immutable once
    rotated; re-check existence per file); stream the export to a temp
    file instead of a bytearray, or lower the in-memory cap.

### Low

11. [Low] netmon/health.py:48-50,269-279 — two unguarded resource paths in the "never break startup" module
    What is wrong: (a) `setup_logging()` guards the `mkdir` (lines 44-47)
    but not the `RotatingFileHandler` construction (lines 48-50). On
    Windows, if orion.log is locked by a second brutedash instance or an
    AV scan, the handler raises PermissionError/OSError; run.py calls
    `setup_logging()` bare in `main()`, so startup crashes before the
    dashboard binds — the opposite of the function's stated contract.
    (b) `write_diagnostics_bundle` opens `sqlite3.connect(...)` directly
    (line 269) and closes it only on the success path (line 279); if the
    integrity check raises, the except path writes the failure file but
    the connection handle leaks (one per failed bundle; bundles are also
    written from the crash handler).
    Concrete fix: wrap handler creation in try/except OSError → return
    (console-only logging); use `contextlib.closing` / try-finally for
    the diagnostics connection.

12. [Low] app.py:313-320,74,90-101 — demo app: unbounded sample read, racy exists-check, connections leaked on error
    What is wrong: `sample_log()` reads the entire auth.log into memory
    on every GET / with no size cap and no OSError guard — the
    `os.path.exists` check (line 317) and the `open` (line 318) race, so
    a sample file deleted/rotated between them 500s the landing page, and
    a grown sample file is a per-request memory load. Separately,
    `get_db()` (line 74) connects with the sqlite3 default 5s busy
    timeout (netmon uses 30s), and `save_detections`/`known_ips` close
    the connection only on the success path — an INSERT failure (locked
    detections.db under concurrent demo traffic) leaks the handle.
    Concrete fix: cap sample_log reads (e.g. first 256 KB) and wrap in
    try/except OSError → ""; use try/finally (or `closing`) in
    known_ips/save_detections and pass timeout=30 to connect.

13. [Low] netmon/detect.py:41-60,738-754 — stale local-IP cache for process lifetime; arp_spoof shape-2 is an unbounded N+1 query loop
    What is wrong: (a) `_LOCAL_IPS_CACHE` is populated once and never
    refreshed, so after a DHCP address change the sensor box's own new IP
    is labelled "device <ip>" (and its old IP mislabelled "this
    computer") until restart — wrong attribution in alert titles/emails.
    (b) `check_arp_spoof` shape 2 iterates every distinct IP in the
    30-minute window (line 738) issuing 2-3 separate lock-taking DB calls
    per IP (lines 741-754, plus get_first_seen/note_first_seen); on a
    busy whole-network LAN the pass duration grows linearly with device
    count and can overrun the 60s DETECT_INTERVAL, delaying every other
    rule behind it (run_all is sequential).
    Concrete fix: (a) refresh the cache when the lookup returns an IP not
    in it, or expire it hourly. (b) batch shape 2 into one grouped query
    (ip → array of MACs) and one first_seen lookup for all IPs.

## NON-FINDINGS (checked and clean)
- watchdog.py DB resilience (2026-10-11 fix): start_outage/end_outage are
  guarded, the thread keeps pinging, outage ids are retained for retry —
  verified in source.
- pipeline.py watermarks/staleness/disk guard: every public helper is
  exception-contained, missing watermark = unknown (never stale), disk
  pressure suppresses loop-down double-alerting — verified.
- notify.py: bounded queue (100, oldest shed + counter), async worker,
  SMTP timeout=30, failure-streak self-alert — verified.
- ai_assist.py:64 / explainer.py:316 OpenAI timeout=30 — verified (app.py:169
  in finding 4 is the remaining unpatched call site).
- threatintel.py feed fetches: timeout + size cap + retry backoff, never
  raises into the loop — verified.
- ingest.py parse_pfirewall resumed-read header fix and inode rotation
  handling — verified; run_detection_rules isolates each rule.
- capture.py run_pcap streams via PcapReader (no whole-file load) and the
  dashboard /pcap path runs it under isolated_db + notifications_paused —
  verified. (A corrupt pcap mid-iteration still propagates out of
  run_pcap as a Flask 500 on that one request — noted, not ranked: the
  isolated DB contains the blast radius to the upload request itself.)
- detector.py 2026-10-11 fixes (primary-first byte cap, truncated-"from "
  guard) — verified in source.

## TEST BASELINE
`./venv/bin/python -m unittest discover -s tests` — 807 tests, OK
(23.5s, venv python). No failures. (The trailing S-PROMPTFMT / B-EVAL
lines in the output are the release-gate analyzer's documented
pre-existing noise, not test failures.)

VERDICT: NEEDS WORK
