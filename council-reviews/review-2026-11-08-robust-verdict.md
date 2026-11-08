# Council review 2026-11-08 — ROBUSTNESS verdict (brutedash / Project Orion)

Read-only review at git HEAD `75ffce6` (main, up to date with origin/main).
Scope: app.py, detector.py, ipintel.py, netmon/run.py, capture.py,
pipeline.py, db.py, rewind.py, ingest.py, detect.py, watchdog.py,
health.py, scan.py, weekly.py, retention.py, config.py, plus canary.py,
selfcheck.py, swaudit.py, notify.py, threatintel.py, quarantine.py,
relay.py, nuclei.py, amass.py, explainer.py, dashboard.py (rewind/pcap
routes). Lens only: crashes, hangs, unhandled exceptions, Windows
quirks, thread deaths, cache staleness, detection-rule edge cases.

Eight of ten findings were empirically reproduced with
`council-reviews/repro-2026-11-08-robust.py` (venv python, isolated
scratch DBs, monkeypatched boundaries — no production data touched).
Test baseline: `python -m unittest discover -s tests` — 976 tests, OK.

## VERDICT: NEEDS WORK

## Prior-fix verification (checked in current source, not re-flagged)

- Rewind export streaming (H1, fixed Nov 2): FIXED. Production path is
  streamed — `netmon/rewind.py:391 export_window_to_file()` writes one
  record at a time; `netmon/dashboard.py:3870-3874` streams it to a temp
  file and serves 64 KB chunks with unlink in the stream's finally.
  (The old in-memory `export_window()` at rewind.py:347 survives only
  as a test helper; no production caller — grep-verified.)
- Detector chunked reading (M4, fixed Nov 3): FIXED. `detector.py:61
  _iter_capped_lines()` reads 64 KB chunks (`_READ_CHUNK_BYTES`,
  detector.py:30), caps each line at 1 MB before parsing
  (`MAX_LINE_BYTES`, detector.py:29), and counts discarded bytes
  toward the 64 MB total.
- Ingest XML streaming (M5, fixed Nov 4): FIXED. `netmon/ingest.py:331
  _stream_security_xml()` uses `ET.iterparse` (line 349), clears each
  Event element, and emits bounded 1000-event batches; production
  ingestion never materialises the full list.
- Rewind enforce_caps isolation (L6, fixed Nov 5): FIXED for the stat /
  unlink accounting it targeted — per-file stat with skip-on-OSError
  and decrement-only-on-success at `netmon/rewind.py:285-311`. (Finding
  R6 below is a different defect in the same function: the ACTIVE
  segment is not excluded from eviction.)
- App sample-log cap + sqlite timeout (L7, fixed Nov 7): FIXED.
  `app.py:390 SAMPLE_MAX_BYTES = 256 * 1024`, read at app.py:402;
  `timeout=30` at app.py:77 and ipintel.py:43.
- ipintel close-on-all-paths + negative cache (L8, fixed Nov 8): FIXED.
  `ipintel.py` closes the handle in a `finally` on every path and
  negative-caches failures for `NEGATIVE_CACHE_TTL = 10 * 60`
  (ipintel.py:35).
- Staged leftover — host_events / device_hostnames retention growth:
  **STILL PRESENT.** See finding R7.
- Staged leftover — weekly-scan last-run stamp on failure: **STILL
  PRESENT for nuclei and amass; FIXED for the built-in LAN scan.**
  scan.py stamps `vuln_scan_last_ts` only after a completed run
  (netmon/scan.py:362). Nuclei/amass still stamp at launch — see R3.

## Findings

### Critical
None.

### High

**R1 — A transient sniff() failure permanently kills capture AND the
monitor loop: run_live sets the shared shutdown event on exit**
- Severity: High
- Where: `netmon/capture.py:652-656` (the `finally:` under the sniff
  loop does `stop_event.set()`), combined with `netmon/run.py:335,359,
  381` — the SAME `threading.Event` is passed to `run_live`
  (capture thread), to `_monitor_loop` (`while not
  stop_event.wait(...)`, run.py:132), and to the flusher.
- What breaks, and when: `_prn` guards per-packet errors, but `sniff()`
  itself is unguarded — an Npcap/driver hiccup, the interface vanishing
  (USB Wi-Fi dongle, sleep/resume), or a permission error raises out of
  the loop. The `finally` then sets the shared event, which (a) tells
  the monitor loop to exit at its next wait — detection, feeds, digests,
  retention all stop for the life of the process — and (b) defeats the
  batch-14 capture watchdog (`pipeline.ensure_capture`): a restarted
  capture thread enters `run_live`, sees `stop_event.is_set()`, and
  returns instantly, burning the 3-restarts/hour budget on no-ops.
  The dashboard stays up and looks alive; only the external heartbeat
  notices, ~10 minutes later, via the stale loop tick. One transient
  driver error becomes a total, silent monitoring outage until a human
  restarts the process.
- Concrete fix: never set the caller's event. Give `_flush_loop` its
  own private stop event inside `run_live` (set that in the `finally`;
  the sniff loop already exits within `SNIFF_TIMEOUT` of the shared
  event being set at real shutdown, after which the private event
  triggers the final flush and the bounded join). Add a regression
  test: sniff stub raises → shared event still clear, and a second
  `run_live` call with the same event actually calls sniff again.
- Reproduced: YES — repro R1: stubbed `sniff` raising
  `RuntimeError`; after `run_live` raised, `stop_event.is_set()` was
  True, and a "restarted" `run_live` returned without ever calling
  sniff (call count stayed 1).

### Medium

**R2 — Ingest detection rules silently skip the oldest events of any
backlog over 5,000, then advance the watermark past them forever**
- Severity: Medium
- Where: `netmon/ingest.py:486-487` (`_new_events` fetches
  `host_events_since(since, limit=5000)`), `netmon/db.py:2918-2928`
  (that helper is `ORDER BY ts DESC LIMIT ?` — newest first), and the
  unconditional watermark stamps, e.g. `netmon/ingest.py:575`
  (`check_failed_logons` sets `ingest_correlate_4625_ts` to `now` after
  processing whatever it got; the 7045/USB/Defender checks have the
  same shape).
- What breaks, and when: the rules receive only the NEWEST 5,000
  events since the watermark. Any older events in the same backlog are
  never evaluated — and because the watermark then jumps to `now`,
  they can never be evaluated later either. The backlog is routine,
  not exotic: the monitor is down for a weekend (or ingestion is
  paused) while Windows keeps exporting, and the next poll inserts
  tens of thousands of stored events at once. A 4625 brute-force burst
  sitting in the older half of that backlog produces no alert, no
  correlation, and no trace that anything was skipped — a silent
  detection hole in exactly the recovery pass that should catch up.
- Concrete fix: page instead of capping once — loop
  `host_events_since` in ascending-ts pages (or raise the fetch to an
  explicit cursor: process in ts order and advance each rule's
  watermark only to the newest ts actually processed, never to `now`).
  At minimum, set the watermark to `max(ts of processed events)` so an
  over-cap remainder is retried next pass instead of discarded.
- Reproduced: YES — repro R7: isolated DB, 6-event 4625 burst from
  203.0.113.9 followed by 6,000 newer filler events;
  `check_failed_logons()` fired 0 alerts and stamped the watermark
  ~100,000 s ahead of the burst.

**R3 — STILL PRESENT (staged leftover): nuclei and amass stamp
"last run" at launch, so one failed scan suppresses retries for a
full week**
- Severity: Medium
- Where: `netmon/nuclei.py:564` (`maybe_weekly_nuclei` does
  `set_meta("nuclei_scan_last_ts", now)` BEFORE `start_nuclei_async()`)
  and `netmon/amass.py:557` (identical with `amass_last_ts`). Neither
  failure path clears it: nuclei's `run_full_nuclei_scan` failure
  returns (netmon/nuclei.py, `except`/not-ok paths) only reset the
  `*_running` flag in `finally`; the success stamp at nuclei.py:504
  never runs. Amass's `run_domain_scan` never stamps `amass_last_ts`
  at all — the launch stamp is the only one. Contrast: the built-in
  scan does it right (netmon/scan.py:362, success-only).
- What breaks, and when: one transient failure — binary crash,
  subprocess timeout (`timeout_min*60 + 300` for nuclei), a DB hiccup —
  consumes the entire weekly slot. The next monitor pass sees
  `now - last < WEEK_SECONDS` and skips; the box goes up to 7 days
  with no deep/external scan after a single bad run, with the
  dashboard showing a fresh-looking "last run" time.
- Concrete fix: stamp at launch only under a separate in-flight key
  (e.g. `nuclei_scan_started_ts`), and have the failure paths restore
  `*_last_ts` to the previous successful value (or delete the launch
  stamp); stamp `*_last_ts` on success only, as scan.py does.
- Reproduced: YES — repro R5: with the binary/targets stubbed present
  and the async launch stubbed to a scan that fails, both
  `maybe_weekly_nuclei()` and `maybe_weekly_amass()` stamped their
  last-run meta and a second (retry) call returned None for both.

**R4 — Canary trap: a dead listener thread is never restarted —
start() trusts the `running` flag, not the thread**
- Severity: Medium
- Where: `netmon/canary.py:189-190` (`start()`: `if
  _state["running"]: return True`, with no liveness check),
  `netmon/canary.py:234-240` (`ensure_running()` correctly checks
  `is_running()` — running flag AND `thread.is_alive()`,
  canary.py:78-81 — then calls the `start()` that ignores it), and
  `netmon/canary.py:147-148` (`_serve` breaks out of its accept loop
  on any `OSError` without clearing `_state["running"]`).
- What breaks, and when: if the accept loop dies (socket error, the
  socket closed underneath it — routine on Windows after sleep/resume
  or a driver reset), `_state["running"]` stays True forever.
  `ensure_running()` runs every monitor pass, sees the dead thread,
  calls `start()`, gets `True` back, and nothing is ever rebound. The
  tripwire is silently down while `status()` keeps reporting the
  configured port; a scanner can knock on the whole LAN without
  tripping the one High alert designed to catch exactly that.
  (Contrast: quarantine.py's `ensure_worker` checks `is_alive()` —
  the correct pattern already exists in the codebase.)
- Concrete fix: in `start()`, treat "running but thread dead" as
  stopped: under `_lock`, if `_state["running"]` and the recorded
  thread is not alive, fall through to the bind path (closing any
  stale socket first). Also have `_serve` clear `_state["running"]`
  in a `finally` when its loop exits.
- Reproduced: YES — repro R2: `_state` seeded with `running=True` and
  a joined (dead) thread; `is_running()` was False, `start()` returned
  True, `is_running()` was still False afterwards.

**R5 — Self-check: a failed netstat on Windows learns an EMPTY
listening-port baseline, then flags every real port as drift on
recovery**
- Severity: Medium
- Where: `netmon/selfcheck.py:90-124` (`check_listening_ports`): the
  empty-result guard at lines 102-106 applies only when NOT Windows
  (`if not current and not _is_windows():`), so on Windows an empty
  set falls through to the baseline-learn branch (lines 117-124) and
  is stored as the baseline. `_windows_listening_ports`
  (selfcheck.py:71) returns an empty set whenever `_run(["netstat",
  ...])` fails, times out (15 s), or exits non-zero. The sibling check
  does this right: `check_services` (selfcheck.py:131+) returns
  `"error"` on an empty enumeration instead of learning it.
- What breaks, and when: one transient netstat failure on a Windows
  box (the product's primary platform) poisons the baseline to zero
  ports. The next successful run — up to 6 h later — reports every
  genuinely-listening port (SMB, the dashboard itself, …) as "new
  listening ports vs baseline" and fires the Medium self_drift alert:
  a false alarm naming the box's normal services, training the owner
  to ignore the real drift alert. A baseline learned during a
  first-run netstat failure persists until manually cleared.
- Concrete fix: treat an empty Windows result as `"error"` (like
  `check_services`): if `_is_windows()` and not `current`, return
  `("error", "could not read listening ports", set())` and never
  learn a baseline from it.
- Reproduced: YES — repro R6: `_is_windows` stubbed True, `_run`
  stubbed to `""` → `("ok", "baseline learned: 0 listening ports")`;
  with netstat "recovered" ({TCP 445, TCP 5001}) the next check
  returned `("drift", "new listening ports vs baseline: TCP:445,
  TCP:5001")`.

**R6 — Rewind enforce_caps can unlink the segment that is actively
being written (POSIX data loss; Windows retry churn)**
- Severity: Medium
- Where: `netmon/rewind.py:254-311` (`enforce_caps`): both the
  time-cap loop (from line 266) and the size-cap eviction loop (from
  line ~299) iterate `_segments()` with no exclusion of the live
  segment held in `_seg_file` / `_seg_start` (rewind.py:51). Segment
  files are named by their open epoch (`_rotate`, rewind.py:144-176)
  and rotate only every `SEGMENT_SECONDS = 300`, while `_caps()`
  (rewind.py:~117) permits `rewind_minutes` as low as 1.0 and the
  monitor loop calls `enforce_caps` every 60 s (netmon/run.py `_rewind`
  step) — so an open segment's name legitimately ages past a small
  configured cutoff while packets are still being appended to it.
- What breaks, and when: with `rewind_minutes` set below 5, the 60 s
  sweep unlinks the active segment. On POSIX the unlink succeeds:
  `record_packet` keeps writing to an unlinked inode, `status()`
  under-reports the buffer, and the forensic window the owner later
  exports silently lacks everything since the unlink — evidence loss
  in exactly the buffer kept for post-incident review. On Windows the
  unlink raises `OSError` (open file) and is retried every sweep.
  Defaults (60 min) are safe; the defect needs only a plausible
  small-retention configuration, which `_caps` explicitly accepts.
- Concrete fix: exclude the active segment from eviction — track its
  path at `_rotate` time and skip it in both loops of `enforce_caps`
  (it becomes evictable at the next rotation), and/or clamp
  `rewind_minutes` to at least `SEGMENT_SECONDS / 60` in `_caps()`.
- Reproduced: YES — repro R8: active segment aged 120 s (mid-rotation
  lifetime) with retention stubbed to 1 minute; after
  `enforce_caps()`, the file no longer existed while `_seg_file` was
  still open and writable.

### Low

**R7 — STILL PRESENT (staged leftover): host_events and
device_hostnames are never pruned; the hostname map full-scans the
unbounded table on every asset sync**
- Severity: Low
- Where: `netmon/retention.py:45-54` (`_PRUNE_SQL`) and
  `netmon/retention.py:72-82` (`_TABLES`) — flows, dns_queries,
  arp_observations, summaries, outages, score_snapshots, alerts only;
  no DELETE anywhere targets `host_events` or `device_hostnames`
  (grep-verified). Meanwhile `netmon/db.py:2358-2366`
  (`device_hostname_map`) SELECTs the whole `device_hostnames` table
  and folds it in Python, and it is called on every asset refresh
  (`netmon/assets.py:102`, refreshed whenever assets are stale, i.e.
  up to hourly). Capture appends hostname rows on every flush (up to
  1,000 buffered DHCP/mDNS rows per 15 s flush, netmon/capture.py
  `handle()`/`flush()`).
- What breaks, and when: nothing crashes — the DB grows without bound
  for the life of the install and the per-sync scan grows with it, so
  the dashboard's asset path gets steadily slower on exactly the
  long-lived small boxes this targets. `host_events` grows with every
  ingested Windows log forever. (`first_seen` also only grows — one
  row per distinct key, much slower; noted, not ranked.)
- Concrete fix: add both tables to retention — `device_hostnames`
  under `observations_days` (30 d) and `host_events` under a new
  `host_events_days` (default 90) — and/or push the
  latest-per-MAC fold into SQL (`GROUP BY mac` with max(ts)).
- Reproduced: NO — source-only (grep + source inspection above).

**R8 — reverse_dns caches a FAILED or TIMED-OUT lookup as a
definitive empty result for 7 days**
- Severity: Low
- Where: `netmon/threatintel.py:416-452` (`reverse_dns`): the worker
  thread's exception path and the `t.join(3.0)` timeout path both
  leave `box` empty, and lines 447-451 then unconditionally write
  `{"ts": now, "name": ""}` to the meta cache with
  `_RDNS_CACHE_S = 7 * 86400` (threatintel.py:94). A slow resolver that
  would have answered at 3.5 s is indistinguishable from "no PTR
  record" — and is cached as such.
- What breaks, and when: one resolver hiccup (or one slow answer)
  poisons the cache per IP for a week: the dashboard shows no hostname
  for that address for 7 days even though DNS recovered seconds later,
  and the staleness is invisible (empty string is also the legitimate
  "no PTR" answer). Cache staleness of exactly the class L8 fixed for
  ipintel — but there the negative TTL is 10 minutes, here it is
  10,080.
- Concrete fix: cache only definitive outcomes — have `_go` record
  success/failure explicitly; write the cache row only on success
  (including a successful empty PTR answer), or use a short negative
  TTL (e.g. 10 min, mirroring ipintel) for failure/timeout.
- Reproduced: YES — repro R3: `gethostbyaddr` stubbed to raise →
  `reverse_dns` returned `""`; with the stub replaced by a working
  resolver, the second call still returned `""` from cache.

**R9 — Quiet hours: a window wrapping past midnight checks the
weekday of the wrong day, so the post-midnight half is not quiet**
- Severity: Low
- Where: `netmon/notify.py:402-440` (`in_quiet_hours`): the day test
  at lines ~416-423 uses the CURRENT weekday for the whole window;
  the wrap branch (line ~436, `inside = mins >= start or mins <
  end`) never considers that the `mins < end` half belongs to the
  window that started the PREVIOUS day.
- What breaks, and when: quiet window "Fridays 22:00–06:00" —
  Friday 23:00 is correctly quiet, Saturday 03:00 is not (day=Sat ∉
  [Fri]), so High/Critical alert emails and digests the owner
  explicitly silenced until 06:00 go out at 03:00. The mirror error
  also exists in reverse (a Saturday-only window is not quiet at
  Saturday 03:00 either — that half belongs to Friday's window, which
  doesn't exist — but IS treated as the tail of Saturday's own window
  on Sunday morning if Saturday is listed… the day attribution is
  simply off by one for the entire post-midnight segment).
- Concrete fix: for wrapping windows, evaluate both attributions: the
  `mins >= start` half against today's weekday, the `mins < end` half
  against yesterday's weekday (`(day - 1) % 7`).
- Reproduced: YES — repro R4: window `{days:[4], 22:00–06:00}`;
  Fri 2026-11-06 23:00 local → True; Sat 2026-11-07 03:00 local →
  False (expected True).

**R10 — nuclei/amass output parsing reads the whole JSONL file into
memory (twice), despite the "parsed line-by-line" design claim**
- Severity: Low
- Where: `netmon/nuclei.py:397-401` and `netmon/amass.py:348-352`
  (`parse_jsonl_file` does `fh.read()` — unbounded — then
  `parse_jsonl_text` does `text.splitlines()`, a second full copy).
  The per-line (1 MB) and total-line (200k) caps are only consulted
  afterwards, line by line, over the already-materialised text. Both
  module docstrings promise "Bounded output parsing: JSONL parsed
  line-by-line" (nuclei.py:31, amass.py:28) — the file path does not
  honour it.
- What breaks, and when: scanner output size is bounded by run time,
  not bytes. A long nuclei run against 64 targets with chatty
  templates (or a malfunctioning/forked binary writing runaway
  output) can leave a JSONL file in the hundreds of MB; parsing it in
  the monitor/dashboard process peaks at ~2–3× the file size and can
  OOM the same small box R1/H1-style — this time via the scheduled
  scan path. Realistic files are far smaller, hence Low.
- Concrete fix: stream the file — iterate `for line in fh` in
  `parse_jsonl_file`, enforce `MAX_JSONL_LINE` per line and
  `MAX_JSONL_LINES` as a counter, and stop reading past a hard byte
  cap (e.g. 256 MB) with the partial findings kept.
- Reproduced: NO — source-only.

## Non-findings (checked and clean)

- pipeline.py: safe_step timed detach + in-flight registry, watermark
  unknown-never-stale semantics, capture restart budget, disk-pressure
  suppression of the loop-down double-alert — all intact.
- db.py: double-checked-locking init, reconnect proxy (dead-error
  only, stays closed after explicit close), bounded lock-retry
  (5 attempts), writability probe persists nothing.
- detect.py: pass-scoped device maps, single-query arp_spoof,
  300 s local-IP TTL with loopback floor, per-rule isolation in
  run_all. (The DST fall-back hour double-counts one hour-cell in
  device profiles for one day in 14 — cosmetic, not ranked.)
- watchdog.py: concurrent pings, outage bookkeeping failures logged
  and retried without killing the thread, locale-independent gateway
  discovery. health.py: heartbeat timeout=10, bundle sections
  isolated, bundle sqlite handle closed in finally.
- scan.py (built-in): single-scan claim released in `finally` on
  every path; last-run stamp on success only (see R3 contrast).
- capture.py hot path other than R1: ScanTracker DB calls fire after
  lock release and are guarded; flush writes each buffer in its own
  guard with counted drops; C1 caps (flows / DNS buffer / scan
  sources) present; sniff loop observes stop within SNIFF_TIMEOUT.
- quarantine.py worker: `ensure_worker` checks `is_alive()` (the
  pattern R4 asks canary to copy); per-device poison failures
  isolated. notify.py: bounded queue (100, oldest shed + counter),
  SMTP timeout=30, worker loop guarded per job.
- detector.py / app.py / ipintel.py: clean apart from the verified
  fixes above — no new robustness findings this cycle.

## Reproduction

All repro snippets: `council-reviews/repro-2026-11-08-robust.py`
(run with `venv/bin/python`; uses isolated scratch DBs throughout —
R1–R8 all print PASS-DEFECT at HEAD 75ffce6).
