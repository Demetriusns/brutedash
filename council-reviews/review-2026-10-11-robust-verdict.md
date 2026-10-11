I have verified my findings against the actual source. Here is my structured review.

FINDINGS:
1. [High] detector.py:93,113-117 — 64MB byte cap can silently skip the PRIMARY auth.log
   What is wrong: `sources = _rotated_siblings(log_path) + [(log_path, False)]` (line 93) scans siblings oldest-first with the current log LAST. When `bytes_read > MAX_TOTAL_BYTES` in any source, line 117 does `break` — "stop merging further sources" — so if old rotated siblings consume the 64MB cap, the freshest file (the primary auth.log) is never scanned and the detector silently returns partial/stale findings. Worse, line 96 `if os.path.getsize(src) > MAX_TOTAL_BYTES: continue` skips even the primary itself when auth.log alone exceeds 64MB — before commit 620c2ea the primary was always fully read.
   Failure scenario: Verbose SSH logging fills rotated siblings past 64MB; today's live brute-force campaign in auth.log is scored as "No brute-force activity detected." This directly inverts the hardening fix the commit was written for.
   Concrete fix: Always scan the primary. Either put the primary first (`sources = [(log_path, False)] + siblings` and break only after it), or apply the byte cap to siblings only and read the primary uncapped.

2. [High] detector.py:80 — IndexError crash on a log line ending with "from " (empirically confirmed)
   What is wrong: `_count_line` guards only on `if "from " not in line:` then does `ip = line.split("from ", 1)[1].split()[0]`. A line whose last token is "from " (truncated/wrapped log line) yields `""` → `.split()` → `[]` → `IndexError: list index out of range` (reproduced locally). The line loop's `except OSError` (line 118) does not catch IndexError, so it propagates out of `detect_brute_force`.
   Failure scenario: A user pastes such a log into app.py's POST handler — app.py:228 calls `detect_brute_force(tmp_path, threshold=3)` with no try/except around it → Flask 500 on the request. Any scheduled scan consuming syslog-format auth logs with a wrapped line crashes the whole detection pass.
   Concrete fix: Guard the extraction: `tail = line.split("from ", 1)[1].split(); if not tail: return; ip = tail[0]` — or wrap `_count_line`'s body per-line in try/except that logs and continues.

3. [High] watchdog.py:157,161 — unguarded DB calls kill the watchdog thread permanently; no liveness check
   What is wrong: Inside `Watchdog.run()`, `dbm.start_outage(label, now)` and `dbm.end_outage(oid, now)` are unguarded. `start_outage` does `conn.commit()` under the module lock (db.py:2239-2246); `_db()`/`commit` can raise (locked past the 30s busy timeout under heavy capture writes, corrupt DB, disk full on commit). The exception escapes `run()` → the watchdog thread dies once and is never restarted.
   Failure scenario: One DB hiccup stops all outage logging for the rest of the run. Nothing notices: run.py restarts only the capture thread via `pipeline.ensure_capture`; the dashboard (dashboard.py:3971-3972) keeps rendering the last `watchdog.current()` status as if live. A dead gateway/watchdog looks "up" forever.
   Concrete fix: Wrap the DB calls in try/except inside the loop (log one stderr line, keep pinging; retry the bookkeeping next pass), and add a `_watchdog_alive` tick check to the monitor loop or the dashboard's `_loop_watchdog_tick` so a dead watchdog raises a self-alert.

4. [Medium] pipeline.py:262-269 — note_loop_tick swallows the write failure, so the "tick stamped even when disk is full" guarantee is hollow
   What is wrong: `note_loop_tick` catches all exceptions from `dbm.set_meta` and returns None. run.py's own docstring claims "The tick is stamped even when the disk is full — a dead loop must be distinguishable from a paused one," but on a full disk `set_meta` cannot write, so the stamp fails silently. `loop_tick_fresh` then returns None ("unknown, never stale") and `check_loop_down` (pipeline.py:294-310) explicitly bails out under `disk_pressure()` too — a loop that dies during disk pressure is invisible to the loop-down watchdog, and nobody is told the tick mechanism is down.
   Failure scenario: Disk fills; monitor loop dies 20 minutes later; `check_and_alert_loop_down` never fires because fresh is None, and the disk-full alert (fired hours earlier) is the wrong diagnosis.
   Concrete fix: Either drop the "stamped even when full" claim from run.py's docstring, or persist the tick outside SQLite (a small file in the config/logs dir — still vulnerable to a full disk, but then `check_loop_down` should report the tick-write failure as its own alert rather than collapsing to "unknown").

5. [Medium] weekly.py:47-148 — generate_weekly_report crashes on any DB hiccup instead of degrading
   What is wrong: The module docstring promises "The report degrades gracefully: an empty database still produces a readable 'quiet week' report instead of an error." That holds for empty tables, but every `dbm.query(...)` in `generate_weekly_report` is unguarded — a locked/corrupt DB or a missing `flows`/`alerts` table raises straight out (only the optional `first_seen` query has try/except). `--weekly-report` then exits with a traceback.
   Failure scenario: A WAL-lock contention on the weekly cron run turns a routine report into a crashed job with no output instead of a degraded "couldn't read the database" report.
   Concrete fix: Wrap the query blocks in try/except and fall back to empty/unknown sections, or wrap the whole report body so the CLI prints a graceful message and returns nonzero-free.

NON-FINDINGS (checked and clean):
- pipeline.safe_step coverage of _monitor_loop: all 14 step bodies run through `safe_step`, which never raises — a failing step logs one stderr line and the loop continues. Verified against run.py:100-212 and pipeline.py:762-769.
- retention._prune_table: alert pruning deletes mappings and alerts in the same transaction under dbm._lock with identical ORDER BY id LIMIT subqueries — no cross-batch skew; failures log and continue to the next table. Verified retention.py:112-148.
- threatintel.maybe_refresh_feeds: lock-guarded, interval + retry backoff, "Never raises". Verified threatintel.py:248-277.
- Watchdog gateway discovery: subprocess calls have timeouts, full exception swallow, and three locale-independent layers before falling back to 192.168.1.1 — no startup crash path. Verified watchdog.py:45-79.
- env_compat in run.py: digest-hours parsing returns "" (not None) for a missing var and is wrapped in try/except — no AttributeError path. Verified config.py:208-222, run.py:279-287.

VERDICT: NEEDS WORK