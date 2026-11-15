# ROBUSTNESS VERDICT — brutedash @ 481b417 — NEEDS WORK

No Critical. 1 High (new, regression from a shipped fix), 2 Medium, 3 Low.

## Prior-item verification

- **R1 shipped** (85e4ead): verified — `capture.py:618ff` flusher uses private `flush_stop`, shared event never set.
- **R2 shipped** (03116a4, 2026-11-10): paging/watermark code present — **but introduces N1 below.**
- **R3 shipped** (85e4ead), **R4 shipped** (85e4ead), **R5 shipped** (85e4ead): present per commit + source spot-check.
- **R6 shipped** (e0d52f0, 2026-11-12): verified — `rewind.py` tracks `_seg_path`, `enforce_caps` skips active segment in both loops.
- **R7 shipped** (530ef60, 2026-11-14): `retention.py:63-64,94-96` prunes `host_events` (90d, own window) and `device_hostnames` (30d); `config.py:113-114`. Curated `device_names` untouched. **But see N2.**
- **R8 shipped** (85e4ead): verified — `threatintel.py` `reverse_dns` marks failures `"neg"`, short TTL only; definitive answers keep 7d.
- **R9 STILL PRESENT** — see L1. **R10 STILL PRESENT** — see L2.

## High

**N1 — R2 fix regressed ingest: unbounded whole-backlog materialisation + watermark never advances on a no-match pass; rules re-scan all history every 5 min, synchronously, in the monitor loop**
- Where: `netmon/ingest.py:489-526` (`_new_events`), `:529ff` (all four `check_*` rules), `netmon/run.py:194` (`safe_step("ingest", _ingest)` — no `timeout=`, unlike amass/nuclei).
- What breaks: (a) `_new_events` pages **all** rows since the watermark into one list `out=[]` — no cap; filtering by source/event_id is done in Python *after* `host_events_since` (which filters only on `ts`), so every rule walks every host event. (b) If no *matching* event exists, the rule returns 0 and never stamps its watermark — the next pass re-pages the entire history again. (c) `check_failed_logons` additionally does 3 DB queries *per event* (correlation, `ingest.py:~545ff`) and an O(n²) burst scan (`ingest.py:563`). A routine large backlog (monitor down a weekend; first run; 90 days of `host_events` now retained per R7) therefore wedges the monitor loop for minutes-to-unbounded time per pass, every pass — loop tick goes stale, heartbeat reports loop-down, detection/feeds stall behind it. The old 5,000 cap was a silent-skip bug; the fix traded it for a memory/liveness bug.
- Fix: stream per page — process and discard each 5,000-row page, advancing the watermark to the newest ts *scanned* (not merely matched) when a page yields no matches; push source/event_id filtering into `host_events_since` SQL; cap pages per pass with carry-over; give the ingest `safe_step` a `timeout=` like amass/nuclei; replace the O(n²) burst scan with a two-pointer window.
- Reproduced: YES — scratch DB, 12,000 non-matching firewall events: `check_failed_logons()` fetched all 12,000 rows, watermark stayed `None`, second pass fetched all 12,000 again; `_new_events(0)` returned all 12,000 rows in one list. 3,000 matching 4625 events processed in 0.3s, scaling quadratically + 9,000 correlation queries.

## Medium

**N2 — Retention holds the global DB lock for an entire table prune; first R7 prune can stall capture flush and every dashboard query**
- Where: `netmon/retention.py:133-165` (`_prune_table`: `with dbm._lock:` wraps the whole `while True` batched-delete loop, `:143`); `netmon/db.py:43` — same non-reentrant `Lock` guards `insert_flows`, `query`, etc.
- What breaks: batches commit individually but the lock is never released between them. Pruning a legacy unbounded table (exactly what R7 now does first-run for `host_events`/`device_hostnames` — potentially 100k+ rows) blocks the capture flusher and all dashboard reads for the full duration; the flusher thread parks, flow buffers fill to `MAX_FLOWS` and shed data.
- Fix: acquire `dbm._lock` per batch only (move `with` inside the `while`), optionally sleep/yield between batches.
- Verified: source-only (lock scope and shared-lock use inspected directly).

**L1/R9 — STILL PRESENT: quiet-hours wrap window checks the wrong weekday after midnight**
- Where: `netmon/notify.py:402-440` (`in_quiet_hours`): `day not in days` tested once with today's weekday before the wrap branch `mins >= start or mins < end` — the `mins < end` half is never attributed to yesterday.
- What breaks: "Fri 22:00–06:00" is not quiet Sat 03:00; silenced High/Critical mail sends at 03:00. Unchanged from 2026-11-08 (reproduced then: Fri 23:00 True, Sat 03:00 False).
- Fix: evaluate `mins >= start` against today, `mins < end` against `(day-1) % 7`.

## Low

**L2/R10 — STILL PRESENT: nuclei/amass JSONL parsing reads the whole file into memory twice**
- Where: `netmon/nuclei.py:399-405`, `netmon/amass.py:350-356` — `parse_jsonl_text(fh.read())`, then `text.splitlines()` makes a second copy; per-line/total caps are only consulted afterwards. Docstrings still claim line-by-line parsing.
- What breaks: a runaway/chatty scanner output (100s of MB) peaks at ~2–3× file size in the monitor process; OOM risk on the target small box.
- Fix: stream `for line in fh` with per-line cap, line counter, and a hard byte cap (e.g. 256 MB), keeping partial findings.
- Verified: source-only, unchanged at HEAD.

**L3 — Notify worker has the pre-fix canary pattern: a dead worker is never restarted**
- Where: `netmon/notify.py:56,96-102` (`_ensure_worker`): `_worker_started` bool set once, thread object not even retained, no `is_alive()` check — the exact defect R4 fixed in `canary.py`.
- What breaks: if the worker thread ever dies (its loop guards job exceptions, so this needs a `BaseException`/queue failure — rarer than canary's socket death, hence Low), alert/digest email silently stops for the process lifetime while `_ensure_worker` keeps returning as if running.
- Fix: retain the thread, treat "started but not alive" as stopped and restart, mirroring `canary.start()` / `quarantine.ensure_worker()`.
- Verified: source-only.

## Non-findings (checked, clean)

`capture.py` hot path caps (flows/DNS/hostname/TTL/`_mac_seen` all bounded; flush isolates per-buffer failures); `pipeline.safe_step` timed detach + in-flight registry; `watchdog.py` concurrent pings with DB-failure-isolated outage bookkeeping; `rewind` export streaming + R6 active-segment guard; `db.py` double-checked init, 30s busy timeout, WAL; `scan.py` workers bounded by per-connect timeout (unbounded `join()` is therefore bounded in practice); subprocess calls in relay/selfcheck/swaudit/health all carry timeouts; OpenAI clients in `ai_assist.py`/`explainer.py` set `timeout=30`; pcap upload capped at 100 MB and analysed against an isolated scratch DB.

**Recommended batch:** N1 first (High, reproduced, regression), then N2 (same "one pass stalls everything" shape); L1+L2 are the carried staged items and fit the same cycle.
