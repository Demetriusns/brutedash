# Pipeline failure modes — detection pipeline robustness

How brutedash's detection pipeline breaks, what it costs when it does,
and what the pipeline does about it. Written for the operator: each mode
names what breaks, the blast radius, the behavior before this batch, and
the fallback that replaced it.

The pipeline: **capture** (scapy sniff → flows → SQLite) → **parse**
(flow aggregation, DNS/ARP/hostname buffers) → **rules** (the 23
detections in `netmon/detection_catalog.py`, run every 60s) →
**alert** (`db.add_alert`) → **incident** (case grouping) →
**notify** (email queue → SMTP worker) → **dashboard** (Flask + served
JS).

Three mechanisms carry the whole batch (`netmon/pipeline.py`):

- **trace_id** — one uuid4-hex id minted at rule-fire time in
  `db.add_alert`, stored on `alerts.trace_id`, carried onto
  `incident_alerts.trace_id`, handed to the notify hook, and shown on
  the dashboard as the "Follow-up ID". One id follows a single
  detection end to end. It never goes into emails or feeds — internal
  plumbing, with a test proving it.
- **Watermarks** — per-stage "last healthy" timestamps in `meta`:
  `last_flow_ts` (capture tick), `wm_rules_ts` (rule pass),
  `ti_feeds_refreshed_ts` (feed refresh), `wm_notify_ts`
  (notification). Surfaced in the dashboard's sensor-health view
  ("Pipeline health"). A missing watermark is *unknown*, never stale —
  a fresh install must not page on day one. When several stages go
  newly stale in the same pass, one combined self-alert fires at the
  highest member severity instead of one per stage.
- **Disk guard** — free-space check on the DB filesystem; below the
  threshold non-essential writes stop while detection keeps running.

Standing rules for every fallback:
1. A fallback that silently drops detections is worse than a crash —
   every degraded path either still lands the alert or logs loudly.
2. Quiet is a feature — fallback transitions log (stderr); they don't
   page the user. The only exceptions are the two self-alert cases:
   disk-full and a stage silent too long.

---

## 1. Capture thread dies

- **What breaks:** the scapy sniff loop raises (interface vanishes,
  permission lost, scapy hiccup) → the thread exits → no new flows.
- **Blast radius:** total blindness. Rules keep running on stale data
  and stay silent; the dashboard looks alive but sees nothing new.
- **Before:** the heartbeat's `_health()` reported "capture thread
  died" to healthchecks.io (`/fail`), and that was it — nobody
  restarted anything.
- **Fallback:** `pipeline.ensure_capture` restarts the thread, bounded
  at 3 restarts/hour, then gives up quietly. Past that, the
  stale-capture watermark (no `last_flow_ts` for 5+ min) fires one High
  self-alert (`self_drift`). Dashboard-only mode sets
  `pipeline_capture_expected=0`, so an intentionally-stopped capture
  never pages.

## 2. Malformed packets / parse errors

- **What breaks:** a crafted or corrupt packet makes the aggregator or
  a parser raise mid-flush.
- **Blast radius:** one flush's batch of flows is lost; the loop
  continues.
- **Before:** `_flush_loop` already swallowed per-flush exceptions.
- **Fallback:** unchanged — the loss is bounded to one flush window
  (60s), and it logs. Parse code paths that touch untrusted bytes
  (DHCP options, mDNS names, feed lines) sanitize or skip bad input
  rather than raising.

## 3. One detection rule crashes

- **What breaks:** a rule raises on poison input (e.g. a weird flow
  row) or a transient DB error.
- **Blast radius (before):** the whole 60s rule pass aborted — one bad
  rule blinded the other eight for that minute, and `run.py` swallowed
  it with a bare `except: pass`, so nobody ever knew.
- **Fallback:** `detect.run_all` now isolates each rule: the failure is
  logged with the rule's name (`netmon detect: <rule> failed: ...`)
  and the pass continues. The monitor loop counts whole-pass failures
  via `pipeline.note_rules_result`; 3 consecutive failures raise one
  Medium self-alert, cleared on recovery.

## 4. DB locked / busy (WAL contention)

- **What breaks:** capture writes flows while the dashboard reads and
  the monitor writes — SQLite returns "database is locked".
- **Blast radius:** the failed write's data (flows, an alert, an
  incident link) is lost.
- **Before:** the write raised; `run.py`'s bare `except: pass`
  swallowed it — a detection could vanish without a trace.
- **Fallback:** `db._write_with_retry` retries lock errors with
  backoff, strictly bounded at 5 attempts (no retry storms; a test
  asserts the exact bound). A lock that never clears propagates to the
  monitor loop, which logs it — loud, not silent. Non-lock errors raise
  immediately.

## 5. Disk full

- **What breaks:** every writer fails at once — flows, alerts,
  summaries, the packet buffer.
- **Blast radius:** everything, including the alert about the disk.
- **Before:** the rewind buffer had its own low-disk guard; nothing
  else did.
- **Fallback:** `pipeline.disk_pressure` (free < `monitor.disk_min_free_mb`,
  default 512) gates the monitor loop: detection rules and feed
  refreshes keep running; summaries, scans, ingest, digests, and
  reports pause. The rewind buffer pauses first (its own guard).
  `pipeline.disk_alert_once` fires one Medium self-alert per episode
  (flag cleared on recovery). The disk-full path is allocation-light —
  one stat call, small strings, one small row — and if even that row
  can't store, the stderr line is the record. Never raises.

## 6. Feed refresh fails (network down)

- **What breaks:** URLhaus / Emerging Threats / CISA KEV downloads
  fail — DNS down, no route, feed server error.
- **Blast radius:** threat-intel enrichment goes stale; detection
  itself keeps working.
- **Before:** failed refreshes kept old rows and backed off 1h (no
  retry storm) — but the dashboard showed the old "last updated" with
  no hint anything was wrong.
- **Fallback:** same keep-the-cache behavior, plus honesty:
  `ti_feed_status` marks each feed `stale` past 2× the refresh
  interval, and `ti_feed_health` reports `failed_recently` when the
  last attempt postdates the last success. The dashboard shows a
  "stale" badge per feed and a plain-English note: "showing the saved
  lists — detection keeps working from the saved lists." A feed stale
  36h+ also raises one Low self-alert.

## 7. SMTP down / not configured

- **What breaks:** the mail server refuses, credentials rot, or the
  network drops mid-send.
- **Blast radius:** High/Critical pages never arrive; the user thinks
  all is quiet.
- **Before:** `_maybe_send_alert` returned False silently — the only
  record was... nothing.
- **Fallback:** every send failure logs one stderr line; consecutive
  failures are counted on the worker thread; at 5 in a row, one Medium
  self-alert fires ("Alert emails aren't going out") — once per
  episode, cleared on the next successful send. Unconfigured SMTP stays
  a silent no-op (nothing configured = nothing promised). The notify
  watermark (`wm_notify_ts`) is stamped on success; 24h without one
  (after it once worked) raises a Medium self-alert via the staleness
  check.

## 8. LLM unavailable (no key / API error / timeout)

- **What breaks:** no `OPENAI_API_KEY`, provider "off", API error, or
  malformed model JSON.
- **Blast radius:** AI narration degrades; detection never depended on
  it.
- **Before:** `explainer.summarize` already fell back to the rule-based
  summary; `triage_verdict` and `answer_question` returned None
  (dashboard showed "unavailable").
- **Fallback:** the summarize fallback is unchanged (it works).
  `triage_verdict` now returns a deterministic rule-based second
  opinion built only from the alert's own plain-English fields and the
  detection catalog's false-positive notes — same `{"verdict",
  "reasoning"}` shape, labeled up front as the rule-based take, capped
  at 900 chars. `answer_question` answers plainly that the service is
  unavailable and points at the dashboard summary. No new model calls,
  no invented facts.

## 9. External binaries missing (nuclei / amass / bettercap)

- **What breaks:** the scheduled subprocess can't run — binary not
  installed or not on PATH.
- **Blast radius:** that scan's findings stop; everything else runs.
- **Before:** both scanners already degraded gracefully with install
  instructions in the UI.
- **Fallback:** unchanged — missing-binary is a normal state, not an
  error. Documented here so the enumeration is complete.

## 10. Corrupt rows

- **What breaks:** a bad JSON blob in `meta`, a NULL where code
  expects a string, a half-written row from a killed process.
- **Blast radius:** one listing, one page, one lookup — if the code
  lets it spread.
- **Before:** mostly guarded per-row (`get_assets`, KEV parsing,
  Amass JSONL); migrations wrapped in try/except.
- **Fallback:** same discipline, stated as policy: corruption is
  isolated per row (skip + log), never breaks a listing; migrations
  never break startup. New code follows the same pattern — the
  trace_id backfill and the pipeline meta reads are all guarded.

## 11. Clock skew (NTP jump, DST, VM suspend)

- **What breaks:** the wall clock jumps backwards or forwards —
  watermark ages go negative, cooldowns misfire, outage math breaks.
- **Blast radius:** false "stale" pages (clock jumped forward) or
  missed staleness (clock jumped back).
- **Before:** `outage_stats` already clamped with `max(0.0, ...)`.
- **Fallback:** watermark ages are clamped at zero (never negative);
  a backwards jump reads as "just now", and the stage re-marks on the
  next healthy tick. Cooldowns use the same monotonic-safe pattern:
  a stale flag set "in the future" simply delays the next alert.

## 12. Dashboard-only vs full-monitor confusion

- **What breaks:** the operator runs `--dashboard-only` (or capture
  was never requested) and the staleness check pages about a "dead"
  capture that was never supposed to run.
- **Blast radius:** one false High page per episode.
- **Before:** n/a (no staleness check).
- **Fallback:** `run.py` records `pipeline_capture_expected` in `meta`
  at startup; the staleness check and the dashboard both honor it —
  an intentionally-off capture shows "not running in this mode",
  never "stale".

## 13. Watchdog ping failures (network down vs monitor down)

- **What breaks:** the gateway/internet pings fail — real outage or
  the box's own network stack wedged.
- **Blast radius:** outage rows accumulate; nothing else.
- **Before:** unchanged — `watchdog.py` already logs outages with
  start/end timestamps.
- **Fallback:** unchanged. Noted here because "no flows + ping
  failing" (network down) vs "no flows + ping fine" (capture dead) is
  exactly how the operator tells modes 1 and 13 apart using the
  watermarks.

---

## How to follow one detection (trace_id)

1. An alert fires → `alerts.trace_id` (dashboard: "Follow-up ID").
2. The case groups it → `incident_alerts.trace_id` (case timeline
   shows the id per alert).
3. The notify hook receives the id; worker log lines carry it.
4. stderr lines for attach failures, self-alerts, restarts, and
   disk events all include the id.

Grep the id in the logs and the DB and you get the detection's whole
life: which rule fired it, which case it joined, whether its email
queued, and what the pipeline was doing around it.

## How to read the watermarks

Dashboard → Settings → "This box (sensor health)" → "Pipeline
health": each stage shows its last healthy time and ok/stale/unknown.
`ok` = heard from recently. `stale` = silent too long (one self-alert
already fired — check the alerts list). `unknown` = never seen healthy
(fresh install, or the stage never ran) — not an error.
