"""netmon/run.py -- entry point for the Phase 1 network monitor.

Starts, in this order:
  1. watchdog thread  (ping gateway + internet, logs outages)
  2. capture thread   (live sniff -> flows -> SQLite; needs root)
  3. monitor thread   (periodic detection rules + AI summary every 15 min)
  4. Flask dashboard  (http://127.0.0.1:5001)

Usage:
  sudo python -m netmon.run                  # full monitor on default iface
  sudo python -m netmon.run --iface wlan0    # pick the interface
  python -m netmon.run --pcap capture.pcap   # one-shot pcap analysis
  python -m netmon.run --dashboard-only       # just serve the dashboard

Live capture needs root (raw sockets). The dashboard alone does not.
"""
import argparse
import os
import sys
import threading
import time

from . import detect as detm
from . import explainer as expl
from . import config as cfgm
from .watchdog import Watchdog

DETECT_INTERVAL = 60  # seconds between periodic rule runs


def _monitor_loop(stop_event, digest_hours=24, loop_state=None):
    """Detection rules every minute; AI summary every SUMMARY_INTERVAL;
    email digest every digest_hours (0 disables). Also: the weekly self
    vulnerability scan, the Windows-log ingest poll, and the sensor-box
    self-health check -- all best-effort, none can break the loop.

    Pipeline robustness (batch 14):
      * the capture thread is watched and restarted (bounded -- see
        netmon/pipeline.py);
      * every step runs via pipeline.safe_step: a failure logs one
        stderr line instead of dying silently or killing the loop;
      * detection rules ALWAYS run, even with a full disk; a failed pass
        is counted and 3 in a row raises one self-alert;
      * a nearly-full disk pauses non-essential writes (summaries,
        scans, digests, reports) with one self-alert -- the rewind
        buffer pauses first via its own guard;
      * per-stage watermarks (capture tick, rule pass, feed refresh,
        notification) feed the dashboard's sensor-health view, and a
        stage silent too long raises one self-alert.

    loop_state: {"capture": {"state","is_alive","start"} or None,
                 "capture_expected": bool, "disk_min_free_mb": float}.
    """
    from . import pipeline as pipelinem
    loop_state = loop_state or {}
    capture_ctl = loop_state.get("capture")
    capture_expected = loop_state.get("capture_expected", True)
    disk_min_free_mb = loop_state.get("disk_min_free_mb",
                                      pipelinem.DISK_MIN_FREE_MB)

    # Lazy step bodies: a broken optional import must not kill the loop;
    # safe_step logs the failure and the loop continues.
    def _feeds():
        from . import threatintel as tim
        tim.maybe_refresh_feeds()

    def _summary():
        expl.summarize(save=True)

    def _weekly_scan():
        from . import scan as scanm
        scanm.maybe_weekly_scan()

    def _ingest():
        from . import ingest as ingm
        ingm.run_ingest()

    def _selfcheck():
        from . import selfcheck as selfm
        selfm.maybe_scheduled_selfcheck()

    def _amass():
        from . import amass as amassm
        amassm.maybe_weekly_amass()

    def _nuclei():
        from . import nuclei as nucleim
        nucleim.maybe_weekly_nuclei()

    def _swaudit():
        from . import swaudit as swam
        swam.maybe_daily_swaudit()

    def _reporting():
        from . import reporting as repm
        repm.maybe_daily_score()
        repm.maybe_daily_briefing()

    def _rewind():
        from . import rewind as rwm
        rwm.refresh()
        rwm.enforce_caps()

    def _digest():
        from . import notify as notifm
        # Async: the monitor thread must never stall on SMTP (B1).
        notifm.send_digest_async()

    def _retention():
        from . import retention as retm
        retm.maybe_prune()

    def _canary():
        from . import canary as canarym
        # The tripwire stays up even under disk pressure: it's cheap,
        # and a blind trap is a dead trap.
        canarym.ensure_running()
        canarym.check_canary_file()

    last_summary = 0
    last_digest = time.time()  # first digest waits a full interval
    last_ingest = 0
    # Batch 16: the loop stamps its own tick watermark every pass. The
    # dashboard's loop-down watchdog (pipeline.check_loop_down) reads it:
    # pid file present + tick stale = the loop died without a clean
    # shutdown. The tick is stamped even when the disk is full -- a dead
    # loop must be distinguishable from a paused one.
    pipelinem.note_loop_tick()
    while not stop_event.wait(DETECT_INTERVAL):
        now = time.time()
        pipelinem.note_loop_tick(now)

        # Front door: restart a dead capture thread (bounded; the
        # stale-capture watermark raises the self-alert past that).
        if capture_ctl is not None:
            pipelinem.safe_step("capture-watchdog",
                                pipelinem.ensure_capture,
                                capture_ctl["state"],
                                capture_ctl["is_alive"],
                                capture_ctl["start"])

        # Detection rules ALWAYS run -- even with a full disk. run_all
        # isolates each rule; a whole-pass failure is counted here and
        # 3 in a row raises one self-alert.
        try:
            detm.run_all()
        except Exception as exc:  # shouldn't happen; belt and suspenders
            pipelinem.note_rules_result(False, exc)
        else:
            pipelinem.note_rules_result(True)

        # Disk-full: stop non-essential writes, alert once, keep
        # detecting. disk_alert_once also clears the flag on recovery.
        pressured = bool(pipelinem.safe_step(
            "disk-guard", pipelinem.disk_pressure,
            min_free_mb=disk_min_free_mb))
        pipelinem.safe_step("disk-alert", pipelinem.disk_alert_once,
                            min_free_mb=disk_min_free_mb)

        # Threat-intel feeds: detection quality depends on them, so they
        # keep refreshing even under disk pressure. A failed refresh
        # keeps the old rows and backs off -- it never breaks the loop.
        pipelinem.safe_step("feeds", _feeds)

        # Stale-stage self-check: one self-alert per silent stage, quiet
        # again once it recovers.
        pipelinem.safe_step("staleness",
                            pipelinem.check_and_alert_staleness,
                            capture_expected=capture_expected)

        # Canary tripwire: keep the fake port listening, watch the bait
        # file. Runs even under disk pressure (see _canary).
        pipelinem.safe_step("canary", _canary)

        if pressured:
            continue  # detection + feeds ran; the rest waits for room

        if now - last_summary >= expl.SUMMARY_INTERVAL:
            last_summary = now
            pipelinem.safe_step("summary", _summary)
        # Weekly self scan of our own LAN (scan.py decides if it's due).
        pipelinem.safe_step("weekly-scan", _weekly_scan)
        # Windows Event Log / firewall log ingestion (ingest.py decides
        # if it's configured); every 5 minutes is plenty for log files.
        if now - last_ingest >= 300:
            last_ingest = now
            pipelinem.safe_step("ingest", _ingest)
        # Sensor-box self-health (selfcheck.py decides if it's due).
        pipelinem.safe_step("selfcheck", _selfcheck)
        # External attack-surface mapping (amass.py decides if it's due,
        # enabled, and configured; silent no-op otherwise).
        pipelinem.safe_step("amass", _amass)
        # Deeper vulnerability scan via Nuclei (nuclei.py decides if it's
        # due, enabled, and installed; silent no-op otherwise). Targets
        # are always our own LAN inventory -- never user-supplied.
        pipelinem.safe_step("nuclei", _nuclei)
        # Software inventory + CVE correlation for the sensor box itself
        # (swaudit.py decides if it's due; local reads only).
        pipelinem.safe_step("swaudit", _swaudit)
        # Prove it (reporting.py): the daily morning briefing (one email,
        # honoring quiet hours) and the daily security-score snapshot for
        # the trend. Best-effort; never breaks the loop.
        pipelinem.safe_step("reporting", _reporting)
        # Forensic rewind (rewind.py): refresh the enabled flag from
        # config and enforce the storage caps so the buffer can never
        # grow past rewind_minutes / rewind_max_mb.
        pipelinem.safe_step("rewind", _rewind)
        # Data retention (batch 16): daily prune of expired rows in
        # bounded batches. Best-effort; never breaks the loop.
        pipelinem.safe_step("retention", _retention)
        if digest_hours > 0 and now - last_digest >= digest_hours * 3600:
            last_digest = now
            pipelinem.safe_step("digest", _digest)


def _bind_allowed(host):
    """True if binding `host` is safe. Loopback is always fine; anything
    else requires a dashboard password (H1: fail closed, don't warn-and-bind).

    Split out for unit testing.
    """
    if (host or "").strip() in ("127.0.0.1", "localhost", "::1"):
        return True
    owner_pw, viewer_pw = cfgm.auth_passwords()
    return bool(owner_pw or viewer_pw)


def main():
    # Product config: first run creates ~/.config/brutedash/config.yaml
    # with commented defaults. CLI flags > env vars > config file.
    # A broken config file must never prevent startup: fall back to
    # defaults with a warning instead of crashing.
    try:
        cfg_path = cfgm.ensure_bootstrap()
        cfg = cfgm.load(cfg_path)
    except Exception as exc:
        print(f"WARNING: could not load config ({exc}); using defaults.")
        cfg = {s: dict(keys) for s, keys in cfgm.DEFAULTS.items()}

    def _safe_int(value, fallback):
        try:
            return int(value)
        except (TypeError, ValueError):
            return fallback

    ap = argparse.ArgumentParser(description="netmon Phase 1 monitor")
    ap.add_argument("--iface", default=cfgm.get(cfg, "capture.interface") or None,
                    help="interface to sniff (default: config capture.interface)")
    ap.add_argument("--pcap", default=None, help="analyze a pcap and exit")
    ap.add_argument("--dashboard-only", action="store_true",
                    help="serve the dashboard without capturing")
    ap.add_argument("--weekly-report", action="store_true",
                    help="print the weekly report and exit (no capture)")
    ap.add_argument("--port", type=int,
                    default=_safe_int(
                        cfgm.env_compat("BRUTEDASH_DASHBOARD_PORT",
                                        "NETMON_PORT")
                        or cfgm.get(cfg, "dashboard.port", 5001),
                        5001))
    ap.add_argument("--host",
                    default=cfgm.env_compat("BRUTEDASH_DASHBOARD_HOST",
                                            "NETMON_HOST")
                    or cfgm.get(cfg, "dashboard.host", "127.0.0.1"),
                    help="interface to bind the dashboard to;"
                    " use 0.0.0.0 to reach it from other devices on your LAN"
                    " (requires NETMON_PASSWORD -- enforced, not advised)")
    args = ap.parse_args()

    # H1: fail closed. A non-loopback bind with no dashboard password is an
    # unauthenticated control panel for the whole monitor -- refuse it
    # loudly instead of warning. Localhost stays usable for dev.
    if not _bind_allowed(args.host):
        print(f"ERROR: refusing to bind {args.host} without NETMON_PASSWORD"
              " set. Set a dashboard password or bind 127.0.0.1.",
              file=sys.stderr)
        sys.exit(2)

    # Digest cadence: env wins, then config file. Never crash on a bad
    # value (empty YAML key, typo): fall back to 24h.
    digest_env = cfgm.env_compat("BRUTEDASH_ALERTS_DIGEST_HOURS",
                                 "NETMON_DIGEST_HOURS").strip()
    try:
        digest_hours = (float(digest_env) if digest_env
                        else float(cfgm.get(cfg, "alerts.digest_hours", 24)))
    except (TypeError, ValueError):
        digest_hours = 24

    if args.weekly_report:
        from . import weekly as weekm
        report = weekm.generate_weekly_report()
        text = weekm.maybe_polish(weekm.format_plaintext(report))
        print(text)
        sent = weekm.email_report(text)
        print("\nEmail: " + ("sent" if sent
                             else "skipped (email not configured)"))
        return

    from . import dashboard as dash  # lazy: weekly-report exits above
    from . import health as healthm

    # The nurse's toolkit: persistent logs, crash bundles, heartbeat.
    # None of this changes behavior when unconfigured.
    healthm.setup_logging()
    healthm.install_crash_handlers()

    if args.pcap:
        from . import capture as capm
        agg = capm.run_pcap(args.pcap)
        print(f"Processed {agg.packets_seen} packets from {args.pcap}.")
        anchor = agg.max_ts or time.time()
        detm.run_all(now=anchor)
        summary, origin = expl.summarize(save=True, now=anchor)
        print(f"\n[{origin}] {summary['headline']}\n")
        print(summary["whats_happening"])
        for s in summary["stands_out"]:
            print(f"  - {s}")
        return

    stop_event = threading.Event()

    watchdog = Watchdog()
    watchdog.start()
    dash.watchdog = watchdog  # dashboard reads live status from here

    # Pipeline robustness (batch 14): the monitor loop watches the
    # capture thread (bounded restarts), tracks per-stage watermarks,
    # and pauses non-essential writes when the disk is nearly full.
    from . import pipeline as pipelinem
    capture_wanted = not args.dashboard_only
    pipelinem.set_capture_expected(capture_wanted)
    try:
        disk_min_free_mb = float(cfgm.get(cfg, "monitor.disk_min_free_mb",
                                          pipelinem.DISK_MIN_FREE_MB))
    except (TypeError, ValueError):
        disk_min_free_mb = pipelinem.DISK_MIN_FREE_MB

    capture_state = {"thread": None, "restarts": [], "gave_up": False}

    def _start_capture():
        from . import capture as capm
        t = threading.Thread(
            target=capm.run_live,
            kwargs={"interface": args.iface, "stop_event": stop_event},
            daemon=True)
        t.start()
        return t

    if capture_wanted:
        capture_state["thread"] = _start_capture()
        print(f"Capturing on {args.iface or 'default interface'}..."
              " (needs root for live sniff)")

    loop_state = {
        "disk_min_free_mb": disk_min_free_mb,
        "capture_expected": capture_wanted,
        "capture": ({
            "state": capture_state,
            "is_alive": lambda: (capture_state["thread"] is not None
                                 and capture_state["thread"].is_alive()),
            "start": _start_capture,
        } if capture_wanted else None),
    }

    monitor = threading.Thread(target=_monitor_loop,
                               args=(stop_event, digest_hours, loop_state),
                               daemon=True)
    # Batch 16: record that the monitor loop started. The dashboard's
    # loop-down watchdog keys off this file: present + tick stale = the
    # loop died without a clean shutdown. Removed in the finally block.
    pipelinem.write_loop_pid()
    monitor.start()

    # Re-enforce any isolations a human left active across a restart.
    # The worker only re-sends for rows the dashboard created via a
    # human click -- it never isolates anything on its own.
    try:
        from . import quarantine as qm
        qm.ensure_worker()
    except Exception:
        pass

    # first summary right away so the dashboard isn't empty
    try:
        expl.summarize(save=True)
    except Exception:
        pass

    print(f"Dashboard: http://{args.host}:{args.port}")

    # Vital-signs monitor: pings the heartbeat URL (healthchecks.io) every
    # few minutes. The nurse (watching agent) wakes up when pings stop.
    hb_url = (os.environ.get("BRUTEDASH_MONITOR_HEARTBEAT_URL", "").strip()
              or cfgm.get(cfg, "monitor.heartbeat_url", ""))
    try:
        hb_minutes = int(cfgm.get(cfg, "monitor.heartbeat_minutes", 5))
    except (TypeError, ValueError):
        hb_minutes = 5

    def _health():
        thr = capture_state["thread"]
        if (capture_wanted and thr is not None
                and not thr.is_alive()):
            return False, "capture thread died"
        # Batch 16: the monitor loop's own tick. If it stopped, the box
        # is alive but the watching is not -- signal /fail so the
        # external heartbeat service knows before its grace period ends.
        # Unknown (no tick yet, e.g. just started) is not a failure.
        if pipelinem.loop_tick_fresh() is False:
            return False, "monitor loop stopped ticking"
        return healthm.local_health()

    heartbeat = healthm.Heartbeat(hb_url, hb_minutes, _health)
    heartbeat.start()
    if hb_url:
        print(f"Heartbeat: every {hb_minutes} min")
    try:
        dash.app.run(host=args.host, port=args.port,
                     use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    finally:
        heartbeat.stop()
        pipelinem.clear_loop_pid()  # clean shutdown: not a loop-down event
        stop_event.set()
        watchdog.stop()


if __name__ == "__main__":
    main()
