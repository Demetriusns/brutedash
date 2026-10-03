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


def _monitor_loop(stop_event, digest_hours=24):
    """Detection rules every minute; AI summary every SUMMARY_INTERVAL;
    email digest every digest_hours (0 disables)."""
    last_summary = 0
    last_digest = time.time()  # first digest waits a full interval
    while not stop_event.wait(DETECT_INTERVAL):
        try:
            detm.run_all()
        except Exception:
            pass
        now = time.time()
        if now - last_summary >= expl.SUMMARY_INTERVAL:
            last_summary = now
            try:
                expl.summarize(save=True)
            except Exception:
                pass
        if digest_hours > 0 and now - last_digest >= digest_hours * 3600:
            last_digest = now
            try:
                from . import notify as notifm
                # Async: the monitor thread must never stall on SMTP (B1).
                notifm.send_digest_async()
            except Exception:
                pass


def _bind_allowed(host):
    """True if binding `host` is safe. Loopback is always fine; anything
    else requires NETMON_PASSWORD (H1: fail closed, don't warn-and-bind).

    Split out for unit testing.
    """
    if (host or "").strip() in ("127.0.0.1", "localhost", "::1"):
        return True
    return bool(os.environ.get("NETMON_PASSWORD"))


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

    monitor = threading.Thread(target=_monitor_loop,
                               args=(stop_event, digest_hours),
                               daemon=True)
    monitor.start()

    capture_thread = None
    if not args.dashboard_only:
        from . import capture as capm
        capture_thread = threading.Thread(
            target=capm.run_live,
            kwargs={"interface": args.iface, "stop_event": stop_event},
            daemon=True)
        capture_thread.start()
        print(f"Capturing on {args.iface or 'default interface'}..."
              " (needs root for live sniff)")

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
        if (capture_thread is not None and not args.dashboard_only
                and not capture_thread.is_alive()):
            return False, "capture thread died"
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
        stop_event.set()
        watchdog.stop()


if __name__ == "__main__":
    main()
