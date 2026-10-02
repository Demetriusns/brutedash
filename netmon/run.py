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
                notifm.send_digest()
            except Exception:
                pass


def main():
    # Product config: first run creates ~/.config/brutedash/config.yaml
    # with commented defaults. CLI flags > env vars > config file.
    cfg_path = cfgm.ensure_bootstrap()
    cfg = cfgm.load(cfg_path)

    ap = argparse.ArgumentParser(description="netmon Phase 1 monitor")
    ap.add_argument("--iface", default=cfgm.get(cfg, "capture.interface") or None,
                    help="interface to sniff (default: config capture.interface)")
    ap.add_argument("--pcap", default=None, help="analyze a pcap and exit")
    ap.add_argument("--dashboard-only", action="store_true",
                    help="serve the dashboard without capturing")
    ap.add_argument("--weekly-report", action="store_true",
                    help="print the weekly report and exit (no capture)")
    ap.add_argument("--port", type=int,
                    default=int(os.environ.get("NETMON_PORT")
                                or cfgm.get(cfg, "dashboard.port", 5001)))
    ap.add_argument("--host",
                    default=os.environ.get("NETMON_HOST")
                    or cfgm.get(cfg, "dashboard.host", "127.0.0.1"),
                    help="interface to bind the dashboard to;"
                    " use 0.0.0.0 to reach it from other devices on your LAN"
                    " (set NETMON_PASSWORD first)")
    args = ap.parse_args()

    # Digest cadence: env wins, then config file.
    digest_env = os.environ.get("NETMON_DIGEST_HOURS", "").strip()
    try:
        digest_hours = (float(digest_env) if digest_env
                        else float(cfgm.get(cfg, "alerts.digest_hours", 24)))
    except ValueError:
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
    try:
        dash.app.run(host=args.host, port=args.port,
                     use_reloader=False, threaded=True)
    except KeyboardInterrupt:
        pass
    finally:
        stop_event.set()
        watchdog.stop()


if __name__ == "__main__":
    main()
