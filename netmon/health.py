"""netmon/health.py -- the patient monitor for Project Orion.

Two jobs:

1. Heartbeat: every few minutes, ping the configured ``heartbeat_url``
   (a healthchecks.io check). A plain ping means "alive"; a ping to
   ``<url>/fail`` means "alive but something is wrong" (capture thread
   died, database broken, disk full). The nurse -- the agent watching the
   heartbeat from outside -- gets woken when pings stop or fail.
   Empty ``heartbeat_url`` = disabled; zero behavior change.

2. Diagnostics bundle: when something breaks, gather logs, redacted
   config, database integrity, and thread stacks into a timestamped
   folder. Never includes secrets -- API keys and passwords are scrubbed.

Only stdlib is used, so this works on any machine Orion installs on.
"""

import logging
import logging.handlers
import os
import platform
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

LOG_NAME = "orion"
_BUNDLE_INSTALLED = False


# ---------------------------------------------------------------- logging

def setup_logging():
    """Log to a rotating file next to the config dir, plus console."""
    from . import config as cfgm
    log_dir = cfgm.config_dir() / "logs"
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except OSError:
        return  # logging must never break startup
    handler = logging.handlers.RotatingFileHandler(
        log_dir / "orion.log", maxBytes=1_000_000, backupCount=3,
        encoding="utf-8")
    handler.setFormatter(logging.Formatter(
        "%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.setLevel(logging.INFO)
    if not any(isinstance(h, logging.handlers.RotatingFileHandler)
               for h in root.handlers):
        root.addHandler(handler)
    logging.getLogger(LOG_NAME).info("logging to %s", log_dir / "orion.log")


def log_path():
    from . import config as cfgm
    return cfgm.config_dir() / "logs" / "orion.log"


# ------------------------------------------------------- local health check

def local_health():
    """(ok, reason): is this box healthy enough to keep watching?

    Checks disk space and database writability. The caller (run.py) adds
    its own checks -- e.g. whether the capture thread is still alive --
    by wrapping this function.
    """
    # Disk: need room for the database and logs.
    try:
        from . import db as dbm
        free = shutil.disk_usage(os.path.dirname(dbm.DB_PATH)).free
        if free < 200 * 1024 * 1024:
            return False, f"disk critically low ({free // 1024 // 1024} MB free)"
    except Exception as exc:
        return False, f"disk check failed: {exc}"
    # Database: can we write? Routed through the db module's lock; the
    # probe uses a rolled-back savepoint, so no tables or rows persist
    # (B4: the old check opened its own connection and created a
    # _healthcheck table in prod on every tick).
    try:
        from . import db as dbm
        if not dbm.writability_probe():
            return False, "database not writable"
    except Exception as exc:
        return False, f"database check failed: {exc}"
    return True, "ok"


# -------------------------------------------------------------- heartbeat

def _heartbeat_url_ok(url):
    """Scheme allowlist for the heartbeat target: http/https only.

    The URL is operator-configured (their own healthchecks.io check), but
    a typo'd or pasted value (ftp://, file://, ...) must fail closed
    instead of being fetched. The URL itself is never logged -- anyone
    with it can fake heartbeats.
    """
    from urllib.parse import urlparse
    try:
        return urlparse(url or "").scheme.lower() in ("http", "https")
    except Exception:
        return False


class Heartbeat(threading.Thread):
    """Background pinger. Never raises; a broken heartbeat must not break
    the monitor it watches."""

    daemon = True

    def __init__(self, url, minutes, health_fn=None):
        super().__init__(name="heartbeat", daemon=True)
        self.url = (url or "").rstrip("/")
        self.interval = max(1, minutes) * 60
        self.health_fn = health_fn or local_health
        self._stop = threading.Event()
        self.log = logging.getLogger(LOG_NAME)

    def run(self):
        if not self.url:
            return
        if not _heartbeat_url_ok(self.url):
            # Fail closed and LOUD: a heartbeat that silently never
            # pings is worse than none -- the operator must fix the URL.
            self.log.error("heartbeat: refusing to ping a non-http(s)"
                           " URL; heartbeat disabled until the URL is fixed")
            return
        # Ping immediately on startup so a fresh boot is visible fast.
        self._ping_once()
        while not self._stop.wait(self.interval):
            self._ping_once()

    def _ping_once(self):
        try:
            ok, reason = self.health_fn()
        except Exception as exc:  # a broken health check is itself a symptom
            ok, reason = False, f"health check crashed: {exc}"
        target = self.url if ok else self.url + "/fail"
        try:
            req = urllib.request.Request(target, method="GET",
                                         headers={"User-Agent": "orion-health/1"})
            with urllib.request.urlopen(req, timeout=10):
                pass
            if not ok:
                self.log.warning("heartbeat: FAIL signal sent (%s)", reason)
        except Exception as exc:
            # Network blip or bad URL -- log locally, keep monitoring.
            self.log.warning("heartbeat: ping failed (%s)", exc)

    def stop(self):
        self._stop.set()


# ------------------------------------------------------ diagnostics bundle

def _scrub(text):
    """Redact anything that looks like a secret value."""
    import re
    return re.sub(r"(?i)(key|token|password|secret|heartbeat_url|webhook_url)"
                  r"\s*[:=]\s*\S+",
                  r"\1=***", text)


def _git_version():
    try:
        here = Path(__file__).resolve().parent.parent
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, timeout=5,
                             cwd=here).stdout.strip()
        return out or "unknown"
    except Exception:
        return "unknown"


def write_diagnostics_bundle(reason="manual"):
    """Gather a diagnostics bundle. Returns the folder path, or None."""
    from . import config as cfgm
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H%M%S")
    safe_reason = "".join(c if c.isalnum() or c in "-_" else "_"
                          for c in reason)[:40]
    dest = cfgm.config_dir() / "diagnostics" / f"{stamp}-{safe_reason}"
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError:
        return None
    log = logging.getLogger(LOG_NAME)
    try:
        # 1. Summary: what, when, where.
        try:
            free_mb = shutil.disk_usage(
                os.path.dirname(__file__)).free // 1024 // 1024
        except Exception:
            free_mb = -1
        (dest / "summary.txt").write_text(
            f"reason:   {reason}\n"
            f"utc:      {datetime.now(timezone.utc).isoformat()}\n"
            f"host:     {platform.node()}\n"
            f"os:       {platform.system()} {platform.release()}\n"
            f"python:   {platform.python_version()}\n"
            f"orion:    {_git_version()}\n"
            f"disk_mb_free: {free_mb}\n", encoding="utf-8")

        # 2. Config, scrubbed.
        try:
            cfg_text = cfgm.config_path().read_text(encoding="utf-8")
            (dest / "config.redacted.yaml").write_text(
                _scrub(cfg_text), encoding="utf-8")
        except Exception as exc:
            (dest / "config.redacted.yaml").write_text(
                f"<unreadable: {exc}>", encoding="utf-8")

        # 3. Recent log tail, scrubbed like the config (L5: the tail used
        # to ship unredacted -- secrets can land in log lines too).
        try:
            lp = log_path()
            if lp.exists():
                lines = lp.read_text(encoding="utf-8",
                                     errors="replace").splitlines()
                (dest / "orion.log.tail.txt").write_text(
                    _scrub("\n".join(lines[-300:])), encoding="utf-8")
        except Exception as exc:
            (dest / "orion.log.tail.txt").write_text(
                f"<unreadable: {exc}>", encoding="utf-8")

        # 4. Database integrity + row counts.
        try:
            from . import db as dbm
            conn = sqlite3.connect(dbm.DB_PATH, timeout=10)
            integrity = conn.execute(
                "PRAGMA integrity_check").fetchone()[0]
            counts = {}
            for table in ("flows", "alerts", "devices"):
                try:
                    counts[table] = conn.execute(
                        f"SELECT COUNT(*) FROM {table}").fetchone()[0]
                except Exception:
                    counts[table] = "n/a"
            conn.close()
            (dest / "db_check.txt").write_text(
                f"integrity_check: {integrity}\n"
                + "\n".join(f"{t}: {c}" for t, c in counts.items()),
                encoding="utf-8")
        except Exception as exc:
            (dest / "db_check.txt").write_text(
                f"<check failed: {exc}>", encoding="utf-8")

        # 5. Thread stacks -- shows hangs, not just crashes.
        stacks = []
        for tid, frame in sys._current_frames().items():
            name = next((t.name for t in threading.enumerate()
                         if t.ident == tid), "?")
            stacks.append(f"--- thread {name} ({tid}) ---")
            stacks.append("".join(traceback.format_stack(frame)))
        (dest / "threads.txt").write_text("\n".join(stacks),
                                          encoding="utf-8")
    except Exception as exc:
        log.warning("diagnostics: bundle incomplete (%s)", exc)
    log.warning("diagnostics: bundle written to %s", dest)
    return dest


# ---------------------------------------------------------- crash handlers

def _crash(exc_type, exc, tb):
    try:
        write_diagnostics_bundle(
            reason=f"crash-{exc_type.__name__}")
    except Exception:
        pass
    # Then behave as normal so the failure is still visible.
    sys.__excepthook__(exc_type, exc, tb)


def _thread_crash(args):
    try:
        write_diagnostics_bundle(
            reason=f"thread-crash-{args.thread.name}")
    except Exception:
        pass


def install_crash_handlers():
    """Write a diagnostics bundle on any unhandled failure. Idempotent."""
    global _BUNDLE_INSTALLED
    if _BUNDLE_INSTALLED:
        return
    sys.excepthook = _crash
    try:
        threading.excepthook = _thread_crash
    except AttributeError:
        pass  # Python < 3.8: main-thread hook still applies
    _BUNDLE_INSTALLED = True
