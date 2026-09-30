"""netmon/watchdog.py -- connection-drop detection.

Pings the local gateway and a couple of internet hosts every few seconds.
A target is "down" after CONSECUTIVE_FAILS missed pings; the outage is
logged to SQLite with its start time, and closed (with duration) when the
target answers again.

This answers "did my internet drop?" with timestamps instead of vibes.
"""
import re
import subprocess
import threading
import time

from . import db as dbm

PING_INTERVAL = 5
CONSECUTIVE_FAILS = 2  # missed pings before we call it an outage


def find_gateway():
    """Best-effort default gateway IP from the routing table."""
    try:
        out = subprocess.run(["ip", "route", "show", "default"],
                             capture_output=True, text=True,
                             timeout=5).stdout
        m = re.search(r"default via (\S+)", out)
        if m:
            return m.group(1)
    except Exception:
        pass
    return "192.168.1.1"  # common home-router default


def ping_once(host):
    """True if the host answers one ping within the timeout."""
    try:
        result = subprocess.run(
            ["ping", "-c1", "-W2", host],
            capture_output=True, timeout=5)
        return result.returncode == 0
    except Exception:
        return False


class Watchdog(threading.Thread):
    """Background pinger. Keeps current status in .status."""

    daemon = True

    def __init__(self, targets=None, interval=PING_INTERVAL):
        super().__init__()
        self.targets = targets or []
        self.interval = interval
        self.status = {}          # target -> {"up": bool, "since": ts}
        self._fail_counts = {}
        self._outage_ids = {}
        self._stop = threading.Event()
        if not self.targets:
            gw = find_gateway()
            self.targets = [f"gateway ({gw})|{gw}", "internet (1.1.1.1)|1.1.1.1"]

    @staticmethod
    def _split(target):
        # targets look like "label|host"
        if "|" in target:
            label, host = target.split("|", 1)
            return label, host
        return target, target

    def stop(self):
        self._stop.set()

    def run(self):
        for t in self.targets:
            label, _ = self._split(t)
            self.status[label] = {"up": True, "since": time.time()}
            self._fail_counts[label] = 0
        while not self._stop.wait(self.interval):
            now = time.time()
            for target in self.targets:
                label, host = self._split(target)
                ok = ping_once(host)
                if ok:
                    self._fail_counts[label] = 0
                    if not self.status[label]["up"]:
                        oid = self._outage_ids.pop(label, None)
                        if oid:
                            dbm.end_outage(oid, now)
                        self.status[label] = {"up": True, "since": now}
                else:
                    self._fail_counts[label] += 1
                    if (self._fail_counts[label] >= CONSECUTIVE_FAILS
                            and self.status[label]["up"]):
                        self.status[label] = {"up": False, "since": now}
                        oid = dbm.start_outage(label, now)
                        self._outage_ids[label] = oid

    def current(self):
        """Snapshot for the dashboard: {label: {up, since}}."""
        return dict(self.status)
