"""netmon/watchdog.py -- connection-drop detection.

Pings the local gateway and a couple of internet hosts every few seconds.
A target is "down" after CONSECUTIVE_FAILS missed pings; the outage is
logged to SQLite with its start time, and closed (with duration) when the
target answers again.

This answers "did my internet drop?" with timestamps instead of vibes.
"""
import platform
import re
import subprocess
import threading
import time
from concurrent.futures import ThreadPoolExecutor

from . import db as dbm

PING_INTERVAL = 5
CONSECUTIVE_FAILS = 2  # missed pings before we call it an outage

_IS_WINDOWS = platform.system() == "Windows"


# Localized "Default Gateway" labels for ipconfig parsing. route print
# is tried first (locale-independent), this is the fallback.
_GATEWAY_LABELS = (
    "default gateway",                 # English
    "standardgateway",                 # German
    "passerelle par defaut",           # French (accents stripped by lower())
    "passerelle par défaut",
    "puerta de enlace predeterminada",  # Spanish
    "gateway predefinito",             # Italian
    "gateway padrao",                  # Portuguese
    "gateway padrão",
    "standaardgateway",                # Dutch
)


def find_gateway():
    """Best-effort default gateway IP from the routing table."""
    try:
        if _IS_WINDOWS:
            # Council review (robustness): the old code only matched the
            # English "Default Gateway" ipconfig label -- on localized
            # Windows (German "Standardgateway", French "Passerelle par
            # défaut", ...) it silently fell back to 192.168.1.1. Two
            # locale-independent layers now: route print's 0.0.0.0 row is
            # purely numeric, then ipconfig with localized labels.
            out = subprocess.run(
                ["route", "print", "-4"], capture_output=True,
                text=True, timeout=5).stdout
            m = re.search(r"^\s*0\.0\.0\.0\s+0\.0\.0\.0\s+([\d.]+)",
                          out, re.M)
            if m and m.group(1) != "0.0.0.0":
                return m.group(1)
            out = subprocess.run(["ipconfig"], capture_output=True,
                                 text=True, timeout=5).stdout
            for line in out.splitlines():
                low = line.lower()
                if ":" in line and any(lbl in low
                                       for lbl in _GATEWAY_LABELS):
                    m = re.search(r"(\d+\.\d+\.\d+\.\d+)\s*$", line)
                    if m:
                        return m.group(1)
        else:
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
        if _IS_WINDOWS:
            cmd = ["ping", "-n", "1", "-w", "2000", host]
        else:
            cmd = ["ping", "-c1", "-W2", host]
        result = subprocess.run(cmd, capture_output=True, timeout=5)
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
        self._stop_event = threading.Event()
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
        self._stop_event.set()

    def run(self):
        for t in self.targets:
            label, _ = self._split(t)
            self.status[label] = {"up": True, "since": time.time()}
            self._fail_counts[label] = 0
        # Council review (robustness): targets used to be pinged one at a
        # time -- each ping_once can block up to ~5s, so a cycle with slow
        # targets stretched far past the interval. Ping concurrently; the
        # up/down state machine below still runs sequentially on this
        # thread, so no locking is needed for status bookkeeping.
        pool = ThreadPoolExecutor(
            max_workers=max(1, len(self.targets)),
            thread_name_prefix="watchdog-ping")
        try:
            while not self._stop_event.wait(self.interval):
                now = time.time()
                pairs = [self._split(t) for t in self.targets]
                results = pool.map(lambda lh: (lh[0], ping_once(lh[1])),
                                   pairs)
                for label, ok in results:
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
        finally:
            pool.shutdown(wait=False, cancel_futures=True)

    def current(self):
        """Snapshot for the dashboard: {label: {up, since}}."""
        return dict(self.status)
