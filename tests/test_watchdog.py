"""Tests for the ping Watchdog: concurrent pings + outage state machine."""
import threading
import time
import unittest
from unittest import mock

from helpers import fresh_db as _fresh_db, restore_db as _restore_db
from netmon import db as dbm
from netmon import watchdog as wdm


class PingWatchdogTests(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)

    def test_targets_ping_concurrently(self):
        # 3 targets x 0.4s ping: sequential would need 1.2s per cycle.
        seen_threads = set()

        def slow_ping(host):
            seen_threads.add(threading.get_ident())
            time.sleep(0.4)
            return True

        with mock.patch.object(wdm, "ping_once", side_effect=slow_ping):
            wd = wdm.Watchdog(targets=["a|10.0.0.1", "b|10.0.0.2",
                                       "c|10.0.0.3"], interval=0.2)
            wd.start()
            time.sleep(1.6)
            wd.stop()
            wd.join(timeout=5)
        # At least 3 full cycles in 1.6s proves concurrency (sequential:
        # 1 cycle max). Multiple ping threads proves the pool is used.
        self.assertGreater(len(seen_threads), 1)
        for label in ("a", "b", "c"):
            self.assertTrue(wd.status[label]["up"])

    def test_outage_state_machine(self):
        answers = {"ok": True}

        def canned_ping(host):
            return answers["ok"]

        with mock.patch.object(wdm, "ping_once", side_effect=canned_ping):
            wd = wdm.Watchdog(targets=["wan|10.9.9.9"], interval=0.1)
            wd.start()
            try:
                time.sleep(0.3)
                self.assertTrue(wd.status["wan"]["up"])
                # two consecutive failures -> outage opens
                answers["ok"] = False
                deadline = time.time() + 5
                while wd.status["wan"]["up"] and time.time() < deadline:
                    time.sleep(0.05)
                self.assertFalse(wd.status["wan"]["up"])
                rows = dbm.query(
                    "SELECT COUNT(*) FROM outages WHERE end_ts IS NULL")
                self.assertEqual(rows[0][0], 1)
                # recovery -> outage closes
                answers["ok"] = True
                deadline = time.time() + 5
                while not wd.status["wan"]["up"] and time.time() < deadline:
                    time.sleep(0.05)
                self.assertTrue(wd.status["wan"]["up"])
                rows = dbm.query(
                    "SELECT COUNT(*) FROM outages WHERE end_ts IS NULL")
                self.assertEqual(rows[0][0], 0)
            finally:
                wd.stop()
                wd.join(timeout=5)


if __name__ == "__main__":
    unittest.main()


class FindGatewayTests(unittest.TestCase):
    def _run(self, *outputs, is_windows=True):
        calls = {"n": 0}

        def fake_run(cmd, **kwargs):
            out = outputs[calls["n"]] if calls["n"] < len(outputs) else ""
            calls["n"] += 1

            class R:
                stdout = out
            return R()

        with mock.patch.object(wdm, "_IS_WINDOWS", is_windows), \
             mock.patch.object(wdm.subprocess, "run", fake_run):
            return wdm.find_gateway()

    def test_route_print_numeric_row(self):
        out = ("IPv4 Route Table\n"
               "  0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.50     25\n")
        self.assertEqual(self._run(out), "192.168.1.1")

    def test_german_ipconfig_fallback(self):
        route_out = "no default route here"
        ipconfig_out = ("Drahtlos-LAN-Adapter WLAN:\n"
                        "   Standardgateway . . . . . . . . . : 10.0.0.1\n")
        self.assertEqual(self._run(route_out, ipconfig_out), "10.0.0.1")

    def test_french_ipconfig_fallback(self):
        route_out = "no default route here"
        ipconfig_out = ("Carte réseau sans fil Wi-Fi :\n"
                        "   Passerelle par défaut. . . . . . : 172.16.0.1\n")
        self.assertEqual(self._run(route_out, ipconfig_out), "172.16.0.1")

    def test_english_still_works(self):
        route_out = "no default route here"
        ipconfig_out = ("Wireless LAN adapter Wi-Fi:\n"
                        "   Default Gateway . . . . . . . . . : 192.168.7.1\n")
        self.assertEqual(self._run(route_out, ipconfig_out), "192.168.7.1")

    def test_nothing_found_falls_back(self):
        self.assertEqual(self._run("garbage", "more garbage"),
                         "192.168.1.1")
