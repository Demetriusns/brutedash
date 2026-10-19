"""Capture resilience tests (2026-10-19 daily build, council R1-R3).

The 2026-10-18 weekly council robustness seat rated three capture.py
findings High; this file proves each fix:

  R1  ScanTracker DB I/O (recent_alert_kind / add_alert) no longer runs
      under ScanTracker.lock, and a DB failure in scan tracking can
      never escape into the packet path and kill live capture.
  R2  run_live loops short sniff(timeout=SNIFF_TIMEOUT) calls so an
      idle or stalled interface still observes stop_event promptly.
  R3  flush() writes each detached buffer in its own guard: one failed
      insert logs its dropped row count and the rest still land;
      _flush_loop's final flush is guarded and logged the same way.

Run: python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import capture as capm
from netmon import db as dbm

from helpers import fresh_db as _fresh_db, restore_db as _restore_db


class _ScratchDb(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)


def _burst(tracker, src="203.0.113.9", base_port=1000, n=20, ts=1000.0):
    for i in range(n):
        tracker.observe(src, base_port + i, ts + i, is_syn=True)


# --- R1: DB I/O off the packet path ------------------------------------


class ScanTrackerDbResilienceTests(_ScratchDb):
    def test_db_failure_in_alert_check_does_not_raise(self):
        tracker = capm.ScanTracker()
        with mock.patch.object(dbm, "recent_alert_kind",
                               side_effect=RuntimeError("db gone")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                _burst(tracker)  # must not raise
        self.assertIn("port-scan alert", err.getvalue())
        self.assertIn("dropped", err.getvalue())
        # The burst was consumed: no history left to re-fire on.
        self.assertEqual(tracker.history["203.0.113.9"], [])

    def test_db_failure_in_add_alert_does_not_raise(self):
        tracker = capm.ScanTracker()
        with mock.patch.object(dbm, "recent_alert_kind", return_value=False), \
                mock.patch.object(dbm, "add_alert",
                                  side_effect=RuntimeError("db gone")):
            with contextlib.redirect_stderr(io.StringIO()):
                _burst(tracker)  # must not raise
        self.assertEqual(dbm.query("SELECT kind FROM alerts"), [])

    def test_db_calls_run_with_lock_released(self):
        # The DB stub re-enters by taking ScanTracker.lock: if observe()
        # still held the lock during the DB call (the old code), this
        # acquire would time out and the alert would be dropped.
        tracker = capm.ScanTracker()
        seen = {}

        def _recent(kind, key, within):
            seen["acquired"] = tracker.lock.acquire(timeout=2)
            if seen["acquired"]:
                tracker.lock.release()
            return True  # in cooldown: no add_alert needed

        with mock.patch.object(dbm, "recent_alert_kind",
                               side_effect=_recent):
            _burst(tracker)
        self.assertTrue(seen.get("acquired"))

    def test_alert_still_fires_normally(self):
        tracker = capm.ScanTracker()
        with dbm.notifications_paused():
            _burst(tracker, ts=time.time())
        rows = dbm.query("SELECT kind, severity FROM alerts")
        self.assertEqual(rows, [("port_scan", "High")])


@unittest.skipUnless(capm.HAVE_SCAPY, "handle() needs scapy packet layers")
class HandleGuardTests(_ScratchDb):
    def _syn_packet(self):
        from scapy.all import Ether, IP, TCP
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                / IP(src="203.0.113.9", dst="192.168.1.5")
                / TCP(sport=4444, dport=80, flags="S"))

    def test_handle_survives_scan_tracker_explosion(self):
        agg = capm.FlowAggregator()

        class _Boom:
            @staticmethod
            def observe(*_a):
                raise RuntimeError("scan tracker exploded")

        agg.scans = _Boom()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            agg.handle(self._syn_packet())  # must not raise
        self.assertIn("scan tracking dropped", err.getvalue())
        # ...and the flow itself was still recorded.
        self.assertEqual(len(agg.flows), 1)


# --- R3: flush() per-buffer isolation -----------------------------------


def _loaded_agg(ts=1000.0):
    agg = capm.FlowAggregator()
    agg.flows[("10.0.0.1", "203.0.113.5", 1234, 443, "TCP")] = \
        [2, 300, ts, ts]
    agg.dns_buf.append((ts, "10.0.0.1", "example.com", 1))
    agg.arp_buf.append((ts, "10.0.0.1", "aa:bb:cc:dd:ee:ff"))
    agg.hostname_buf.append(
        (ts, "aa:bb:cc:dd:ee:ff", "10.0.0.1", "myhost", "dhcp"))
    agg.ttl_map["10.0.0.1"] = (64, ts)
    return agg


class FlushIsolationTests(_ScratchDb):
    def test_dns_failure_still_stores_everything_else(self):
        agg = _loaded_agg()
        with mock.patch.object(dbm, "insert_dns_queries",
                               side_effect=RuntimeError("locked")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                stored = agg.flush()
        self.assertEqual(stored, 1)  # the flow row landed
        self.assertIn("dropped 1 DNS rows", err.getvalue())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM flows")[0][0], 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM arp_observations")[0][0], 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM dns_queries")[0][0], 0)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM device_ttl")[0][0], 1)
        self.assertTrue(dbm.get_meta("last_flow_ts"))

    def test_flow_failure_returns_zero_and_keeps_other_buffers(self):
        agg = _loaded_agg()
        with mock.patch.object(dbm, "insert_flows",
                               side_effect=RuntimeError("locked")):
            with contextlib.redirect_stderr(io.StringIO()) as err:
                stored = agg.flush()
        self.assertEqual(stored, 0)
        self.assertIn("dropped 1 flow rows", err.getvalue())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM dns_queries")[0][0], 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM flows")[0][0], 0)

    def test_clean_flush_stores_all_and_returns_count(self):
        agg = _loaded_agg()
        with contextlib.redirect_stderr(io.StringIO()) as err:
            stored = agg.flush()
        self.assertEqual(stored, 1)
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM flows")[0][0], 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM dns_queries")[0][0], 1)


class FlushLoopGuardTests(unittest.TestCase):
    def test_final_flush_failure_is_logged_not_raised(self):
        class _BadAgg:
            @staticmethod
            def flush():
                raise RuntimeError("db gone")

        stop = threading.Event()
        stop.set()  # skip the periodic loop; go straight to final flush
        with contextlib.redirect_stderr(io.StringIO()) as err:
            capm._flush_loop(_BadAgg(), stop)  # must not raise
        self.assertIn("final flush failed", err.getvalue())


# --- R2: run_live sniff loop --------------------------------------------


@unittest.skipUnless(capm.HAVE_SCAPY, "run_live needs scapy")
class RunLiveLoopTests(_ScratchDb):
    def test_sniff_loops_with_timeout_until_stop_set(self):
        calls = []
        stop = threading.Event()

        def _fake_sniff(**kwargs):
            calls.append(kwargs)
            if len(calls) >= 3:
                stop.set()

        with mock.patch.object(capm, "sniff", side_effect=_fake_sniff):
            agg = capm.run_live(interface="fake0", stop_event=stop)
        self.assertIsNotNone(agg)
        self.assertEqual(len(calls), 3)  # re-entered while stop was unset
        for kwargs in calls:
            self.assertEqual(kwargs.get("timeout"), capm.SNIFF_TIMEOUT)
            self.assertFalse(kwargs.get("store"))
            self.assertIn("stop_filter", kwargs)

    def test_prn_swallows_a_bad_packet(self):
        stop = threading.Event()
        captured = {}

        class _BadPkt:
            @staticmethod
            def getlayer(*_a):
                raise RuntimeError("unparseable")

        def _fake_sniff(**kwargs):
            captured["prn"] = kwargs["prn"]
            stop.set()

        with mock.patch.object(capm, "sniff", side_effect=_fake_sniff):
            capm.run_live(interface="fake0", stop_event=stop)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = captured["prn"](_BadPkt())  # must not raise
        self.assertIsNone(out)
        self.assertIn("dropped one packet", err.getvalue())


if __name__ == "__main__":
    unittest.main()
