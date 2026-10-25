"""Council review 2026-10-25 -- shipped batch regression tests.

Quorum batch (2-of-3 seats on rewind + 1 Critical with head agreement):

  C1 (robustness, Critical) capture memory was unbounded: the flow
     table and DNS buffer grew between flushes, and ScanTracker kept
     one history entry per SYN source forever. All three are capped
     now; existing entries are never evicted mid-window, drops are
     counted and logged at flush.
  H1 (robustness, High) rewind export_window held the capture lock
     while building and read whole 64 MB segments into RAM. It now
     snapshots the segment list under the lock, builds without it,
     and streams one packet at a time.
  H2 (security, High) the read-only viewer role could download raw
     packet payloads (/api/rewind/export) and the weekly/incident PDF
     reports. All three routes are owner-only now, and rewind segment
     files/directory are created owner-only (0600/0700) like the DB
     and config already were.

Run: python -m unittest discover -s tests -v
"""
import os
import shutil
import stat
import struct
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import capture as capm
from netmon import config as cfgm
from netmon import rewind as rwm

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

try:
    from netmon import dashboard as dashm
except Exception:
    dashm = None


# --- C1: ScanTracker history bounds -------------------------------------


class ScanTrackerBoundsTests(unittest.TestCase):
    def test_stale_one_shot_sources_are_swept_globally(self):
        tracker = capm.ScanTracker()
        # A one-shot source: a few SYNs, well under the alert burst.
        for i in range(3):
            tracker.observe("198.51.100.1", 1000 + i, 1000.0 + i,
                            is_syn=True)
        self.assertIn("198.51.100.1", tracker.history)
        # A later source, past one full window, triggers the sweep:
        # the first source is never seen again, yet must not linger.
        tracker.observe("198.51.100.2", 80, 1000.0 + capm.SCAN_WINDOW + 5,
                        is_syn=True)
        self.assertNotIn("198.51.100.1", tracker.history)
        self.assertIn("198.51.100.2", tracker.history)

    def test_distinct_sources_are_capped_oldest_first(self):
        tracker = capm.ScanTracker()
        with mock.patch.object(capm, "SCAN_MAX_SOURCES", 5):
            for i in range(8):
                tracker.observe(f"198.51.100.{i}", 80, 2000.0 + i,
                                is_syn=True)
        self.assertLessEqual(len(tracker.history), 5)
        self.assertGreaterEqual(tracker.sources_dropped, 3)
        # The newest source (the one just observed) is never evicted.
        self.assertIn("198.51.100.7", tracker.history)


# --- C1: flow / DNS buffer caps ------------------------------------------

@unittest.skipUnless(capm.HAVE_SCAPY, "handle() needs scapy packet layers")
class FlowCapTests(unittest.TestCase):
    def _pkt(self, sport):
        from scapy.all import Ether, IP, TCP
        return (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
                / IP(src="203.0.113.9", dst="192.168.1.5")
                / TCP(sport=sport, dport=80, flags="S"))

    def test_new_flows_dropped_at_cap_existing_still_aggregate(self):
        agg = capm.FlowAggregator()
        with mock.patch.object(capm, "MAX_FLOWS", 3):
            for sport in (4001, 4002, 4003, 4004, 4005):
                agg.handle(self._pkt(sport))
            self.assertEqual(len(agg.flows), 3)
            self.assertEqual(agg.flows_dropped, 2)
            # A packet for an already-tracked flow still counts.
            agg.handle(self._pkt(4001))
            self.assertEqual(agg.flows_dropped, 2)
            key = next(k for k in agg.flows if k[2] == 4001)
            self.assertEqual(agg.flows[key][0], 2)

    def test_flush_logs_cap_drops_and_resets_counters(self):
        import contextlib
        import io
        self._db = _fresh_db()
        try:
            agg = capm.FlowAggregator()
            agg.flows_dropped = 7
            agg.dns_dropped = 4
            with contextlib.redirect_stderr(io.StringIO()) as err:
                agg.flush()
            self.assertIn("memory caps shed 7 new flows", err.getvalue())
            self.assertIn("4 DNS rows", err.getvalue())
            self.assertEqual(agg.flows_dropped, 0)
            self.assertEqual(agg.dns_dropped, 0)
        finally:
            _restore_db(*self._db)


# --- H1/H2: rewind streaming, lock, permissions ---------------------------


class RewindBatchTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rewind-council-")
        self._old_enabled = rwm._ENABLED
        self._old_dir = rwm.rewind_dir
        self._old_diskok = rwm._disk_ok
        rwm._ENABLED = True
        tmp = self.tmp
        rwm.rewind_dir = lambda: __import__("pathlib").Path(tmp)
        rwm._disk_ok = lambda _d: True

    def tearDown(self):
        rwm._reset_for_tests()
        rwm._ENABLED = self._old_enabled
        rwm.rewind_dir = self._old_dir
        rwm._disk_ok = self._old_diskok
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_export_streams_and_survives_truncated_tail(self):
        base = time.time()
        rwm.record_packet(b"pkt-a", base - 50)
        rwm.record_packet(b"pkt-b", base - 40)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        # Corrupt the tail of the only segment: a partial record header
        # appended after the real packets must end iteration cleanly.
        segs = rwm._segments(rwm.rewind_dir())
        self.assertEqual(len(segs), 1)
        with open(segs[0][1], "ab") as f:
            f.write(b"\x01\x02\x03")
        blob, count = rwm.export_window(base - 100, base + 100)
        self.assertEqual(count, 2)
        self.assertIn(b"pkt-a", blob)
        self.assertIn(b"pkt-b", blob)

    def test_export_does_not_hold_lock_while_building(self):
        base = time.time()
        rwm.record_packet(b"pkt-a", base - 50)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        seen = {}
        orig = rwm._iter_segment_packets

        def spy(path):
            # Inside the build phase the capture lock must be free:
            # record_packet() takes it on the packet hot path.
            seen["acquired"] = rwm._lock.acquire(blocking=False)
            if seen["acquired"]:
                rwm._lock.release()
            yield from orig(path)

        with mock.patch.object(rwm, "_iter_segment_packets", spy):
            blob, count = rwm.export_window(base - 100, base + 100)
        self.assertEqual(count, 1)
        self.assertTrue(seen.get("acquired"))

    @unittest.skipIf(os.name == "nt", "POSIX permission bits")
    def test_segment_files_are_owner_only(self):
        base = time.time()
        rwm.record_packet(b"pkt-a", base - 50)
        rwm._reset_for_tests()
        segs = rwm._segments(rwm.rewind_dir())
        self.assertTrue(segs)
        for _start, path in segs:
            mode = stat.S_IMODE(os.stat(path).st_mode)
            self.assertEqual(mode & 0o077, 0,
                             f"{path} is group/other accessible: {mode:o}")


# --- H2: download routes are owner-only -----------------------------------

@unittest.skipIf(dashm is None, "Flask not installed")
class DownloadRouteRoleTests(unittest.TestCase):
    OWNER_PW = "owner-pw-council"
    VIEWER_PW = "viewer-pw-council"

    def setUp(self):
        self._db = _fresh_db()
        self._old_env = {}
        for key in ("BRUTEDASH_AUTH_OWNER_PASSWORD",
                    "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD"):
            self._old_env[key] = os.environ.get(key)
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = self.OWNER_PW
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = self.VIEWER_PW
        os.environ.pop("NETMON_PASSWORD", None)
        dashm._LOGIN_ATTEMPTS.clear()
        dashm.app.config["TESTING"] = True
        # config.load() folds BRUTEDASH_* env vars into the config
        # dict and load_cached() caches it by file mtime: without a
        # clear, these test passwords would outlive the env vars and
        # keep the password gate on for every later test module in
        # the process (test_config.py clears the cache for the same
        # reason).
        cfgm._CACHE.clear()

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        dashm._LOGIN_ATTEMPTS.clear()
        cfgm._CACHE.clear()
        _restore_db(*self._db)

    def _login_client(self, password):
        c = dashm.app.test_client()
        r = c.post("/login", data={"password": password})
        self.assertEqual(r.status_code, 302)
        return c

    def test_viewer_cannot_download_raw_packets_or_pdfs(self):
        c = self._login_client(self.VIEWER_PW)
        for url in ("/api/rewind/export?hours=1",
                    "/reports/weekly.pdf",
                    "/reports/incident/1.pdf"):
            r = c.get(url)
            self.assertEqual(r.status_code, 403, url)

    def test_owner_can_download_rewind_export(self):
        c = self._login_client(self.OWNER_PW)
        r = c.get("/api/rewind/export?hours=1")
        self.assertEqual(r.status_code, 200)
        # A valid (possibly empty) pcap: global header magic first.
        self.assertEqual(struct.unpack("<I", r.data[:4])[0], 0xA1B2C3D4)


if __name__ == "__main__":
    unittest.main()
