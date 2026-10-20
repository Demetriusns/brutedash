"""Tests for the 2026-10-20 daily build: security quartet M2/M3/L1/L2
from the 2026-10-18 weekly security review.

M2: POST / gets a dedicated per-IP sliding-window limiter (own usage
dict, monotonic clock, fixed 30/min + 600/hour caps, not LLM-gated),
/history is capped at LIMIT 500, and save_detections prunes rows older
than 30 days.
M3 (adapted): ipintel._fetch reads at most 64KB+1 and drops over-cap
bodies. (The https swap was NOT applied: the free ip-api endpoint
refuses SSL -- verified live 2026-10-20 -- so the scheme change is a
staged Tier 2 provider decision.)
L1: app.get_db() and ipintel._db() self-heal detections.db to 0600.
L2: netmon.config.load() self-heals an existing config.yaml to 0600.

Run: python -m unittest discover -s tests -v
"""
import json
import os
import stat
import sys
import tempfile
import unittest
from datetime import datetime, timedelta
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

import ipintel
from netmon import config as cfgm


def _mode(path):
    return stat.S_IMODE(os.stat(path).st_mode)


@unittest.skipIf(appm is None, "Flask not installed")
class TestScanLimiterMath(unittest.TestCase):
    def setUp(self):
        appm._SCAN_USAGE.clear()

    def test_fresh_ip_allowed(self):
        allowed, retry = appm._scan_allowed("10.7.7.1", now=1000.0,
                                            limits=(2, 5))
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def test_per_min_window_blocks_and_denied_not_recorded(self):
        now = 2000.0
        for _ in range(2):
            self.assertTrue(appm._scan_allowed(
                "10.7.7.2", now=now, limits=(2, 100))[0])
        allowed, retry = appm._scan_allowed("10.7.7.2", now=now + 1,
                                            limits=(2, 100))
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertLessEqual(retry, 60)
        # The denial must not consume budget: after the minute, allowed.
        self.assertTrue(appm._scan_allowed(
            "10.7.7.2", now=now + 62, limits=(2, 100))[0])

    def test_per_hour_window_blocks(self):
        now = 3000.0
        for _ in range(3):
            self.assertTrue(appm._scan_allowed(
                "10.7.7.3", now=now, limits=(100, 3))[0])
        allowed, _ = appm._scan_allowed("10.7.7.3", now=now + 61,
                                        limits=(100, 3))
        self.assertFalse(allowed)

    def test_scan_and_brief_budgets_are_independent(self):
        # Spending the scan budget must not touch the brief budget.
        appm._BRIEF_USAGE.clear()
        for _ in range(2):
            appm._scan_allowed("10.7.7.4", now=5000.0, limits=(2, 100))
        self.assertFalse(appm._scan_allowed(
            "10.7.7.4", now=5000.0, limits=(2, 100))[0])
        self.assertTrue(appm._brief_allowed(
            "10.7.7.4", now=5000.0, limits=(2, 100))[0])


@unittest.skipIf(appm is None, "Flask not installed")
class TestDemoWritePath(unittest.TestCase):
    def setUp(self):
        fd, self._db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._old_db_path = appm.DB_PATH
        appm.DB_PATH = self._db_path
        appm._SCAN_USAGE.clear()
        self.client = appm.app.test_client()

    def tearDown(self):
        appm.DB_PATH = self._old_db_path
        appm._SCAN_USAGE.clear()
        os.unlink(self._db_path)

    def test_post_blocked_with_429_when_scan_budget_spent(self):
        # Test client posts come from 127.0.0.1; spend its whole
        # per-minute budget directly, then the route must refuse.
        for _ in range(appm.SCAN_LIMITS[0]):
            self.assertTrue(appm._scan_allowed("127.0.0.1")[0])
        resp = self.client.post("/", data={"log": ""})
        self.assertEqual(resp.status_code, 429)
        self.assertIn("Retry-After", resp.headers)

    def test_post_allowed_under_budget(self):
        resp = self.client.post("/", data={"log": ""})
        self.assertEqual(resp.status_code, 200)

    def test_history_capped_at_500_rows(self):
        conn = appm.get_db()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn.executemany(
            "INSERT INTO detections (ip, count, severity, scanned_at)"
            " VALUES (?,?,?,?)",
            [("10.0.0.7", 5, "Medium", now)] * 505)
        conn.commit()
        conn.close()
        resp = self.client.get("/history")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.data.count(b"<tr><td>"), 500)

    def test_save_detections_prunes_rows_older_than_30_days(self):
        conn = appm.get_db()
        old = (datetime.now() - timedelta(days=31)).strftime(
            "%Y-%m-%d %H:%M:%S")
        fresh = (datetime.now() - timedelta(days=1)).strftime(
            "%Y-%m-%d %H:%M:%S")
        conn.execute(
            "INSERT INTO detections (ip, count, severity, scanned_at)"
            " VALUES (?,?,?,?)", ("10.1.1.1", 9, "High", old))
        conn.execute(
            "INSERT INTO detections (ip, count, severity, scanned_at)"
            " VALUES (?,?,?,?)", ("10.2.2.2", 9, "High", fresh))
        conn.commit()
        conn.close()
        appm.save_detections(
            [{"ip": "10.3.3.3", "count": 4, "severity": "Medium"}])
        self.assertEqual(appm.known_ips(), {"10.2.2.2", "10.3.3.3"})


@unittest.skipIf(appm is None, "Flask not installed")
class TestDbPermissionSelfHeal(unittest.TestCase):
    def _loose_db(self):
        fd, path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        os.chmod(path, 0o644)
        return path

    def test_app_get_db_heals_0644(self):
        path = self._loose_db()
        old = appm.DB_PATH
        appm.DB_PATH = path
        try:
            conn = appm.get_db()
            conn.close()
            self.assertEqual(_mode(path) & 0o077, 0)
        finally:
            appm.DB_PATH = old
            os.unlink(path)

    def test_ipintel_db_heals_0644(self):
        path = self._loose_db()
        old = ipintel.DB_PATH
        ipintel.DB_PATH = path
        try:
            conn = ipintel._db()
            conn.close()
            self.assertEqual(_mode(path) & 0o077, 0)
        finally:
            ipintel.DB_PATH = old
            os.unlink(path)


class TestConfigLoadSelfHeal(unittest.TestCase):
    def test_load_heals_loose_config_yaml(self):
        fd, path = tempfile.mkstemp(suffix=".yaml")
        with os.fdopen(fd, "w") as f:
            f.write("alerts:\n  digest_hours: 12\n")
        os.chmod(path, 0o644)
        try:
            from pathlib import Path
            cfg = cfgm.load(Path(path))
            self.assertEqual(_mode(path) & 0o077, 0)
            self.assertEqual(cfg["alerts"]["digest_hours"], 12)
        finally:
            os.unlink(path)


class _FakeResp:
    def __init__(self, body):
        self._body = body
        self.read_sizes = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def read(self, size=-1):
        self.read_sizes.append(size)
        if size is None or size < 0:
            return self._body
        return self._body[:size]


class TestIpIntelFetchCap(unittest.TestCase):
    def test_small_reply_parsed_and_read_is_bounded(self):
        body = json.dumps({
            "status": "success", "country": "United States",
            "org": "Example ISP", "proxy": False, "hosting": True,
        }).encode()
        resp = _FakeResp(body)
        with mock.patch.object(ipintel.urllib.request, "urlopen",
                               return_value=resp):
            intel = ipintel._fetch("8.8.8.8")
        self.assertEqual(intel["country"], "United States")
        self.assertTrue(intel["hosting"])
        self.assertEqual(resp.read_sizes, [ipintel.MAX_RESPONSE_BYTES + 1])

    def test_over_cap_reply_dropped(self):
        big = json.dumps({
            "status": "success", "country": "X",
            "org": "Y" * (ipintel.MAX_RESPONSE_BYTES + 100),
            "proxy": False, "hosting": False,
        }).encode()
        resp = _FakeResp(big)
        with mock.patch.object(ipintel.urllib.request, "urlopen",
                               return_value=resp):
            self.assertEqual(ipintel._fetch("8.8.8.8"), {})


if __name__ == "__main__":
    unittest.main()
