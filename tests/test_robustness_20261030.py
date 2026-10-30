"""Tests for the 2026-10-30 daily build: app.py demo-hardening
(security L1 + robustness M4, council review 2026-10-25).

L1: /brief counts are range-checked (1..BRIEF_MAX_COUNT) like the IP
and severity fields already were, and detector._count_line only
counts tokens that are real IP addresses -- attacker-controlled log
text no longer lands in detections.db as a fake "IP".

M4: sample_log() degrades to "" on an unreadable sample file instead
of crashing GET /; app.py sqlite connections close in `finally`
(get_db CREATE failure, known_ips, save_detections, /history); the
POST / temp-file unlink is guarded so a locked file on Windows can
never mask the scan result.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

from detector import detect_brute_force


def _log(lines):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    return tmp.name


def _fail(ip, n):
    return [
        f"Oct  2 19:{i:02d}:01 host sshd[{100+i}]: Failed password"
        f" for root from {ip} port 51234 ssh2"
        for i in range(n)
    ]


class TestDetectorValidatesIPs(unittest.TestCase):
    def _run(self, lines):
        path = _log(lines)
        try:
            return detect_brute_force(path, threshold=3)
        finally:
            os.unlink(path)

    def test_garbage_tokens_not_counted(self):
        out = self._run(_fail("evil.example", 5) + _fail("999.999.1.1", 5)
                        + _fail("203.0.113.7", 4))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "203.0.113.7")
        self.assertEqual(out[0]["count"], 4)

    def test_markup_shaped_token_not_counted(self):
        out = self._run(_fail("<script>alert(1)</script>", 5))
        self.assertEqual(out, [])

    def test_invalid_accepted_token_no_critical(self):
        lines = _fail("not-an-ip", 5) + [
            "Oct  2 20:01:01 host sshd[999]: Accepted password"
            " for admin from not-an-ip port 51235 ssh2"]
        self.assertEqual(self._run(lines), [])

    def test_ipv6_still_counted(self):
        out = self._run(_fail("2001:db8::1", 3))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "2001:db8::1")


@unittest.skipIf(appm is None, "Flask not installed")
class TestBriefCountRange(unittest.TestCase):
    def setUp(self):
        self.client = appm.app.test_client()
        appm._BRIEF_USAGE.clear()

    def _post(self, count):
        with mock.patch.object(
                appm, "write_brief",
                return_value=(appm.rule_based_brief("10.9.9.9", 5, "High"),
                              "rule-based")) as wb:
            resp = self.client.post(
                "/brief", data={"ip": "10.9.9.9", "count": str(count),
                                "severity": "High"})
        return resp, wb

    def test_zero_and_negative_counts_rejected(self):
        for bad in (0, -1, -100000):
            resp, wb = self._post(bad)
            self.assertEqual(resp.status_code, 400, bad)
            wb.assert_not_called()

    def test_huge_count_rejected(self):
        resp, wb = self._post(appm.BRIEF_MAX_COUNT + 1)
        self.assertEqual(resp.status_code, 400)
        wb.assert_not_called()

    def test_boundary_counts_accepted(self):
        for good in (1, appm.BRIEF_MAX_COUNT):
            resp, wb = self._post(good)
            self.assertEqual(resp.status_code, 200, good)
            wb.assert_called_once()


@unittest.skipIf(appm is None, "Flask not installed")
class TestSampleLogGuard(unittest.TestCase):
    def test_unreadable_sample_returns_empty(self):
        # auth.log as a directory: open() raises IsADirectoryError,
        # an OSError -- the form must degrade, not crash.
        with tempfile.TemporaryDirectory() as d:
            os.mkdir(os.path.join(d, "auth.log"))
            old = appm.BASE_DIR
            appm.BASE_DIR = d
            try:
                self.assertEqual(appm.sample_log(), "")
            finally:
                appm.BASE_DIR = old

    def test_missing_sample_returns_empty(self):
        with tempfile.TemporaryDirectory() as d:
            old = appm.BASE_DIR
            appm.BASE_DIR = d
            try:
                self.assertEqual(appm.sample_log(), "")
            finally:
                appm.BASE_DIR = old


@unittest.skipIf(appm is None, "Flask not installed")
class TestDbConnectionsCloseOnError(unittest.TestCase):
    def _bad_conn(self):
        conn = mock.Mock()
        conn.execute.side_effect = RuntimeError("db exploded")
        return conn

    def test_get_db_closes_on_create_failure(self):
        bad = self._bad_conn()
        with mock.patch.object(appm.sqlite3, "connect", return_value=bad):
            with self.assertRaises(RuntimeError):
                appm.get_db()
        bad.close.assert_called_once()

    def test_known_ips_closes_on_error(self):
        bad = self._bad_conn()
        with mock.patch.object(appm, "get_db", return_value=bad):
            with self.assertRaises(RuntimeError):
                appm.known_ips()
        bad.close.assert_called_once()

    def test_save_detections_closes_on_error(self):
        bad = self._bad_conn()
        with mock.patch.object(appm, "get_db", return_value=bad):
            with self.assertRaises(RuntimeError):
                appm.save_detections(
                    [{"ip": "10.1.1.1", "count": 4, "severity": "Medium"}])
        bad.close.assert_called_once()

    def test_history_closes_on_error(self):
        bad = self._bad_conn()
        client = appm.app.test_client()
        with mock.patch.object(appm, "get_db", return_value=bad):
            resp = client.get("/history")
        self.assertEqual(resp.status_code, 500)
        bad.close.assert_called_once()


@unittest.skipIf(appm is None, "Flask not installed")
class TestUnlinkGuard(unittest.TestCase):
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

    def test_post_survives_unlink_failure(self):
        log = "\n".join(_fail("203.0.113.9", 4))
        with mock.patch.object(appm.os, "unlink",
                               side_effect=OSError("file locked")):
            resp = self.client.post("/", data={"log": log})
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"203.0.113.9", resp.data)


if __name__ == "__main__":
    unittest.main()
