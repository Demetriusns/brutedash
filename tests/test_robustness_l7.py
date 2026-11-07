"""Tests for the 2026-11-07 daily build: robustness L7 (council
review 2026-11-01, finding 7) -- the app.py demo residuals.

L7a: sample_log() caps its read at SAMPLE_MAX_BYTES (256 KB) instead
of loading the whole sample file into memory on every GET /.
L7b: app.get_db() and ipintel._db() open detections.db with
timeout=30 (PRAGMA busy_timeout 30000), matching netmon/db.py,
instead of the sqlite3 default 5s that turned a held lock into a 500.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

try:
    import ipintel
except ImportError:
    ipintel = None


@unittest.skipIf(appm is None, "Flask not installed")
class TestSampleLogCap(unittest.TestCase):
    def _with_sample(self, content):
        d = tempfile.TemporaryDirectory()
        with open(os.path.join(d.name, "auth.log"), "w") as f:
            f.write(content)
        old = appm.BASE_DIR
        appm.BASE_DIR = d.name
        self.addCleanup(setattr, appm, "BASE_DIR", old)
        self.addCleanup(d.cleanup)
        return appm.sample_log()

    def test_oversized_sample_truncated_at_cap(self):
        got = self._with_sample("x" * (appm.SAMPLE_MAX_BYTES + 10000))
        self.assertEqual(len(got), appm.SAMPLE_MAX_BYTES)

    def test_small_sample_returned_whole(self):
        content = "Oct  2 19:00:01 host sshd[1]: Failed password\n"
        self.assertEqual(self._with_sample(content), content)

    def test_missing_sample_still_empty(self):
        with tempfile.TemporaryDirectory() as d:
            old = appm.BASE_DIR
            appm.BASE_DIR = d
            try:
                self.assertEqual(appm.sample_log(), "")
            finally:
                appm.BASE_DIR = old


@unittest.skipIf(appm is None, "Flask not installed")
class TestAppDbTimeout(unittest.TestCase):
    def test_get_db_busy_timeout_is_30s(self):
        with tempfile.TemporaryDirectory() as d:
            old = appm.DB_PATH
            appm.DB_PATH = os.path.join(d, "detections.db")
            try:
                conn = appm.get_db()
                try:
                    busy = conn.execute(
                        "PRAGMA busy_timeout").fetchone()[0]
                finally:
                    conn.close()
            finally:
                appm.DB_PATH = old
        self.assertEqual(busy, 30000)


@unittest.skipIf(ipintel is None, "ipintel unavailable")
class TestIpintelDbTimeout(unittest.TestCase):
    def test_db_busy_timeout_is_30s(self):
        with tempfile.TemporaryDirectory() as d:
            old = ipintel.DB_PATH
            ipintel.DB_PATH = os.path.join(d, "detections.db")
            try:
                conn = ipintel._db()
                try:
                    busy = conn.execute(
                        "PRAGMA busy_timeout").fetchone()[0]
                finally:
                    conn.close()
            finally:
                ipintel.DB_PATH = old
        self.assertEqual(busy, 30000)


if __name__ == "__main__":
    unittest.main()
