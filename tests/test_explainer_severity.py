"""Severity-aware evidence tests for netmon/explainer.py (session #15).

The lesson: build_evidence() used to pull alerts ORDER BY ts DESC LIMIT
10 -- pure recency. Eleven alerts in the window and the oldest (maybe
the Critical one) vanished silently. Now alerts are severity-first, and
any omission is disclosed in the evidence text.

These tests run against a throwaway SQLite file, never the real netmon.db.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon import db as dbm
from netmon import explainer


class TestSeverityEvidence(unittest.TestCase):
    def setUp(self):
        self._real_path = dbm.DB_PATH
        self._real_conn = dbm._conn
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        self._tmp = tmp.name
        dbm.DB_PATH = self._tmp
        dbm._conn = None

    def tearDown(self):
        try:
            if dbm._conn is not None:
                dbm._conn.close()
        except Exception:
            pass
        dbm._conn = self._real_conn
        dbm.DB_PATH = self._real_path
        os.unlink(self._tmp)

    def _add_alert(self, ts, severity, title):
        conn = dbm._db()
        conn.execute(
            "INSERT INTO alerts(ts, kind, severity, title, detail)"
            " VALUES (?,?,?,?,?)",
            (ts, "test", severity, title, "detail"))
        conn.commit()

    def test_critical_oldest_survives_recency_flood(self):
        now = time.time()
        # 11 newer Low alerts flood the window; the Critical is the oldest.
        self._add_alert(now - 59 * 60, "Critical", "CRITICAL-OLD")
        for i in range(1, 12):
            self._add_alert(now - i * 60, "Low", f"low-{i}")
        evidence = explainer.build_evidence(window_min=60, now=now)
        self.assertIn("CRITICAL-OLD", evidence)
        self.assertIn("[Critical]", evidence)

    def test_omission_is_disclosed(self):
        now = time.time()
        for i in range(12):
            self._add_alert(now - i * 60, "Low", f"low-{i}")
        evidence = explainer.build_evidence(window_min=60, now=now)
        self.assertIn("omitted", evidence)
        self.assertIn("2 more", evidence)

    def test_no_omission_note_when_everything_fits(self):
        now = time.time()
        self._add_alert(now - 60, "High", "only-alert")
        evidence = explainer.build_evidence(window_min=60, now=now)
        self.assertIn("only-alert", evidence)
        self.assertNotIn("omitted", evidence)

    def test_stands_out_orders_worst_first(self):
        alerts = [("Low", "a", "", ""), ("Critical", "b", "", ""),
                  ("Medium", "c", "", ""), ("High", "d", "", "")]
        bullets = explainer.compact_stands_out(alerts)
        self.assertTrue(bullets[0].startswith("b"))
        self.assertTrue(bullets[1].startswith("d"))


if __name__ == "__main__":
    unittest.main()
