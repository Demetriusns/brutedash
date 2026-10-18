"""Tests for netmon/weekly.py -- council review 2026-10-18.

The weekly report used to die on its first database query: one DB
hiccup (locked / corrupt / missing table) raised out of
generate_weekly_report, killed the --weekly-report CLI in run.py,
and the owner got no report at all -- contradicting the module's own
"degrades gracefully" docstring. It also rendered raw packet counts
and port numbers, contradicting its "no jargon" docstring.

Covered:
- a failing db.query never raises; the report is flagged degraded
  and still renders as plain text with a plain-English note;
- a healthy (empty) database is NOT flagged degraded;
- the plain-text rendering contains no "packets" / "port <n>" jargon.
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import weekly as weekm

from helpers import ScratchDbTestCase


def _boom(sql, params=()):
    raise RuntimeError("database is locked")


class WeeklyDegradedTest(unittest.TestCase):
    def test_db_failure_never_raises_and_flags_degraded(self):
        with mock.patch.object(weekm.dbm, "query", side_effect=_boom):
            report = weekm.generate_weekly_report(now=time.time())
        self.assertTrue(report["degraded"])
        self.assertEqual(report["totals"]["mb"], 0)
        self.assertEqual(report["top_talkers"], [])
        self.assertIn("couldn't read", report["headline"])

    def test_degraded_report_still_renders_with_plain_note(self):
        with mock.patch.object(weekm.dbm, "query", side_effect=_boom):
            report = weekm.generate_weekly_report(now=time.time())
        text = weekm.format_plaintext(report)
        self.assertIn("couldn't be read", text)
        self.assertIn("Your network this week", text)

    def test_partial_failure_still_degrades(self):
        real_query = weekm.dbm.query
        calls = {"n": 0}

        def flaky(sql, params=()):
            calls["n"] += 1
            if calls["n"] > 1:
                raise RuntimeError("no such table: alerts")
            return real_query(sql, params)

        # No scratch DB here: the first (real) call may itself fail on
        # an uninitialised DB, which also counts as degraded -- either
        # way the report must come back flagged, never raise.
        with mock.patch.object(weekm.dbm, "query", side_effect=flaky):
            report = weekm.generate_weekly_report(now=time.time())
        self.assertTrue(report["degraded"])


class WeeklyPlainLanguageTest(ScratchDbTestCase):
    def test_empty_db_is_not_degraded(self):
        report = weekm.generate_weekly_report(now=time.time())
        self.assertFalse(report["degraded"])

    def test_plaintext_has_no_packet_or_port_jargon(self):
        report = weekm.generate_weekly_report(now=time.time())
        text = weekm.format_plaintext(report)
        self.assertNotIn("packets", text)
        self.assertNotIn("Mainly port", text)

    def test_talker_lines_have_no_packet_or_port_jargon(self):
        now = time.time()
        with mock.patch.object(
                weekm.dbm, "query",
                side_effect=[
                    [(1024 * 1024, 10, 3)],          # totals
                    [("203.0.113.7", 5 * 1024 * 1024, 42)],  # talkers
                    [(443, "tcp", 5 * 1024 * 1024)],  # main port
                    [], [], [(0, 0)], [], [], [],
                ]):
            report = weekm.generate_weekly_report(now=now)
        self.assertFalse(report["degraded"])
        self.assertEqual(len(report["top_talkers"]), 1)
        line = report["top_talkers"][0]
        self.assertNotIn("packets", line)
        self.assertNotIn("port 443", line)
        self.assertIn("encrypted web browsing", line)


if __name__ == "__main__":
    unittest.main()
