"""Robustness R2 (2026-11-08 council review): ingest rules must not
skip the oldest events of a >5,000-event backlog, and watermarks must
advance only to the newest event actually processed, never to `now`.

Before the fix, _new_events fetched the newest 5,000 rows once
(host_events_since ordered ts DESC) and every rule stamped its
watermark with time.time(), so a burst sitting in the older half of a
backlog produced no alert and could never be evaluated later.
"""
import json
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase
from netmon import db as dbm
from netmon import ingest as ingm


def _ev(ts, event_id, fields, source="eventlog", computer="HOST1"):
    detail = json.dumps({"summary": "x", "fields": fields})
    return (ts, source, event_id, computer, "u", detail)


def _logon(ts, ip):
    return _ev(ts, "4625", {"IpAddress": ip, "TargetUserName": "victim",
                            "LogonType": "3"})


class TestBacklogNotSkipped(ScratchDbTestCase):
    def test_oldest_burst_in_large_backlog_fires(self):
        # The council repro: 6-event burst, then 6,000 newer fillers.
        base = time.time() - 100000
        rows = [_logon(base + i * 60, "203.0.113.9") for i in range(6)]
        rows += [_logon(base + 1000 + i, "-") for i in range(6000)]
        dbm.insert_host_events(rows)
        self.assertEqual(ingm.check_failed_logons(), 1)
        # Watermark = newest event actually processed, not wall-clock.
        wm = float(dbm.get_meta("ingest_correlate_4625_ts"))
        self.assertEqual(wm, base + 1000 + 5999)
        self.assertLess(wm, time.time() - 50000)

    def test_buried_new_service_fires(self):
        # A 7045 oldest, buried under 6,000 newer rows of another kind:
        # the raw paging must walk past the filler, not just matches.
        base = time.time() - 100000
        rows = [_ev(base, "7045", {"ServiceName": "EvilSvc",
                                   "ImagePath": "C:\\evil\\evil.exe"})]
        rows += [_logon(base + 1000 + i, "-") for i in range(6000)]
        dbm.insert_host_events(rows)
        self.assertEqual(ingm.check_new_services(), 1)
        wm = float(dbm.get_meta("ingest_correlate_7045_ts"))
        self.assertEqual(wm, base)

    def test_event_older_than_wall_clock_now_is_not_skipped(self):
        # First pass processes one old, quiet event; a burst that was
        # stored late (ts after the first pass's max, but long before
        # wall-clock now) must still fire on the next pass. With the
        # old stamp-to-now watermark it fell behind forever.
        base = time.time() - 100000
        dbm.insert_host_events([_logon(base, "-")])
        self.assertEqual(ingm.check_failed_logons(), 0)
        dbm.insert_host_events(
            [_logon(base + 3600 + i * 60, "203.0.113.9") for i in range(6)])
        self.assertEqual(ingm.check_failed_logons(), 1)

    def test_watermark_advances_only_to_processed_ts(self):
        base = time.time() - 50000
        dbm.insert_host_events([_logon(base, "-")])  # below threshold
        self.assertEqual(ingm.check_failed_logons(), 0)
        wm = float(dbm.get_meta("ingest_correlate_4625_ts"))
        self.assertEqual(wm, base)


class TestHostEventsSincePaging(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        base = 1_700_000_000.0
        self.base = base
        dbm.insert_host_events(
            [_logon(base + i * 10, "-") for i in range(5)])

    def test_default_stays_newest_first(self):
        rows = dbm.host_events_since(self.base - 1, limit=2)
        self.assertEqual([r["ts"] for r in rows],
                         [self.base + 40, self.base + 30])

    def test_ascending_pages_walk_the_whole_window(self):
        page1 = dbm.host_events_since(self.base - 1, limit=2, offset=0,
                                      ascending=True)
        page2 = dbm.host_events_since(self.base - 1, limit=2, offset=2,
                                      ascending=True)
        page3 = dbm.host_events_since(self.base - 1, limit=2, offset=4,
                                      ascending=True)
        self.assertEqual([r["ts"] for r in page1],
                         [self.base, self.base + 10])
        self.assertEqual([r["ts"] for r in page2],
                         [self.base + 20, self.base + 30])
        self.assertEqual([r["ts"] for r in page3], [self.base + 40])


if __name__ == "__main__":
    unittest.main()
