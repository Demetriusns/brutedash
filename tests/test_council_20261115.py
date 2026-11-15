"""Council review 2026-11-15: "the monitor must keep moving."

Shipped batch (all robustness seat, head-verified):
  N1 (High)  -- the R2 ingest fix paged the WHOLE backlog into one
                list per rule and filtered in Python; a rule with no
                matching events never advanced its watermark and
                re-scanned everything every pass, and the failed-logon
                burst scan was O(n^2) with 3 correlation queries per
                event. Filtering now runs in SQL, a per-pass ceiling
                carries the remainder over, correlation is per-IP, the
                burst scan is two-pointer, and the monitor loop gives
                the ingest step the same timeout as the scanners.
  N2 (Med)   -- retention held the global DB lock across a whole
                table prune; the lock is now held per batch only.
  R9 (Med)   -- quiet-hours windows wrapping midnight tested the
                after-midnight half against the wrong weekday.
  R10 (Low)  -- nuclei/amass JSONL parsing read the whole file into
                memory twice; it now streams under a byte cap.
  L3 (Low)   -- the notify worker was never restarted if its thread
                died (the pre-fix canary pattern); it now restarts,
                mirroring canary.start() after R4.

Run: python -m unittest discover -s tests -v
"""
import json
import os
import sys
import threading
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, scratch_file
from netmon import amass as amassm
from netmon import db as dbm
from netmon import ingest as ingm
from netmon import notify as notifm
from netmon import nuclei as nucleim
from netmon import retention as retm


def _ev(ts, event_id, fields, source="eventlog", computer="HOST1"):
    detail = json.dumps({"summary": "x", "fields": fields})
    return (ts, source, event_id, computer, "u", detail)


def _logon(ts, ip):
    return _ev(ts, "4625", {"IpAddress": ip, "TargetUserName": "victim",
                            "LogonType": "3"})


class TestN1SqlFiltering(ScratchDbTestCase):
    def test_host_events_since_filters_in_sql(self):
        base = 1_700_000_000.0
        dbm.insert_host_events([
            _logon(base, "-"),
            _ev(base + 1, "7045", {"ServiceName": "S"}),
            _ev(base + 2, "5156", {}, source="pfirewall"),
            _logon(base + 3, "-"),
        ])
        rows = dbm.host_events_since(base - 1, ascending=True,
                                     source="eventlog",
                                     event_ids=("4625",))
        self.assertEqual([r["ts"] for r in rows], [base, base + 3])
        # Unfiltered callers (dashboard) are unchanged.
        self.assertEqual(
            len(dbm.host_events_since(base - 1, ascending=True)), 4)

    def test_no_match_pass_fetches_nothing(self):
        # The seat's repro: 12,000 non-matching events. Post-fix the
        # rule's fetch returns zero rows (the filter is in SQL), and a
        # second pass is just as cheap -- pre-fix each pass
        # materialised all 12,000 rows in Python.
        base = time.time() - 100000
        dbm.insert_host_events(
            [_ev(base + i, "5156", {}, source="pfirewall")
             for i in range(12000)])
        fetched = []
        orig = dbm.host_events_since

        def counting(*a, **k):
            rows = orig(*a, **k)
            fetched.append(len(rows))
            return rows

        dbm.host_events_since = counting
        try:
            self.assertEqual(ingm.check_failed_logons(), 0)
            self.assertEqual(ingm.check_failed_logons(), 0)
        finally:
            dbm.host_events_since = orig
        self.assertEqual(sum(fetched), 0)

    def test_matching_burst_still_fires_after_filtering(self):
        base = time.time() - 100000
        dbm.insert_host_events(
            [_ev(base + i, "5156", {}, source="pfirewall")
             for i in range(2000)])
        dbm.insert_host_events(
            [_logon(base + 5000 + i * 60, "203.0.113.9")
             for i in range(6)])
        self.assertEqual(ingm.check_failed_logons(), 1)


class TestN1PassCeiling(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._saved = (ingm._NEW_EVENTS_PAGE, ingm._MAX_EVENTS_PER_PASS)
        ingm._NEW_EVENTS_PAGE = 5
        ingm._MAX_EVENTS_PER_PASS = 12

    def tearDown(self):
        (ingm._NEW_EVENTS_PAGE,
         ingm._MAX_EVENTS_PER_PASS) = self._saved
        super().tearDown()

    def test_ceiling_carries_remainder_to_next_pass(self):
        base = 1_700_000_000.0
        dbm.insert_host_events(
            [_logon(base + i * 10, "-") for i in range(20)])
        first = ingm._new_events(base - 1, source="eventlog",
                                 event_ids=("4625",))
        # Page-granular ceiling: 3 pages of 5, then the peek stops it.
        self.assertEqual(len(first), 15)
        rest = ingm._new_events(first[-1]["ts"], source="eventlog",
                                event_ids=("4625",))
        self.assertEqual(len(rest), 5)
        self.assertEqual(first[-1]["ts"] + 50, rest[-1]["ts"])

    def test_ceiling_never_strands_a_same_ts_group(self):
        base = 1_700_000_000.0
        rows = [_logon(base + i * 10, "-") for i in range(13)]
        rows += [_logon(base + 1000, "-") for _ in range(7)]
        dbm.insert_host_events(rows)
        got = ingm._new_events(base - 1, source="eventlog",
                               event_ids=("4625",))
        # The ceiling lands inside the ts=base+1000 group; the pass
        # must consume the whole group, or the watermark (ts-only)
        # would skip the rest of it forever.
        self.assertEqual(len(got), 20)


class TestN1BurstWindow(ScratchDbTestCase):
    def test_burst_at_exact_window_edge_fires(self):
        base = time.time() - 10000
        dbm.insert_host_events(
            [_logon(base + d, "203.0.113.9")
             for d in (0, 150, 300, 450, 600)])
        self.assertEqual(ingm.check_failed_logons(), 1)

    def test_burst_just_outside_window_stays_quiet(self):
        base = time.time() - 10000
        dbm.insert_host_events(
            [_logon(base + d, "203.0.113.9")
             for d in (0, 150, 300, 450, 601)])
        self.assertEqual(ingm.check_failed_logons(), 0)

    def test_large_single_ip_history_no_burst(self):
        base = time.time() - 900000
        dbm.insert_host_events(
            [_logon(base + i * 3600, "203.0.113.9") for i in range(500)])
        self.assertEqual(ingm.check_failed_logons(), 0)


class _CountingLock:
    def __init__(self, real):
        self._real = real
        self.count = 0

    def __enter__(self):
        self.count += 1
        return self._real.__enter__()

    def __exit__(self, *exc):
        return self._real.__exit__(*exc)

    def acquire(self, *a, **k):
        return self._real.acquire(*a, **k)

    def release(self):
        return self._real.release()

    def locked(self):
        return self._real.locked()


class TestN2RetentionLock(ScratchDbTestCase):
    def test_prune_releases_lock_between_batches(self):
        old = time.time() - 100 * 86400
        dbm.insert_host_events(
            [(old + i, "eventlog", "4625", "PC1", "bob", "x")
             for i in range(250)])
        counter = _CountingLock(dbm._lock)
        real = dbm._lock
        dbm._lock = counter
        try:
            deleted = retm._prune_table("host_events",
                                        time.time() - 90 * 86400, 100)
        finally:
            dbm._lock = real
        self.assertEqual(deleted, 250)
        # 250 rows / batch 100 = 3 batches = 3 separate acquisitions
        # (pre-fix the whole prune was a single acquisition).
        self.assertGreaterEqual(counter.count, 3)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM host_events")[0][0], 0)


def _ts(year, month, day, hour, minute=0):
    return datetime(year, month, day, hour, minute).timestamp()


class TestR9QuietHoursWrap(unittest.TestCase):
    # 2026-11-13 is a Friday, 11-14 a Saturday, 11-16 a Monday.
    def setUp(self):
        self.assertEqual(datetime(2026, 11, 13).weekday(), 4)
        self.assertEqual(datetime(2026, 11, 16).weekday(), 0)
        self._orig = dbm.get_quiet_hours

    def tearDown(self):
        dbm.get_quiet_hours = self._orig

    def _set_windows(self, windows):
        dbm.get_quiet_hours = lambda: windows

    def test_friday_night_window_covers_saturday_early_hours(self):
        self._set_windows([{"days": [4], "start": "22:00",
                            "end": "06:00", "kinds": ["all"]}])
        self.assertTrue(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 13, 23)))
        # The R9 bug: this was False before the fix.
        self.assertTrue(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 14, 3)))
        self.assertFalse(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 14, 23)))
        self.assertFalse(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 15, 3)))

    def test_monday_window_does_not_reach_back_to_monday_early(self):
        self._set_windows([{"days": [0], "start": "22:00",
                            "end": "06:00", "kinds": ["all"]}])
        # Monday 03:00 belongs to a Sunday-night window (not listed).
        self.assertFalse(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 16, 3)))
        # Tuesday 03:00 belongs to Monday's window.
        self.assertTrue(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 17, 3)))

    def test_non_wrap_window_unchanged(self):
        self._set_windows([{"days": [5], "start": "12:00",
                            "end": "14:00", "kinds": ["all"]}])
        self.assertTrue(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 14, 13)))
        self.assertFalse(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 15, 13)))

    def test_no_days_means_every_day_still_wraps(self):
        self._set_windows([{"days": [], "start": "22:00",
                            "end": "06:00", "kinds": ["all"]}])
        self.assertTrue(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 14, 3)))
        self.assertFalse(notifm.in_quiet_hours(
            "host_event", now=_ts(2026, 11, 14, 12)))


_NUCLEI_LINE = json.dumps({
    "template-id": "t-one", "type": "http",
    "host": "http://192.168.1.10",
    "matched-at": "http://192.168.1.10/",
    "info": {"name": "One", "severity": "medium"}})
_NUCLEI_LINE2 = json.dumps({
    "template-id": "t-two", "type": "http",
    "host": "http://192.168.1.11",
    "matched-at": "http://192.168.1.11/",
    "info": {"name": "Two", "severity": "high"}})
_AMASS_LINE = json.dumps({
    "name": "www.example.com", "domain": "example.com",
    "addresses": ["93.184.216.34"], "tag": "cert", "sources": ["crtsh"]})
_AMASS_LINE2 = json.dumps({
    "name": "api.example.com", "domain": "example.com",
    "addresses": ["93.184.216.35"], "tag": "dns", "sources": []})


class TestR10StreamingParse(unittest.TestCase):
    def test_nuclei_file_matches_text_parse(self):
        text = _NUCLEI_LINE + "\nnot json\n" + _NUCLEI_LINE2 + "\n"
        with scratch_file(suffix=".jsonl", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.assertEqual(nucleim.parse_jsonl_file(path),
                             nucleim.parse_jsonl_text(text))

    def test_amass_file_matches_text_parse(self):
        text = _AMASS_LINE + "\n" + _AMASS_LINE2 + "\n"
        with scratch_file(suffix=".jsonl", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            self.assertEqual(amassm.parse_jsonl_file(path),
                             amassm.parse_jsonl_text(text))

    def test_byte_cap_keeps_partial_findings(self):
        text = _NUCLEI_LINE + "\n" + _NUCLEI_LINE2 + "\n"
        with scratch_file(suffix=".jsonl", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
            saved = nucleim.MAX_JSONL_BYTES
            nucleim.MAX_JSONL_BYTES = len(_NUCLEI_LINE) + 1
            try:
                got = nucleim.parse_jsonl_file(path)
            finally:
                nucleim.MAX_JSONL_BYTES = saved
        self.assertEqual([f["template_id"] for f in got], ["t-one"])

    def test_missing_file_is_empty(self):
        self.assertEqual(nucleim.parse_jsonl_file("/nope/x.jsonl"), [])
        self.assertEqual(amassm.parse_jsonl_file("/nope/x.jsonl"), [])


class TestL3NotifyWorkerRestart(unittest.TestCase):
    def test_dead_worker_is_restarted(self):
        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()
        saved = (notifm._worker_started, notifm._worker_thread)
        notifm._worker_started = True
        notifm._worker_thread = dead
        try:
            notifm._ensure_worker()
            self.assertIsNot(notifm._worker_thread, dead)
            self.assertTrue(notifm._worker_thread.is_alive())
        finally:
            # Leave the healthy live worker recorded (production
            # state); only restore if ensure failed to replace it.
            if notifm._worker_thread is dead:
                (notifm._worker_started,
                 notifm._worker_thread) = saved

    def test_live_worker_is_not_replaced(self):
        notifm._ensure_worker()
        first = notifm._worker_thread
        self.assertTrue(first.is_alive())
        notifm._ensure_worker()
        self.assertIs(notifm._worker_thread, first)


if __name__ == "__main__":
    unittest.main()
