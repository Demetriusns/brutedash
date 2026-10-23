"""Tests for robustness R6+R7 (2026-10-18 council review, shipped
2026-10-23).

R6 -- netmon/db.py _db() lazy init was unsynchronized: two threads
taking their first _db() concurrently both ran _connect() (full schema
+ migrations), one connection was leaked and the concurrent DDL could
surface as "database is locked" at startup. Fixed with double-checked
locking on a dedicated init lock (the module _lock cannot be used --
callers already hold it and it is not re-entrant).

R7 -- netmon/ingest.py run_ingest(): os.path.getmtime / getsize in the
per-file loop were unguarded, so one file vanishing mid-pass (routine
log rotation) aborted ingestion for every remaining file and left
ingest_last_run_ts unstamped, repeating the failure every cycle. The
per-file body now catches OSError, counts the file in
summary["files_skipped"], and continues.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, scratch_dir
from netmon import db as dbm
from netmon import ingest as ingm

FIELDS = "#Fields: date time action\n"
ROW = "2026-10-04 10:00:0%d DROP\n"


class TestDbLazyInitRace(ScratchDbTestCase):
    """R6: concurrent first _db() calls create exactly one connection."""

    def tearDown(self):
        # fresh_db()/restore_db() manage _conn; also drop any fake the
        # race stub installed so no sentinel leaks into other tests.
        super().tearDown()

    def test_concurrent_first_calls_connect_exactly_once(self):
        calls = []
        sentinel = object()

        def slow_fake_connect():
            calls.append(1)
            time.sleep(0.25)  # widen the race window deterministically
            return sentinel

        old_connect = dbm._connect
        dbm._connect = slow_fake_connect
        dbm._conn = None
        try:
            barrier = threading.Barrier(8)
            results = []

            def worker():
                barrier.wait(timeout=10)
                results.append(dbm._db())

            threads = [threading.Thread(target=worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join(timeout=15)
            self.assertEqual(len(results), 8)
            self.assertEqual(len(calls), 1,
                             "_connect ran more than once under race")
            self.assertTrue(all(r is sentinel for r in results),
                            "threads did not all get the one connection")
        finally:
            dbm._connect = old_connect
            dbm._conn = None

    def test_second_call_reuses_connection_without_reconnect(self):
        calls = []
        sentinel = object()

        def fake_connect():
            calls.append(1)
            return sentinel

        old_connect = dbm._connect
        dbm._connect = fake_connect
        dbm._conn = None
        try:
            self.assertIs(dbm._db(), sentinel)
            self.assertIs(dbm._db(), sentinel)
            self.assertEqual(len(calls), 1)
        finally:
            dbm._connect = old_connect
            dbm._conn = None

    def test_thread_local_isolated_connection_still_wins(self):
        calls = []

        def fake_connect():
            calls.append(1)
            return object()

        old_connect = dbm._connect
        dbm._connect = fake_connect
        dbm._conn = None
        try:
            sentinel = object()
            dbm._thread_state.conn = sentinel
            try:
                self.assertIs(dbm._db(), sentinel)
            finally:
                del dbm._thread_state.conn
            self.assertEqual(calls, [],
                             "isolated thread-local path called _connect")
        finally:
            dbm._connect = old_connect
            dbm._conn = None


class TestIngestVanishingFile(ScratchDbTestCase):
    """R7: a file vanishing mid-pass skips only that file."""

    def setUp(self):
        super().setUp()
        self._old_watch = ingm.watch_dir
        self._old_safe = ingm._safe_files

    def tearDown(self):
        ingm.watch_dir = self._old_watch
        ingm._safe_files = self._old_safe
        super().tearDown()

    def _write_log(self, d, name, rows):
        path = os.path.join(d, name)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(FIELDS + "".join(ROW % r for r in rows))
        return path

    def test_file_vanished_before_stat_is_skipped_pass_completes(self):
        with scratch_dir() as d:
            good = self._write_log(d, "good.log", [1])
            ghost = os.path.join(d, "ghost.log")  # never created
            ingm.watch_dir = lambda: d  # noqa: E731
            ingm._safe_files = lambda _d: iter([ghost, good])
            summary = ingm.run_ingest()
            self.assertNotIn("error", summary)
            self.assertEqual(summary["files"], 2)
            self.assertEqual(summary["files_skipped"], 1)
            self.assertEqual(summary["events"], 1,
                             "later file was not ingested after the skip")
            self.assertIsNotNone(dbm.get_meta("ingest_last_run_ts"),
                                 "pass did not stamp ingest_last_run_ts")

    def test_file_vanished_at_getsize_is_skipped(self):
        with scratch_dir() as d:
            bad = self._write_log(d, "bad.log", [1])
            good = self._write_log(d, "good.log", [2])
            ingm.watch_dir = lambda: d  # noqa: E731
            ingm._safe_files = lambda _d: iter([bad, good])
            real_getsize = os.path.getsize

            def flaky_getsize(p):
                if os.path.abspath(p) == os.path.abspath(bad):
                    raise FileNotFoundError("rotated away")
                return real_getsize(p)

            with mock.patch("os.path.getsize", side_effect=flaky_getsize):
                summary = ingm.run_ingest()
            self.assertNotIn("error", summary)
            self.assertEqual(summary["files_skipped"], 1)
            self.assertEqual(summary["events"], 1)
            self.assertIsNotNone(dbm.get_meta("ingest_last_run_ts"))

    def test_normal_pass_counts_no_skipped_files(self):
        with scratch_dir() as d:
            self._write_log(d, "a.log", [1])
            self._write_log(d, "b.log", [2])
            ingm.watch_dir = lambda: d  # noqa: E731
            summary = ingm.run_ingest()
            self.assertNotIn("error", summary)
            self.assertEqual(summary["files"], 2)
            self.assertEqual(summary["files_skipped"], 0)
            self.assertEqual(summary["events"], 2)


if __name__ == "__main__":
    unittest.main()
