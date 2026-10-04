"""Tests for log-file ingestion progress tracking (netmon/ingest.py).

Council review: a .log file replaced wholesale under the same name (new
export copy) with a size >= the old one used to keep the stale byte offset,
silently skipping the new file's head. The inode is now tracked so a
replaced file is re-read from the top, while plain appends keep the fast
path. Run: python -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, scratch_dir
from netmon import db as dbm
from netmon import ingest as ingm

FIELDS = "#Fields: date time action\n"
ROW = "2026-10-04 10:00:0%d DROP\n"


class TestIngestInode(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_watch = ingm.watch_dir

    def tearDown(self):
        ingm.watch_dir = self._old_watch
        super().tearDown()

    def _run_in(self, d):
        ingm.watch_dir = lambda: d  # noqa: E731
        return ingm.run_ingest()

    def test_replaced_larger_file_is_reread_from_top(self):
        # First pass: one DROP row -> offset recorded with the inode.
        with scratch_dir() as d:
            path = os.path.join(d, "pfirewall.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(FIELDS + ROW % 1)
            s1 = self._run_in(d)
            self.assertTrue(s1["enabled"])
            self.assertEqual(s1["events"], 1)
            state = dbm.ingest_state_get(path)
            self.assertGreater(state["offset"], 0)
            self.assertIsNotNone(state["inode"])

            # Replace the file wholesale under the same name with a LARGER
            # file (new export copy): different inode, size >= old size.
            os.unlink(path)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(FIELDS + ROW % 2 + ROW % 3 + ROW % 4)
            self.assertGreaterEqual(os.path.getsize(path),
                                    state["offset"])
            s2 = self._run_in(d)
            # All three new rows must be seen: the stale offset was reset.
            self.assertEqual(s2["events"], 3,
                             "replaced log was not re-read from the top")

    def test_plain_append_keeps_offset(self):
        # Appends keep the inode: the stale offset is NOT reset to zero --
        # the second pass continues from the recorded offset with the same
        # inode (fast path). (Note: resumed rows need the #Fields header,
        # which lives at the file head -- a separate pre-existing parser
        # limitation, not this change.)
        with scratch_dir() as d:
            path = os.path.join(d, "pfirewall.log")
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(FIELDS + ROW % 1)
            self._run_in(d)
            before = dbm.ingest_state_get(path)
            with open(path, "a", encoding="utf-8") as fh:
                fh.write(ROW % 2)
            self._run_in(d)
            after = dbm.ingest_state_get(path)
            self.assertEqual(after["inode"], before["inode"])
            self.assertEqual(after["offset"], os.path.getsize(path))
            self.assertGreater(after["offset"], before["offset"])

    def test_inode_column_migrates(self):
        cols = {r[1] for r in dbm._db().execute(
            "PRAGMA table_info(ingest_state)")}
        self.assertIn("inode", cols)


if __name__ == "__main__":
    unittest.main()
