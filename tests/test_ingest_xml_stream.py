"""Tests for streaming Windows event XML ingestion (netmon/ingest.py).

Robustness M5 (council review 2026-11-01): parse_security_xml used to
ET.parse a whole export (up to 50 MB) into a DOM and accumulate every
event into one list before run_ingest inserted anything -- head-measured
at 71.1 MB peak traced allocations for an 11.6 MB / 20,000-event file.
The streaming core (iterparse, per-Event clear, bounded emit batches)
must keep the same tuples, order, skipped counting and failure shapes
while never holding the file. Run: python -m unittest discover -s tests
"""
import json
import os
import sys
import tempfile
import tracemalloc
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, scratch_dir
from netmon import db as dbm
from netmon import ingest as ingm


def _event(idx, pad=""):
    sec = idx % 60
    minute = (idx // 60) % 60
    hour = 14 + (idx // 3600)
    return (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        "<System><EventID>4625</EventID>"
        f'<TimeCreated SystemTime="2026-10-03T{hour:02d}:{minute:02d}:{sec:02d}Z"/>'
        "<Computer>PC-01</Computer><Channel>Security</Channel></System>"
        "<EventData>"
        f'<Data Name="TargetUserName">user{idx}</Data>'
        '<Data Name="IpAddress">203.0.113.9</Data>'
        '<Data Name="LogonType">3</Data>'
        f'<Data Name="Pad">{pad}</Data>'
        "</EventData></Event>\n")


def _write_xml(body, suffix=".xml"):
    fh = tempfile.NamedTemporaryFile("w", suffix=suffix, delete=False)
    fh.write(body)
    fh.close()
    return fh.name


def _doc(n, pad=""):
    return "<Events>\n" + "".join(_event(i, pad) for i in range(n)) + "</Events>\n"


class StreamSecurityXmlTests(unittest.TestCase):
    def test_batches_bounded_and_content_matches_wrapper(self):
        path = _write_xml(_doc(2500))
        try:
            batches = []
            count, skipped = ingm.stream_security_xml(
                path, since_ts=0, emit=batches.append, batch_size=1000)
            self.assertEqual(count, 2500)
            self.assertEqual(skipped, 0)
            self.assertEqual([len(b) for b in batches], [1000, 1000, 500])
            streamed = [e for b in batches for e in b]
            wrapped, w_skipped = ingm.parse_security_xml(path, since_ts=0)
            self.assertEqual(w_skipped, 0)
            self.assertEqual(streamed, wrapped)  # same tuples, same order
            detail = json.loads(streamed[0][5])
            self.assertEqual(detail["fields"]["TargetUserName"], "user0")
            self.assertIn("Failed logon", detail["summary"])
        finally:
            os.unlink(path)

    def test_small_batch_size_respected(self):
        path = _write_xml(_doc(5))
        try:
            sizes = []
            count, _s = ingm.stream_security_xml(
                path, emit=lambda b: sizes.append(len(b)), batch_size=2)
            self.assertEqual(count, 5)
            self.assertEqual(sizes, [2, 2, 1])
        finally:
            os.unlink(path)

    def test_since_ts_filter_and_skipped_count(self):
        bad = ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
               "<System><TimeCreated "
               'SystemTime="2026-10-03T14:00:00Z"/></System></Event>\n')
        path = _write_xml("<Events>\n" + _event(0) + bad + _event(61)
                          + "</Events>\n")
        try:
            wrapped, w_skipped = ingm.parse_security_xml(path, since_ts=0)
            self.assertEqual(len(wrapped), 2)
            self.assertEqual(w_skipped, 1)  # no EventID -> unparsable
            max_ts = max(e[0] for e in wrapped)
            count, s_skipped = ingm.stream_security_xml(
                path, since_ts=max_ts, emit=lambda b: None)
            self.assertEqual(count, 0)  # nothing newer; not "skipped"
            self.assertEqual(s_skipped, 1)
        finally:
            os.unlink(path)

    def test_entity_file_emits_nothing(self):
        lol = ('<?xml version="1.0"?><!DOCTYPE Events [<!ENTITY x "y">]>'
               "<Events>" + _event(0) + "</Events>")
        path = _write_xml(lol)
        try:
            calls = []
            count, skipped = ingm.stream_security_xml(
                path, emit=calls.append)
            self.assertEqual((count, skipped), (0, 1))
            self.assertEqual(calls, [])
        finally:
            os.unlink(path)

    def test_bad_xml_no_emits_and_wrapper_shape(self):
        path = _write_xml("<Events><broken")
        try:
            calls = []
            count, skipped = ingm.stream_security_xml(
                path, emit=calls.append)
            self.assertEqual((count, skipped), (0, 1))
            self.assertEqual(calls, [])
            events, w_skipped = ingm.parse_security_xml(path)
            self.assertEqual(events, [])
            self.assertEqual(w_skipped, 1)
        finally:
            os.unlink(path)

    def test_valid_prefix_then_corrupt_tail_keeps_prefix(self):
        body = "<Events>\n" + _event(0) + _event(1) + "<Event><broken"
        path = _write_xml(body)
        try:
            got = []
            count, skipped = ingm.stream_security_xml(
                path, emit=got.extend)
            self.assertEqual(count, 2)
            self.assertEqual(skipped, 1)
            self.assertEqual(len(got), 2)
            # The wrapper keeps its all-or-nothing shape on the same file.
            events, w_skipped = ingm.parse_security_xml(path)
            self.assertEqual(events, [])
            self.assertEqual(w_skipped, 1)
        finally:
            os.unlink(path)

    def test_streaming_memory_bounded(self):
        # 20,000 events / ~11 MB on disk: the old DOM+list code peaked
        # at 71.1 MB traced; streaming through a discarding emit must
        # stay far under that (batch + empty element shells only).
        path = _write_xml(_doc(20000, pad="x" * 200))
        try:
            tracemalloc.start()
            try:
                count, skipped = ingm.stream_security_xml(
                    path, since_ts=0, emit=lambda b: None)
                _cur, peak = tracemalloc.get_traced_memory()
            finally:
                tracemalloc.stop()
            self.assertEqual(count, 20000)
            self.assertEqual(skipped, 0)
            self.assertLess(peak, 25 * 1024 * 1024,
                            f"streaming peak {peak} bytes is not bounded")
        finally:
            os.unlink(path)


class RunIngestXmlStreamTests(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_watch = ingm.watch_dir

    def tearDown(self):
        ingm.watch_dir = self._old_watch
        super().tearDown()

    def test_run_ingest_stores_xml_events_and_skips_unchanged(self):
        with scratch_dir() as d:
            with open(os.path.join(d, "sec.xml"), "w",
                      encoding="utf-8") as fh:
                fh.write(_doc(2500))
            ingm.watch_dir = lambda: d  # noqa: E731
            s1 = ingm.run_ingest()
            self.assertTrue(s1["enabled"])
            self.assertEqual(s1["events"], 2500)
            rows = dbm.query("SELECT COUNT(*) FROM host_events"
                             " WHERE source='eventlog'")
            self.assertEqual(rows[0][0], 2500)
            s2 = ingm.run_ingest()
            self.assertEqual(s2["events"], 0)  # unchanged export skipped


if __name__ == "__main__":
    unittest.main()
