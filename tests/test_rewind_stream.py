"""Rewind export streaming — council review 2026-11-01, robustness H1.

Shipped 2026-11-02 (daily build): export_window() built the whole
export in RAM — a bytearray up to EXPORT_MAX_BYTES (512 MB) plus the
bytes(out) copy — and the dashboard route held that blob in an
in-memory Response. On the small-box target one export could peak
near 1 GB and OOM-kill the process that also runs capture/detection.

export_window_to_file() streams one record at a time to a caller-
owned binary file object, and /api/rewind/export now streams to a
temp file served in 64 KB chunks, unlinked in the stream's finally
block (call_on_close empirically does not fire under the test
client, so cleanup does not rely on it).

Run: python -m unittest discover -s tests -v
"""
import glob
import io
import os
import shutil
import struct
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import rewind as rwm

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None


class _RewindCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rewind-stream-")
        self._old_enabled = rwm._ENABLED
        self._old_dir = rwm.rewind_dir
        self._old_diskok = rwm._disk_ok
        self._old_cap = rwm.EXPORT_MAX_BYTES
        rwm._ENABLED = True
        rwm.rewind_dir = lambda: Path(self.tmp)
        rwm._disk_ok = lambda _d: True

    def tearDown(self):
        rwm._reset_for_tests()
        rwm._ENABLED = self._old_enabled
        rwm.rewind_dir = self._old_dir
        rwm._disk_ok = self._old_diskok
        rwm.EXPORT_MAX_BYTES = self._old_cap
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _seed(self):
        base = time.time()
        rwm.record_packet(b"pkt-a", base - 50)
        rwm.record_packet(b"pkt-b", base - 40)
        rwm.record_packet(b"outside", base + 5000)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        return base


class ExportWindowToFileTests(_RewindCase):
    def test_streamed_bytes_identical_to_in_memory_export(self):
        base = self._seed()
        blob, count = rwm.export_window(base - 100, base + 100)
        buf = io.BytesIO()
        fcount, written = rwm.export_window_to_file(base - 100,
                                                    base + 100, buf)
        self.assertEqual(fcount, count)
        self.assertEqual(fcount, 2)
        self.assertEqual(buf.getvalue(), blob)
        self.assertEqual(written, len(blob))

    def test_does_not_close_caller_file(self):
        base = self._seed()
        buf = io.BytesIO()
        rwm.export_window_to_file(base - 100, base + 100, buf)
        self.assertFalse(buf.closed)

    def test_empty_window_is_header_only(self):
        base = self._seed()
        buf = io.BytesIO()
        count, written = rwm.export_window_to_file(base + 1000,
                                                   base + 2000, buf)
        self.assertEqual(count, 0)
        self.assertEqual(written, 24)
        self.assertEqual(struct.unpack("<I", buf.getvalue()[:4])[0],
                         0xA1B2C3D4)

    def test_cap_honoured_by_streaming_path(self):
        base = time.time()
        for i in range(3):
            rwm.record_packet(b"x" * 100, base - 50 + i)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        # Room for the header + exactly one 100-byte record.
        rwm.EXPORT_MAX_BYTES = 24 + 16 + 100
        buf = io.BytesIO()
        count, written = rwm.export_window_to_file(base - 100,
                                                   base + 100, buf)
        self.assertEqual(count, 1)
        self.assertEqual(written, 24 + 16 + 100)
        self.assertEqual(len(buf.getvalue()), written)

    def test_writes_to_a_real_file(self):
        base = self._seed()
        path = os.path.join(self.tmp, "out.pcap")
        with open(path, "wb") as f:
            count, written = rwm.export_window_to_file(
                base - 100, base + 100, f)
        self.assertEqual(count, 2)
        self.assertEqual(os.path.getsize(path), written)


@unittest.skipIf(dashm is None, "Flask not installed")
class RewindExportRouteStreamsTests(_RewindCase):
    def test_route_serves_streamed_file_and_cleans_up(self):
        base = self._seed()
        pattern = os.path.join(tempfile.gettempdir(), "*.pcap")
        before = set(glob.glob(pattern))
        client = dashm.app.test_client()
        with client.get("/api/rewind/export?hours=1") as r:
            self.assertEqual(r.status_code, 200)
            self.assertEqual(r.headers.get("X-Packets"), "2")
            cd = r.headers.get("Content-Disposition", "")
            self.assertIn("rewind-last-hours.pcap", cd)
            self.assertEqual(struct.unpack("<I", r.data[:4])[0],
                             0xA1B2C3D4)
            self.assertIn(b"pkt-a", r.data)
        # Response closed -> call_on_close unlinked the temp file.
        self.assertEqual(set(glob.glob(pattern)) - before, set())


if __name__ == "__main__":
    unittest.main()
