"""Regression tests for robustness M4 (council review, 2026-11-01):
detector reads sources in bounded chunks and caps each line at
MAX_LINE_BYTES BEFORE parsing, so a single newline-free line can no
longer defeat the MAX_TOTAL_BYTES cap by being materialised whole.

On pre-fix code these fail behaviourally: an event placed beyond the
line cap on one huge line was counted (the whole line was read and
parsed), and _iter_capped_lines / MAX_LINE_BYTES did not exist.

Run: python -m unittest discover -s tests -v
"""
import gzip
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import detector
from detector import detect_brute_force

IP = "203.0.113.7"
FAIL = (f"Oct  2 19:00:01 host sshd[100]: Failed password"
        f" for root from {IP} port 51234 ssh2")
PAD = b"x" * 4096


def _write(data: bytes, suffix=".log"):
    tmp = tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False)
    tmp.write(data)
    tmp.close()
    return tmp.name


class TestLineCap(unittest.TestCase):
    def setUp(self):
        self._orig = (detector.MAX_LINE_BYTES, detector._READ_CHUNK_BYTES,
                      detector.MAX_TOTAL_BYTES)
        # Small caps/chunks so the tests exercise the machinery fast.
        detector.MAX_LINE_BYTES = 1024
        detector._READ_CHUNK_BYTES = 256

    def tearDown(self):
        (detector.MAX_LINE_BYTES, detector._READ_CHUNK_BYTES,
         detector.MAX_TOTAL_BYTES) = self._orig

    def _run_bytes(self, data: bytes):
        path = _write(data)
        try:
            return detect_brute_force(path, threshold=3)
        finally:
            os.unlink(path)

    def test_event_beyond_line_cap_not_counted(self):
        # One huge single line: 3 failures' worth of text exists only
        # AFTER the 1 KB kept prefix, repeated on 3 giant lines. The
        # capped reader must never parse it.
        line = PAD + FAIL.encode()
        out = self._run_bytes((line + b"\n") * 3)
        self.assertEqual(out, [])

    def test_event_within_line_cap_prefix_counted(self):
        # Failure text sits inside the kept prefix of an over-long
        # line; the discarded tail must not lose the detection.
        line = FAIL.encode() + PAD
        out = self._run_bytes((line + b"\n") * 3)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], IP)
        self.assertEqual(out[0]["count"], 3)

    def test_line_spanning_many_chunks_parses_whole(self):
        # 900-byte line (under the 1 KB cap, ~4 chunks at 256 B): the
        # IP near the END must still be seen -- chunk reassembly works.
        line = (b"Oct  2 19:00:01 host sshd[100]: Failed password for "
                b"root " + b" " * 780 + f"from {IP} port 51234 ssh2"
                .encode())
        self.assertLess(len(line), detector.MAX_LINE_BYTES)
        self.assertGreater(len(line), detector._READ_CHUNK_BYTES * 3)
        out = self._run_bytes((line + b"\n") * 3)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 3)

    def test_final_line_without_newline_counted(self):
        data = ("\n".join([FAIL] * 3)).encode()  # no trailing newline
        out = self._run_bytes(data)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 3)

    def test_total_byte_cap_counts_discarded_bytes(self):
        # Each giant line is ~4 KB raw but only 1 KB kept. With a 3 KB
        # total cap, raw accounting stops during line 1, so the valid
        # events on later lines are never reached. (Kept-only
        # accounting would have read all 3 event lines.)
        detector.MAX_TOTAL_BYTES = 3000
        giant = PAD + b"\n"
        events = (FAIL + "\n").encode() * 3
        out = self._run_bytes(giant + events)
        self.assertEqual(out, [])

    def test_gz_sibling_huge_line_truncated_same_way(self):
        # A small .gz that inflates to giant single lines: the event
        # beyond the cap in the sibling must not merge into counts,
        # while the primary's own 3 failures still report.
        with tempfile.TemporaryDirectory() as d:
            primary = os.path.join(d, "auth.log")
            with open(primary, "wb") as f:
                f.write((FAIL + "\n").encode() * 3)
            line = PAD + FAIL.encode()
            with gzip.open(os.path.join(d, "auth.log.1.gz"), "wb") as f:
                f.write((line + b"\n") * 5)
            out = detect_brute_force(primary, threshold=3)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 3)  # not 3 + 5

    def test_normal_multiline_counting_unchanged(self):
        out = self._run_bytes((FAIL + "\n").encode() * 11)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "High")
        self.assertEqual(out[0]["count"], 11)


if __name__ == "__main__":
    unittest.main()
