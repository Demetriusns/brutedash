"""Regression tests for robustness R5 (council review 2026-10-18):
a corrupt or truncated .gz rotated sibling must not crash
detect_brute_force. The sibling-read block used to catch only OSError;
a truncated gzip raises EOFError and a corrupt deflate stream raises
zlib.error, and both escaped -- killing the whole detection pass,
including the healthy primary log's findings (app.py POST / then 500s).
"""

import gzip
import os
import tempfile
import unittest

from detector import detect_brute_force


def _fail(ip, n):
    return [("Oct  2 20:01:01 host sshd[100]: Failed password for root"
             f" from {ip} port 22 ssh2")] * n


def _gz_bytes(lines):
    return gzip.compress(("\n".join(lines) + "\n").encode())


class TestCorruptGzSibling(unittest.TestCase):
    def _run(self, primary_lines, siblings):
        """siblings: {name: bytes}. Returns detect_brute_force results."""
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "auth.log"), "w") as f:
                f.write("\n".join(primary_lines) + "\n")
            for name, blob in siblings.items():
                with open(os.path.join(d, name), "wb") as f:
                    f.write(blob)
            return detect_brute_force(os.path.join(d, "auth.log"))

    def test_truncated_gz_sibling_returns_primary_findings(self):
        raw = _gz_bytes(_fail("203.0.113.7", 5))
        out = self._run(_fail("203.0.113.7", 5),
                        {"auth.log.1.gz": raw[:len(raw) // 2]})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "203.0.113.7")
        self.assertGreaterEqual(out[0]["count"], 5)

    def test_garbage_deflate_gz_sibling_returns_primary_findings(self):
        # Valid gzip header, garbage deflate payload -> zlib.error on read.
        bad = (b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\x03"
               + b"\xff" * 8 + b"\x00" * 8)
        out = self._run(_fail("198.51.100.9", 4),
                        {"auth.log.1.gz": bad})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "198.51.100.9")
        self.assertEqual(out[0]["count"], 4)

    def test_corrupt_gz_does_not_stop_later_healthy_sibling(self):
        # Siblings merge oldest first: auth.log.2.gz is read before
        # auth.log.1, so a dead .2 must not prevent .1 from merging.
        raw = _gz_bytes(_fail("203.0.113.7", 5))
        out = self._run(
            _fail("203.0.113.7", 2),
            {"auth.log.2.gz": raw[:len(raw) // 2],
             "auth.log.1": "\n".join(_fail("203.0.113.7", 6)).encode()
             + b"\n"})
        self.assertEqual(len(out), 1)
        self.assertGreaterEqual(out[0]["count"], 8)

    def test_partial_lines_before_corruption_are_kept(self):
        # A large sibling truncated halfway: the complete lines the
        # decompressor emitted before EOF must stay counted.
        raw = _gz_bytes(_fail("203.0.113.7", 2000))
        out = self._run(_fail("203.0.113.7", 5),
                        {"auth.log.1.gz": raw[:len(raw) // 2]})
        self.assertEqual(len(out), 1)
        self.assertGreater(out[0]["count"], 5)
        self.assertLess(out[0]["count"], 2005)

    def test_valid_gz_sibling_still_merges(self):
        out = self._run(_fail("203.0.113.7", 5),
                        {"auth.log.1.gz": _gz_bytes(_fail("203.0.113.7", 7))})
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 12)
        self.assertEqual(out[0]["severity"], "High")

    def test_missing_primary_still_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):
                detect_brute_force(os.path.join(d, "auth.log"))


if __name__ == "__main__":
    unittest.main()
