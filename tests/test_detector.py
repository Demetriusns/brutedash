"""Tests for detector.detect_brute_force, including the Critical
login-after-bruteforce finding (session #15: the break-in itself must be
a first-class detection, not just "many failures").

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import detect_brute_force


def _log(lines):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    return tmp.name


def _fail(ip, n, user="root"):
    return [
        f"Oct  2 19:{i:02d}:01 host sshd[{100+i}]: Failed password"
        f" for {user} from {ip} port 51234 ssh2"
        for i in range(n)
    ]


def _accept(ip, user="admin"):
    return (f"Oct  2 20:01:01 host sshd[999]: Accepted password"
            f" for {user} from {ip} port 51235 ssh2")


class TestDetector(unittest.TestCase):
    def _run(self, lines, **kw):
        path = _log(lines)
        try:
            return detect_brute_force(path, **kw)
        finally:
            os.unlink(path)

    def test_many_failures_high(self):
        out = self._run(_fail("203.0.113.7", 11))
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["severity"], "High")
        self.assertEqual(out[0]["kind"], "brute_force")

    def test_few_failures_medium(self):
        out = self._run(_fail("203.0.113.7", 3))
        self.assertEqual(out[0]["severity"], "Medium")

    def test_below_threshold_silent(self):
        self.assertEqual(self._run(_fail("203.0.113.7", 2)), [])

    def test_login_after_bruteforce_is_critical(self):
        out = self._run(_fail("203.0.113.7", 12) + [_accept("203.0.113.7")])
        crit = [r for r in out if r["kind"] == "login_after_bruteforce"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["severity"], "Critical")
        self.assertEqual(crit[0]["ip"], "203.0.113.7")
        # worst-first: the Critical leads even though the High has the count
        self.assertEqual(out[0]["kind"], "login_after_bruteforce")

    def test_accepted_without_failures_no_finding(self):
        self.assertEqual(self._run([_accept("203.0.113.7")]), [])

    def test_accepted_key_without_failures_no_finding(self):
        line = ("Oct  2 20:01:01 host sshd[999]: Accepted publickey"
                " for admin from 203.0.113.7 port 51235 ssh2")
        self.assertEqual(self._run([line]), [])


class TestRotation(unittest.TestCase):
    """Rotation-aware scanning: a campaign split across a logrotate
    boundary must score as one campaign (hardening item, 2026-10-11)."""

    def _sibling(self, dirpath, name, lines, gz=False):
        path = os.path.join(dirpath, name)
        if gz:
            import gzip
            with gzip.open(path, "wt") as f:
                f.write("\n".join(lines) + "\n")
        else:
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
        return path

    def _run_dir(self, files, primary="auth.log", **kw):
        """files: {name: (lines, gz)} -> detect on dirpath/primary."""
        with tempfile.TemporaryDirectory() as d:
            for name, (lines, gz) in files.items():
                self._sibling(d, name, lines, gz=gz)
            return detect_brute_force(os.path.join(d, primary), **kw)

    def test_split_campaign_scores_as_one(self):
        # 7 fails in auth.log.1 + 5 fails in auth.log = 12 -> High.
        # Without rotation merging this reads as two silent fragments.
        out = self._run_dir({
            "auth.log.1": (_fail("203.0.113.7", 7), False),
            "auth.log": (_fail("203.0.113.7", 5), False),
        })
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 12)
        self.assertEqual(out[0]["severity"], "High")

    def test_critical_spans_rotation(self):
        # 11 fails in the rotated log, break-in in the current one.
        out = self._run_dir({
            "auth.log.1": (_fail("203.0.113.7", 11), False),
            "auth.log": ([_accept("203.0.113.7")], False),
        })
        crit = [r for r in out if r["kind"] == "login_after_bruteforce"]
        self.assertEqual(len(crit), 1)
        self.assertEqual(crit[0]["count"], 11)

    def test_gz_sibling_merges(self):
        out = self._run_dir({
            "auth.log.2.gz": (_fail("203.0.113.7", 6), True),
            "auth.log": (_fail("203.0.113.7", 6), False),
        })
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 12)

    def test_no_siblings_unchanged_behavior(self):
        out = self._run_dir({"auth.log": (_fail("203.0.113.7", 2), False)})
        self.assertEqual(out, [])

    def test_missing_primary_still_raises(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(FileNotFoundError):
                detect_brute_force(os.path.join(d, "auth.log"))

    def test_unreadable_sibling_skipped(self):
        # Simulate a sibling that errors on read (root bypasses chmod 0,
        # so force the OSError path by patching os.path.getsize).
        import detector
        with tempfile.TemporaryDirectory() as d:
            self._sibling(d, "auth.log", _fail("203.0.113.7", 4))
            self._sibling(d, "auth.log.1", _fail("203.0.113.7", 9))
            real_getsize = os.path.getsize

            def _boom(path):
                if path.endswith("auth.log.1"):
                    raise OSError("simulated read failure")
                return real_getsize(path)

            orig = detector.os.path.getsize
            detector.os.path.getsize = _boom
            try:
                out = detect_brute_force(os.path.join(d, "auth.log"))
            finally:
                detector.os.path.getsize = orig
            # only the primary's 4 count (the 9 are unreadable), Medium
            self.assertEqual(len(out), 1)
            self.assertEqual(out[0]["count"], 4)

    def test_high_suffix_beyond_cap_ignored(self):
        # auth.log.99 is beyond MAX_ROTATED_SIBLINGS: never read.
        out = self._run_dir({
            "auth.log.99": (_fail("203.0.113.7", 50), False),
            "auth.log": (_fail("203.0.113.7", 2), False),
        })
        self.assertEqual(out, [])

    def test_primary_never_skipped_by_byte_cap(self):
        # Council review (robustness, 2026-10-11): with siblings scanned
        # first, a cap-consuming sibling left the primary unread and a
        # live campaign in the primary scored silent. The primary is
        # scanned first now -- the byte cap applies to siblings only.
        import detector
        filler = (["Oct  2 19:01:01 host sshd[1]: Connection closed by"
                   " 203.0.113.9 port 1"] * 40)  # ~2.6KB, no "from " in them
        orig = detector.MAX_TOTAL_BYTES
        detector.MAX_TOTAL_BYTES = 1000
        try:
            out = self._run_dir({
                "auth.log.1": (filler, False),
                "auth.log": (_fail("203.0.113.7", 5), False),
            })
        finally:
            detector.MAX_TOTAL_BYTES = orig
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["ip"], "203.0.113.7")
        self.assertEqual(out[0]["count"], 5)

    def test_truncated_from_line_no_crash(self):
        # A wrapped/truncated line ending in "from " used to raise
        # IndexError out of detect_brute_force (council review, robustness,
        # 2026-10-11). It is skipped; real lines still count.
        out = self._run_dir({
            "auth.log": (
                ["Oct  2 19:01:01 host sshd[1]: Failed password"
                 " for root from "] + _fail("203.0.113.7", 3),
                False),
        })
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["count"], 3)


if __name__ == "__main__":
    unittest.main()
