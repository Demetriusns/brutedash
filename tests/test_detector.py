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


if __name__ == "__main__":
    unittest.main()
