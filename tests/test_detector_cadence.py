"""Tests for detector.detect_cadence (council review 2026-11-17, ARTEX
batch B1): windowed cadence detection -- burst rate, interval
regularity, username enumeration, duplicate attempts, and a success
within minutes of a burst at Critical.

The count-based pass (detect_brute_force) is untouched by these; every
case here is about TIMING. Fixtures use distinct timestamps per line
(real sshd logs never repeat a line byte-for-byte across a campaign).

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import detect_cadence

IP = "203.0.113.7"
BASE = datetime(2026, 10, 2, 19, 0, 0)


def _ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def _fail(ip, user, dt, pid=100):
    return (f"{_ts(dt)} host sshd[{pid}]: Failed password for {user}"
            f" from {ip} port 51234 ssh2")


def _accept(ip, user, dt):
    return (f"{_ts(dt)} host sshd[999]: Accepted password for {user}"
            f" from {ip} port 51235 ssh2")


def _run(lines):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    try:
        return detect_cadence(tmp.name)
    finally:
        os.unlink(tmp.name)


def _run_dir(files):
    """files: {name: [lines]} in one temp dir; analyse auth.log."""
    with tempfile.TemporaryDirectory() as d:
        for name, lines in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write("\n".join(lines) + "\n")
        return detect_cadence(os.path.join(d, "auth.log"))


def _burst(n=12, gap_s=5, user="root", ip=IP, start=BASE):
    return [_fail(ip, user, start + timedelta(seconds=gap_s * i),
                  pid=100 + i) for i in range(n)]


class TestBurstCadence(unittest.TestCase):
    def test_burst_fires_high(self):
        out = _run(_burst())
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "burst_cadence")
        self.assertEqual(out[0]["severity"], "High")
        self.assertEqual(out[0]["count"], 12)

    def test_burst_alone_never_critical(self):
        # Task edge case: a lone burst with no success must not reach
        # top severity.
        out = _run(_burst(n=30, gap_s=2))
        self.assertTrue(out)
        self.assertTrue(all(f["severity"] != "Critical" for f in out))

    def test_success_after_burst_is_critical(self):
        lines = _burst() + [_accept(IP, "root",
                                    BASE + timedelta(seconds=55 + 120))]
        out = _run(lines)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0]["kind"], "login_after_burst")
        self.assertEqual(out[0]["severity"], "Critical")

    def test_success_long_after_burst_not_critical(self):
        lines = _burst() + [_accept(IP, "root",
                                    BASE + timedelta(seconds=55 + 1200))]
        out = _run(lines)
        self.assertEqual([f["kind"] for f in out], ["burst_cadence"])

    def test_human_cadence_quiet(self):
        # 12 failures a minute apart + a success: the count-based
        # pass's Critical, but no cadence pattern at all.
        lines = [_fail(IP, "root", BASE + timedelta(minutes=i),
                       pid=100 + i) for i in range(12)]
        lines.append(_accept(IP, "root", BASE + timedelta(minutes=20)))
        self.assertEqual(_run(lines), [])

    def test_regular_spacing_annotated(self):
        out = _run(_burst(n=12, gap_s=10))
        self.assertIn("machine-regular", out[0]["detail"])

    def test_jittered_burst_not_annotated_regular(self):
        gaps = [1, 2, 3, 5, 8, 13, 21, 34, 1, 2, 4]
        lines, t = [], BASE
        for i, g in enumerate(gaps + [0]):
            lines.append(_fail(IP, "root", t, pid=100 + i))
            t += timedelta(seconds=g)
        out = _run(lines)
        self.assertEqual([f["kind"] for f in out], ["burst_cadence"])
        self.assertNotIn("machine-regular", out[0]["detail"])

    def test_burst_merges_across_rotation(self):
        first = [_fail(IP, "root", BASE + timedelta(seconds=5 * i),
                       pid=100 + i) for i in range(6)]
        second = [_fail(IP, "root", BASE + timedelta(seconds=30 + 5 * i),
                        pid=200 + i) for i in range(6)]
        out = _run_dir({"auth.log.1": first, "auth.log": second})
        self.assertEqual([f["kind"] for f in out], ["burst_cadence"])
        self.assertEqual(out[0]["count"], 12)

    def test_year_wrap_orders_events(self):
        # December fails in the rotated log, January success in the
        # primary: syslog has no year, so without wrap repair the
        # success would sort BEFORE the burst and never correlate.
        dec = datetime(2026, 12, 31, 23, 59, 0)
        first = [_fail(IP, "root", dec + timedelta(seconds=5 * i),
                       pid=100 + i) for i in range(12)]
        jan = datetime(2027, 1, 1, 0, 1, 30)
        out = _run_dir({"auth.log.1": first,
                        "auth.log": [_accept(IP, "root", jan)]})
        self.assertEqual([f["kind"] for f in out], ["login_after_burst"])

    def test_iso_timestamps_supported(self):
        lines = []
        for i in range(12):
            dt = BASE + timedelta(seconds=5 * i)
            lines.append(
                f"{dt.strftime('%Y-%m-%dT%H:%M:%S')} host sshd[{100+i}]:"
                f" Failed password for root from {IP} port 51234 ssh2")
        out = _run(lines)
        self.assertEqual([f["kind"] for f in out], ["burst_cadence"])


class TestEnumeration(unittest.TestCase):
    def test_enumeration_fires(self):
        users = ["root", "admin", "ubuntu", "pi", "oracle", "postgres",
                 "git", "deploy", "test"]
        lines = [_fail(IP, u, BASE + timedelta(seconds=30 * i),
                       pid=100 + i) for i, u in enumerate(users)]
        out = _run(lines)
        self.assertEqual([f["kind"] for f in out],
                         ["username_enumeration"])
        self.assertEqual(out[0]["count"], 9)
        self.assertEqual(out[0]["severity"], "High")

    def test_few_users_quiet(self):
        users = ["root", "admin", "ubuntu", "pi", "oracle", "postgres",
                 "git"]
        lines = [_fail(IP, u, BASE + timedelta(seconds=30 * i),
                       pid=100 + i) for i, u in enumerate(users)]
        self.assertEqual(_run(lines), [])


class TestDuplicateAttempts(unittest.TestCase):
    def test_duplicates_fire(self):
        lines = [_fail(IP, "root", BASE, pid=100 + i) for i in range(5)]
        out = _run(lines)
        self.assertEqual([f["kind"] for f in out], ["duplicate_attempts"])
        self.assertEqual(out[0]["severity"], "Medium")
        self.assertEqual(out[0]["count"], 5)

    def test_few_duplicates_quiet(self):
        lines = [_fail(IP, "root", BASE, pid=100 + i) for i in range(3)]
        self.assertEqual(_run(lines), [])

    def test_same_second_different_users_not_duplicates(self):
        users = ["root", "admin", "ubuntu", "pi", "oracle"]
        lines = [_fail(IP, u, BASE, pid=100 + i)
                 for i, u in enumerate(users)]
        kinds = [f["kind"] for f in _run(lines)]
        self.assertNotIn("duplicate_attempts", kinds)


if __name__ == "__main__":
    unittest.main()
