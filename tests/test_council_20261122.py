"""Tests for the council review 2026-11-22 batch (ARTEX hardening):
robustness H1 (enumeration scan is linear, not O(n^2)), H2 (the byte
cap cannot starve the primary log), M1 (type-wrong key state cannot
crash the pass), M2 (an empty sibling is not key history), M4
(concurrent key-state saves are serialised, unique tmp), security
S6 (the unauthenticated demo scan persists no key state) and S7
(key-state file is 0600).

Run: python -m unittest discover -s tests -v
"""
import gzip
import json
import os
import stat
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import detector
from detector import detect_cadence, detect_key_events

IP = "203.0.113.7"
BASE = datetime(2026, 10, 2, 19, 0, 0)
FP_OLD = "AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyFingerprint0001"
FP_NEW = "AAAAC3NzaC1lZDI1NTE5AAAAINewKeyFingerprint0002"


def _ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def _fail(ip, user, dt, pid=100):
    return (f"{_ts(dt)} host sshd[{pid}]: Failed password for {user}"
            f" from {ip} port 51234 ssh2")


def _key(ip, user, dt, fp=None, host="host"):
    line = (f"{_ts(dt)} {host} sshd[100]: Accepted publickey for {user}"
            f" from {ip} port 51234 ssh2")
    if fp:
        line += f": ED25519 SHA256:{fp}"
    return line


def _write_dir(files):
    d = tempfile.mkdtemp()
    for name, lines in files.items():
        with open(os.path.join(d, name), "w") as f:
            f.write("\n".join(lines) + "\n")
    return d


class TestH1EnumerationLinear(unittest.TestCase):
    def test_best_window_after_first_window_expires(self):
        early = [f"user{i}" for i in range(7)]
        late = [f"late{i}" for i in range(9)]
        lines = [_fail(IP, u, BASE + timedelta(seconds=10 * i),
                       pid=100 + i) for i, u in enumerate(early)]
        start = BASE + timedelta(seconds=700)
        lines += [_fail(IP, u, start + timedelta(seconds=10 * i),
                        pid=200 + i) for i, u in enumerate(late)]
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as tmp:
            tmp.write("\n".join(lines) + "\n")
            path = tmp.name
        try:
            out = detect_cadence(path)
        finally:
            os.unlink(path)
        enum = [f for f in out if f["kind"] == "username_enumeration"]
        self.assertEqual(len(enum), 1)
        self.assertEqual(enum[0]["count"], 9)
        self.assertIn("late0", enum[0]["detail"])

    def test_large_single_attacker_log_is_fast(self):
        # 20,000 failures / 50 usernames / one IP / 500s window took
        # ~11.75s with the O(n^2) set-rebuild scan (seat repro).
        lines = []
        for i in range(20000):
            dt = BASE + timedelta(seconds=i % 500)
            lines.append(_fail(IP, f"user{i % 50}", dt, pid=100 + i))
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as tmp:
            tmp.write("\n".join(lines) + "\n")
            path = tmp.name
        try:
            t0 = time.monotonic()
            out = detect_cadence(path)
            elapsed = time.monotonic() - t0
        finally:
            os.unlink(path)
        self.assertLess(elapsed, 4.0)
        self.assertIn("username_enumeration",
                      [f["kind"] for f in out])


class TestH2PrimaryNotStarved(unittest.TestCase):
    def test_gz_sibling_cannot_starve_primary(self):
        # A .gz sibling is small on disk but inflates past a shrunken
        # cap; the primary's burst must still be seen.
        import shutil
        d = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, d, True)
        filler = [_fail("198.51.100.9", "root",
                        BASE + timedelta(seconds=i % 400),
                        pid=100 + i) for i in range(3000)]
        with gzip.open(os.path.join(d, "auth.log.1.gz"), "wt") as f:
            f.write("\n".join(filler) + "\n")
        burst = [_fail(IP, "root", BASE + timedelta(seconds=5 * i),
                       pid=300 + i) for i in range(12)]
        with open(os.path.join(d, "auth.log"), "w") as f:
            f.write("\n".join(burst) + "\n")
        old = detector.MAX_TOTAL_BYTES
        detector.MAX_TOTAL_BYTES = 50_000
        try:
            out = detect_cadence(os.path.join(d, "auth.log"))
        finally:
            detector.MAX_TOTAL_BYTES = old
        self.assertIn("burst_cadence", [f["kind"] for f in out])


class TestM1TypeWrongState(unittest.TestCase):
    def test_bad_value_types_do_not_crash(self):
        d = _write_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [_key(IP, "alice", BASE + timedelta(days=1),
                              FP_OLD)],
        })
        state = os.path.join(d, "state.json")
        with open(state, "w") as f:
            json.dump({"keys": {
                "host|alice|bad1": 12345,
                "host|alice|bad2": {"first_seen": "not-a-number"},
                "host|alice|bad3": {"first_seen": True},
            }}, f)
        out = detect_key_events(os.path.join(d, "auth.log"),
                                state_path=state)
        self.assertEqual(out["findings"], [])
        with open(state) as f:
            saved = json.load(f)
        self.assertNotIn("host|alice|bad1", saved["keys"])
        self.assertNotIn("host|alice|bad2", saved["keys"])


class TestM2EmptySiblingNotHistory(unittest.TestCase):
    def test_zero_byte_sibling_is_baseline(self):
        d = _write_dir({
            "auth.log.1": [],
            "auth.log": [_key(IP, "alice", BASE, FP_OLD)],
        })
        # _write_dir writes "\n" for an empty list; make it truly 0-byte
        with open(os.path.join(d, "auth.log.1"), "w"):
            pass
        out = detect_key_events(os.path.join(d, "auth.log"))
        self.assertEqual(out["findings"], [])
        self.assertIn("baseline", out["coverage"][0]["note"])


class TestM4ConcurrentSaves(unittest.TestCase):
    def test_threads_all_keys_land_and_file_valid(self):
        import shutil
        root = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, root, True)
        state = os.path.join(root, "state.json")
        errors = []

        def worker(n):
            try:
                d = os.path.join(root, f"log{n}")
                os.mkdir(d)
                log = os.path.join(d, "auth.log")
                with open(log, "w") as f:
                    f.write(_key(IP, f"user{n}", BASE,
                                 f"FPxxxx{n:04d}") + "\n")
                detect_key_events(log, state_path=state)
            except Exception as e:  # noqa: BLE001 - collected below
                errors.append(e)

        threads = [threading.Thread(target=worker, args=(n,))
                   for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(errors, [])
        with open(state) as f:
            saved = json.load(f)
        self.assertEqual(len(saved["keys"]), 8)
        if os.name == "posix":
            mode = stat.S_IMODE(os.stat(state).st_mode)
            self.assertEqual(mode, 0o600)


class TestS6DemoPersistsNoState(unittest.TestCase):
    def test_app_py_does_not_pass_a_state_path(self):
        app_src = os.path.join(os.path.dirname(__file__), "..",
                               "app.py")
        with open(app_src) as f:
            src = f.read()
        self.assertNotIn("KEY_STATE_PATH", src)
        self.assertNotIn("state_path=", src.split("detect_key_events")[1]
                         .split(")")[0])


if __name__ == "__main__":
    unittest.main()
