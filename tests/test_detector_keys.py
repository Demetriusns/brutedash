"""Tests for detector.detect_key_events (council review 2026-11-17,
ARTEX batch B2): first-seen SSH key fingerprints, gated on per-host
sshd logging-level coverage.

The ADAPT gate is the point of half these tests: fingerprints only
exist at LogLevel VERBOSE, so a host whose key logins carry no
fingerprints must be reported DARK in the coverage report -- never
silently treated as "no new keys".

Run: python -m unittest discover -s tests -v
"""
import json
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from detector import detect_key_events

IP = "203.0.113.7"
BASE = datetime(2026, 10, 2, 19, 0, 0)
FP_OLD = "AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyFingerprint0001"
FP_NEW = "AAAAC3NzaC1lZDI1NTE5AAAAINewKeyFingerprint0002"


def _ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def _key(ip, user, dt, fp=None, host="host"):
    line = (f"{_ts(dt)} {host} sshd[100]: Accepted publickey for {user}"
            f" from {ip} port 51234 ssh2")
    if fp:
        line += f": ED25519 SHA256:{fp}"
    return line


def _pw_accept(ip, user, dt, host="host"):
    return (f"{_ts(dt)} {host} sshd[999]: Accepted password for {user}"
            f" from {ip} port 51235 ssh2")


def _run_dir(files, state_path=None):
    with tempfile.TemporaryDirectory() as d:
        for name, lines in files.items():
            with open(os.path.join(d, name), "w") as f:
                f.write("\n".join(lines) + "\n")
        return detect_key_events(os.path.join(d, "auth.log"),
                                 state_path=state_path)


def _run(lines, state_path=None):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    try:
        return detect_key_events(tmp.name, state_path=state_path)
    finally:
        os.unlink(tmp.name)


class TestFirstSeenKey(unittest.TestCase):
    def test_first_seen_fires_high(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [_key(IP, "alice", BASE + timedelta(days=1),
                              FP_NEW)],
        })
        self.assertEqual(len(out["findings"]), 1)
        f = out["findings"][0]
        self.assertEqual(f["kind"], "first_seen_key")
        self.assertEqual(f["severity"], "High")
        self.assertEqual(f["ip"], IP)

    def test_known_key_quiet(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [_key(IP, "alice", BASE + timedelta(days=1),
                              FP_OLD)],
        })
        self.assertEqual(out["findings"], [])

    def test_first_seen_after_password_login_critical(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [
                _pw_accept(IP, "alice", BASE + timedelta(days=1)),
                _key(IP, "alice", BASE + timedelta(days=1, minutes=10),
                     FP_NEW),
            ],
        })
        self.assertEqual(len(out["findings"]), 1)
        self.assertEqual(out["findings"][0]["severity"], "Critical")
        self.assertIn("plant-a-key", out["findings"][0]["detail"])

    def test_password_login_for_other_user_no_escalation(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [
                _pw_accept(IP, "bob", BASE + timedelta(days=1)),
                _key(IP, "alice", BASE + timedelta(days=1, minutes=10),
                     FP_NEW),
            ],
        })
        self.assertEqual(out["findings"][0]["severity"], "High")

    def test_root_first_seen_noted_privileged(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [_key(IP, "root", BASE + timedelta(days=1),
                              FP_NEW)],
        })
        self.assertIn("privileged account",
                      out["findings"][0]["detail"])


class TestBaselineAndState(unittest.TestCase):
    def test_no_history_first_run_is_baseline_silent(self):
        # One lone log, no siblings, no state: every key is "first
        # seen" trivially -- the pass must record a baseline and fire
        # nothing rather than calling every existing key new.
        out = _run([_key(IP, "alice", BASE, FP_OLD)])
        self.assertEqual(out["findings"], [])
        self.assertIn("baseline", out["coverage"][0]["note"])

    def test_state_roundtrip(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.json")
            log = os.path.join(d, "auth.log")
            with open(log, "w") as f:
                f.write(_key(IP, "alice", BASE, FP_OLD) + "\n")
            out1 = detect_key_events(log, state_path=state)
            self.assertEqual(out1["findings"], [])  # baseline run
            self.assertTrue(os.path.exists(state))
            out2 = detect_key_events(log, state_path=state)
            self.assertEqual(out2["findings"], [])  # known key
            with open(log, "w") as f:
                f.write(_key(IP, "alice", BASE + timedelta(days=2),
                             FP_NEW) + "\n")
            out3 = detect_key_events(log, state_path=state)
            self.assertEqual(len(out3["findings"]), 1)
            self.assertEqual(out3["findings"][0]["kind"],
                             "first_seen_key")

    def test_corrupt_state_falls_back_to_sibling_history(self):
        with tempfile.TemporaryDirectory() as d:
            state = os.path.join(d, "state.json")
            with open(state, "w") as f:
                f.write("{not json")
            out = _run_dir({
                "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
                "auth.log": [_key(IP, "alice",
                                  BASE + timedelta(days=1), FP_OLD)],
            }, state_path=state)
            self.assertEqual(out["findings"], [])
            # ...and the state file is rewritten as valid JSON.
            with open(state) as f:
                self.assertIn("keys", json.load(f))


class TestCoverageGate(unittest.TestCase):
    def test_verbose_host_reported(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD)],
            "auth.log": [_key(IP, "alice", BASE + timedelta(days=1),
                              FP_OLD)],
        })
        cov = {c["host"]: c for c in out["coverage"]}
        self.assertEqual(cov["host"]["status"], "verbose")

    def test_dark_host_reported_and_no_key_findings(self):
        # Key logins happen but WITHOUT fingerprints (LogLevel below
        # VERBOSE): the rule cannot see keys here. It must say so in
        # the coverage report and must NOT invent findings.
        out = _run_dir({
            "auth.log.1": [_pw_accept(IP, "alice", BASE)],
            "auth.log": [_key(IP, "alice", BASE + timedelta(days=1))],
        })
        cov = {c["host"]: c for c in out["coverage"]}
        self.assertEqual(cov["host"]["status"], "dark")
        self.assertIn("CANNOT see new keys", cov["host"]["note"])
        self.assertEqual(out["findings"], [])

    def test_no_key_auth_reported(self):
        out = _run([_pw_accept(IP, "alice", BASE)])
        cov = {c["host"]: c for c in out["coverage"]}
        self.assertEqual(cov["host"]["status"], "no-key-auth")

    def test_mixed_hosts_reported_separately(self):
        out = _run_dir({
            "auth.log.1": [_key(IP, "alice", BASE, FP_OLD, host="srv1")],
            "auth.log": [
                _key(IP, "alice", BASE + timedelta(days=1), FP_OLD,
                     host="srv1"),
                _key(IP, "bob", BASE + timedelta(days=1), host="srv2"),
            ],
        })
        cov = {c["host"]: c["status"] for c in out["coverage"]}
        self.assertEqual(cov["srv1"], "verbose")
        self.assertEqual(cov["srv2"], "dark")


if __name__ == "__main__":
    unittest.main()
