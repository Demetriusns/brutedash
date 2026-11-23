"""Tests for the 2026-11-23 daily build: UX U11+U12+U10 plain-language
batch (council review 2026-11-22, staged for the daily-build queue).

U11: the SSH-key coverage notes ordered the owner to edit sshd_config
("Set 'LogLevel VERBOSE' in sshd_config") and the demo heading was the
technician phrase "SSH key visibility". Notes now explain in plain
words, keep the pinned warning "CANNOT see new keys", and name no
config file or directive. Heading asks a plain question.

U12: the demo results/history tables headed the count column "Failed
attempts", but count means distinct usernames for enumeration and 1
sighting for a first-seen key. Header is now "Count" and each results
row labels what was counted, per kind.

U10: the dashboard retention "Last prune" line printed raw DB table
names. It now maps them to the same plain labels as the policy rows.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

from detector import detect_key_events

IP = "203.0.113.7"
BASE = datetime(2026, 10, 2, 19, 0, 0)
FP = "AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyFingerprint0001"


def _ts(dt):
    return dt.strftime("%b %d %H:%M:%S")


def _key(ip, user, dt, fp=None, host="host"):
    line = (f"{_ts(dt)} {host} sshd[100]: Accepted publickey for {user}"
            f" from {ip} port 51234 ssh2")
    if fp:
        line += f": ED25519 SHA256:{fp}"
    return line


def _run(lines):
    tmp = tempfile.NamedTemporaryFile("w", suffix=".log", delete=False)
    tmp.write("\n".join(lines) + "\n")
    tmp.close()
    try:
        return detect_key_events(tmp.name)
    finally:
        os.unlink(tmp.name)


class TestU11CoverageCopy(unittest.TestCase):
    def test_dark_note_plain_no_config_order(self):
        out = _run([_key(IP, "alice", BASE)])
        self.assertEqual(len(out["coverage"]), 1)
        note = out["coverage"][0]["note"]
        self.assertEqual(out["coverage"][0]["status"], "dark")
        self.assertIn("CANNOT see new keys", note)  # pinned warning kept
        self.assertNotIn("sshd_config", note)
        self.assertNotIn("LogLevel", note)
        self.assertNotIn("VERBOSE", note)

    def test_verbose_note_plain(self):
        out = _run([_key(IP, "alice", BASE, FP)])
        note = out["coverage"][0]["note"]
        self.assertEqual(out["coverage"][0]["status"], "verbose")
        self.assertIn("can see new keys", note)
        self.assertNotIn("LogLevel", note)
        self.assertNotIn("VERBOSE", note)

    def test_no_source_orders_config_edit(self):
        for name in ("detector.py", "app.py"):
            with open(os.path.join(os.path.dirname(__file__), "..",
                                   name)) as f:
                self.assertNotIn("sshd_config", f.read(), name)


@unittest.skipIf(appm is None, "Flask not installed")
class TestU11U12DemoCopy(unittest.TestCase):
    def test_heading_is_plain_question(self):
        self.assertIn("Can brutedash spot new SSH keys?",
                      appm.RESULTS_HTML)
        self.assertNotIn("SSH key visibility", appm.RESULTS_HTML)

    def test_headers_say_count_not_failed_attempts(self):
        self.assertNotIn("Failed attempts", appm.RESULTS_HTML)
        self.assertNotIn("Failed attempts", appm.HISTORY_HTML)
        self.assertIn("<th>Count</th>", appm.RESULTS_HTML)
        self.assertIn("<th>Count</th>", appm.HISTORY_HTML)

    def test_count_labels_per_kind(self):
        self.assertEqual(appm.count_label("brute_force"), "failed logins")
        self.assertEqual(appm.count_label("burst_cadence"),
                         "failed logins in the burst")
        self.assertEqual(appm.count_label("username_enumeration"),
                         "different usernames tried")
        self.assertEqual(appm.count_label("duplicate_attempts"),
                         "identical failed logins")
        self.assertEqual(appm.count_label("first_seen_key"),
                         "new key seen")
        self.assertEqual(appm.count_label("something_new"),
                         "events counted")
        self.assertEqual(appm.count_label(None), "events counted")

    def test_results_render_shows_label_under_count(self):
        with appm.app.test_request_context():
            from flask import render_template_string
            html = render_template_string(
                appm.RESULTS_HTML, scanned_at="now", coverage=[],
                findings=[{"ip": IP, "count": 7, "severity": "High",
                           "kind": "username_enumeration",
                           "count_label": appm.count_label(
                               "username_enumeration"),
                           "detail": "", "repeat": False}])
        self.assertIn("different usernames tried", html)
        self.assertNotIn("Failed attempts", html)


class TestU10RetentionLabels(unittest.TestCase):
    def test_dashboard_maps_prune_table_names(self):
        path = os.path.join(os.path.dirname(__file__), "..",
                            "netmon", "dashboard.py")
        with open(path) as f:
            src = f.read()
        self.assertIn("tableLabels", src)
        self.assertIn('dns_queries:"DNS lookups"', src)
        self.assertIn('device_hostnames:"Device name sightings"', src)
        self.assertIn("tableLabels[t] || t", src)


if __name__ == "__main__":
    unittest.main()
