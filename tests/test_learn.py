"""Tests for netmon/learn.py + db learning helpers.

Dismissals teach the monitor: repeated dismissals of the same
(rule, pattern) produce a pending suggestion, the human's Apply writes
the allowlist row, and nothing is ever silenced without that click.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from helpers import fresh_db, restore_db
from netmon import db as dbm
from netmon import learn as learnm


class TestWhyTextPlainLanguage(unittest.TestCase):
    def test_why_text_uses_catalog_title_not_kind_id(self):
        # Council review: suggestion copy must not show raw kind ids.
        text = learnm.why_text("arp_spoof", "aa:bb:cc:dd:ee:ff",
                               True, 7, "High")
        self.assertNotIn("arp_spoof", text)
        self.assertIn("ARP spoofing", text)

    def test_why_text_falls_back_gracefully(self):
        text = learnm.why_text("some_future_kind", "x", False, 3, "Low")
        self.assertIn("some future kind", text)


class TestExtractPattern(unittest.TestCase):
    def test_port_kind_prefers_external_ip(self):
        p, broad = learnm.extract_pattern({
            "kind": "unusual_port", "severity": "Medium",
            "title": "Talking on an unusual channel (port 4444)",
            "detail": "Workstation sent traffic to 203.0.113.7 on port"
                      " 4444 (0.31 MB in the last 15 min)."})
        self.assertEqual(p, "203.0.113.7")
        self.assertFalse(broad)

    def test_port_kind_falls_back_to_port(self):
        p, broad = learnm.extract_pattern({
            "kind": "unusual_port", "severity": "Medium",
            "title": "Talking on an unusual channel (port 8080)",
            "detail": "Device talked on port 8080 to a new host."})
        self.assertEqual(p, "port 8080")
        self.assertFalse(broad)

    def test_dns_kind_prefers_domain(self):
        p, broad = learnm.extract_pattern({
            "kind": "dns_lookup_burst", "severity": "Medium",
            "title": "One domain looked up over and over",
            "detail": "192.168.1.10 asked for stats.gamecdn.example"
                      " 300 times in 10 minutes."})
        self.assertEqual(p, "stats.gamecdn.example")
        self.assertFalse(broad)

    def test_device_kind_prefers_mac(self):
        p, broad = learnm.extract_pattern({
            "kind": "new_device", "severity": "Medium",
            "title": "A new device joined the network",
            "detail": "A new device (aa:bb:cc:dd:ee:ff) appeared on the"
                      " local network with IP 192.168.1.42."})
        self.assertEqual(p, "aa:bb:cc:dd:ee:ff")
        self.assertFalse(broad)

    def test_lan_ips_are_never_candidates(self):
        p, broad = learnm.extract_pattern({
            "kind": "traffic_spike", "severity": "Medium",
            "title": "Unusual surge in network traffic",
            "detail": "192.168.1.1 moved 400 MB in the last 5 minutes."})
        self.assertEqual(p, "traffic_spike")
        self.assertTrue(broad)

    def test_no_tokens_is_broad(self):
        p, broad = learnm.extract_pattern({
            "kind": "traffic_spike", "severity": "Medium",
            "title": "Unusual surge in network traffic",
            "detail": "Moved 400.0 MB in the last 5 minutes vs a baseline"
                      " of 10.0 MB/min."})
        self.assertEqual(p, "traffic_spike")
        self.assertTrue(broad)

    def test_timestamps_and_counts_not_extracted(self):
        p, _ = learnm.extract_pattern({
            "kind": "volume_anomaly", "severity": "Medium",
            "title": "Big upload at 3:47am",
            "detail": "Moved 2048.5 MB at 2026-10-03 03:47:12."})
        self.assertNotIn("2048", p)
        self.assertNotIn("03:47", p)

    def test_thresholds(self):
        self.assertEqual(learnm.threshold_for("Low"), 3)
        self.assertEqual(learnm.threshold_for("Medium"), 3)
        self.assertEqual(learnm.threshold_for("High"), 5)
        self.assertEqual(learnm.threshold_for("Critical"), 5)


class TestDismissalLearning(unittest.TestCase):
    def setUp(self):
        self._db_state = fresh_db()

    def tearDown(self):
        restore_db(*self._db_state)

    def _dismiss(self, kind, severity, detail, title="t"):
        aid = dbm.add_alert(kind, severity, title, detail)
        dbm.set_alert_status(aid, "dismissed")
        return dbm.learn_from_dismissal(aid)

    def test_three_dismissals_produce_a_suggestion(self):
        detail = "Host sent traffic to 203.0.113.9 on port 4444 (1 MB)."
        self.assertIsNone(self._dismiss("unusual_port", "Medium", detail))
        self.assertIsNone(self._dismiss("unusual_port", "Medium", detail))
        sug = self._dismiss("unusual_port", "Medium", detail)
        self.assertIsNotNone(sug)
        self.assertEqual(sug["pattern"], "203.0.113.9")
        self.assertEqual(sug["kind"], "unusual_port")
        self.assertFalse(sug["broad"])
        self.assertEqual(len(dbm.list_suggestions()), 1)

    def test_no_duplicate_suggestions(self):
        detail = "Host sent traffic to 203.0.113.9 on port 4444 (1 MB)."
        for _ in range(3):
            self._dismiss("unusual_port", "Medium", detail)
        self.assertIsNone(self._dismiss("unusual_port", "Medium", detail))
        self.assertEqual(len(dbm.list_suggestions()), 1)

    def test_apply_writes_allowlist_and_silences(self):
        detail = "Host sent traffic to 203.0.113.9 on port 4444 (1 MB)."
        for _ in range(3):
            self._dismiss("unusual_port", "Medium", detail)
        sug = dbm.list_suggestions()[0]
        self.assertTrue(dbm.decide_suggestion(sug["id"], "applied"))
        self.assertTrue(dbm.is_allowlisted(
            "unusual_port", "Host sent traffic to 203.0.113.9 on port 1"))
        self.assertEqual(dbm.list_suggestions(), [])  # no longer pending

    def test_ignore_blocks_re_suggestion(self):
        detail = "Host sent traffic to 203.0.113.9 on port 4444 (1 MB)."
        for _ in range(3):
            self._dismiss("unusual_port", "Medium", detail)
        sug = dbm.list_suggestions()[0]
        self.assertTrue(dbm.decide_suggestion(sug["id"], "ignored"))
        self.assertIsNone(self._dismiss("unusual_port", "Medium", detail))
        self.assertEqual(len(dbm.list_suggestions()), 0)  # nothing pending again
        self.assertEqual(len(dbm.list_suggestions("ignored")), 1)
        self.assertEqual(len(dbm.list_suggestions("applied")), 0)
        self.assertFalse(dbm.is_allowlisted(
            "unusual_port", "Host sent traffic to 203.0.113.9 on port 1"))

    def test_critical_needs_five_dismissals(self):
        detail = "C2 beacon to 198.51.100.9 on port 443."
        for _ in range(4):
            self.assertIsNone(
                self._dismiss("beaconing", "Critical", detail))
        sug = self._dismiss("beaconing", "Critical", detail)
        self.assertIsNotNone(sug)
        self.assertIn("5", sug["why"])

    def test_bad_decision_rejected(self):
        detail = "Host sent traffic to 203.0.113.9 on port 4444 (1 MB)."
        for _ in range(3):
            self._dismiss("unusual_port", "Medium", detail)
        sug = dbm.list_suggestions()[0]
        with self.assertRaises(ValueError):
            dbm.decide_suggestion(sug["id"], "maybe")
        self.assertFalse(dbm.decide_suggestion(999999, "applied"))

    def test_missing_alert_is_safe(self):
        self.assertIsNone(dbm.learn_from_dismissal(424242))

    def test_empty_kind_learns_nothing(self):
        aid = dbm.add_alert("", "Medium", "t", "some detail text")
        dbm.set_alert_status(aid, "dismissed")
        self.assertIsNone(dbm.learn_from_dismissal(aid))
        self.assertEqual(dbm.list_suggestions(), [])

    def test_broad_apply_silences_whole_rule(self):
        # A traffic_spike with no tokens -> broad suggestion (pattern = kind).
        detail = "Moved 400.0 MB in the last 5 minutes."
        for _ in range(3):
            self._dismiss("traffic_spike", "Medium", detail)
        sugs = dbm.list_suggestions()
        self.assertEqual(len(sugs), 1)
        self.assertTrue(sugs[0]["broad"])
        self.assertTrue(dbm.decide_suggestion(sugs[0]["id"], "applied"))
        # The whole rule is now silenced, even for text that never
        # mentions the kind name.
        self.assertTrue(dbm.is_allowlisted(
            "traffic_spike", "Moved 999.0 MB in the last 5 minutes."))
        self.assertFalse(dbm.is_allowlisted(
            "unusual_port", "Moved 999.0 MB in the last 5 minutes."))

    def test_threshold_uses_most_demanding_severity(self):
        # 3 Low dismissals alone suggest; but once a High dismissal is
        # seen for the same (kind, pattern), the bar rises to 5.
        detail = "Host sent traffic to 203.0.113.11 on port 4444 (1 MB)."
        aid1 = dbm.add_alert("unusual_port", "High", "t", detail)
        dbm.set_alert_status(aid1, "dismissed")
        dbm.learn_from_dismissal(aid1)
        for _ in range(2):
            self.assertIsNone(self._dismiss("unusual_port", "Low", detail))
        self.assertEqual(dbm.list_suggestions(), [])  # 3 total < 5
        self.assertIsNone(self._dismiss("unusual_port", "Low", detail))
        sugs = dbm.list_suggestions()  # 4 total still < 5
        self.assertEqual(len(sugs), 0)
        sug = self._dismiss("unusual_port", "Low", detail)  # 5th
        self.assertIsNotNone(sug)
        self.assertIn("5", sug["why"])


if __name__ == "__main__":
    unittest.main()
