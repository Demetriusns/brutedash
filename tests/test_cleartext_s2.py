"""Tests for security S2 minimum (2026-11-25): the loud cleartext
warning owed on a non-loopback bind.

The dashboard is plain HTTP. H1 already refuses a non-loopback bind
without a password; S2 covers the allowed case -- a password makes the
bind permitted, not encrypted. Pins:
- _is_loopback / _cleartext_warning host classification in netmon.run
- the existing _bind_allowed rules are unchanged
- the sign-in page shows the not-encrypted banner only when run.py's
  NETMON_CLEARTEXT_LAN flag is set (never on loopback/default runs)

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon.run import _bind_allowed, _cleartext_warning, _is_loopback

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

BANNER_MARK = "This sign-in page is"


class TestHostClassification(unittest.TestCase):
    def test_loopback_hosts(self):
        for host in ("127.0.0.1", "localhost", "::1", " 127.0.0.1 "):
            self.assertTrue(_is_loopback(host), host)

    def test_non_loopback_hosts(self):
        for host in ("0.0.0.0", "192.168.1.20", "", None):
            self.assertFalse(_is_loopback(host), host)


class TestCleartextWarning(unittest.TestCase):
    def test_no_warning_on_loopback(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertIsNone(_cleartext_warning(host), host)

    def test_warning_on_lan_bind(self):
        text = _cleartext_warning("0.0.0.0")
        self.assertIsNotNone(text)
        self.assertIn("WITHOUT encryption", text)
        self.assertIn("plain text", text)
        self.assertIn("0.0.0.0", text)

    def test_bind_rules_unchanged(self):
        old = os.environ.get("NETMON_PASSWORD")
        os.environ.pop("NETMON_PASSWORD", None)
        try:
            self.assertTrue(_bind_allowed("127.0.0.1"))
            self.assertFalse(_bind_allowed("0.0.0.0"))
        finally:
            if old is None:
                os.environ.pop("NETMON_PASSWORD", None)
            else:
                os.environ["NETMON_PASSWORD"] = old


@unittest.skipIf(dashm is None, "Flask not installed")
class TestLoginBanner(unittest.TestCase):
    def setUp(self):
        self._old = dashm.app.config.get("NETMON_CLEARTEXT_LAN")
        dashm.app.config.pop("NETMON_CLEARTEXT_LAN", None)
        self.client = dashm.app.test_client()

    def tearDown(self):
        dashm.app.config.pop("NETMON_CLEARTEXT_LAN", None)
        if self._old is not None:
            dashm.app.config["NETMON_CLEARTEXT_LAN"] = self._old

    def test_no_banner_by_default(self):
        body = self.client.get("/login").get_data(as_text=True)
        self.assertNotIn(BANNER_MARK, body)
        self.assertFalse(dashm._cleartext_lan())

    def test_banner_when_flag_set(self):
        dashm.app.config["NETMON_CLEARTEXT_LAN"] = True
        self.assertTrue(dashm._cleartext_lan())
        body = self.client.get("/login").get_data(as_text=True)
        self.assertIn(BANNER_MARK, body)
        self.assertIn("NOT encrypted", body)
        self.assertIn("network you", body)


if __name__ == "__main__":
    unittest.main()
