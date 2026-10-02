"""Tests for netmon/relay.py: relay_active() detection.

The dashboard banner keys off this: blue only when bettercap is really
relaying, amber when the mode is armed but idle. Run:
python -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon import relay as relaym


class TestRelayActive(unittest.TestCase):
    def setUp(self):
        relaym._RELAY_CACHE["at"] = 0  # bust cache before each test

    def test_no_relay_running(self):
        # No bettercap on this machine during tests.
        self.assertFalse(relaym.relay_active())

    def test_never_raises(self):
        try:
            relaym.relay_active()
        except Exception as exc:  # noqa: BLE001
            self.fail(f"relay_active raised {exc!r}")

    def test_cache_serves_stale_within_ttl(self):
        relaym._RELAY_CACHE["at"] = time.monotonic()
        relaym._RELAY_CACHE["active"] = True  # forced value
        # Even though no bettercap runs, the cache wins inside the TTL.
        self.assertTrue(relaym.relay_active())

    def test_cache_expires(self):
        relaym._RELAY_CACHE["at"] = time.monotonic() - 3600
        relaym._RELAY_CACHE["active"] = True  # stale forced value
        # TTL long passed: re-probed, and no bettercap runs here.
        self.assertFalse(relaym.relay_active())


if __name__ == "__main__":
    unittest.main()
