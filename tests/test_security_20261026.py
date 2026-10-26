"""Security H1 (2026-10-25 weekly review) -- the login "5-minute
block" did not exist.

_login_allowed() denied only when >=5 failures fell inside the 60s
window; _LOGIN_BLOCK=300 merely retained stamps. Five fresh guesses
were allowed every minute, indefinitely (~7,200/day against the
single shared owner password). The block is now derived from the
stamps: any 5 failures inside one 60s span block until 300s after
that cluster's 5th failure. No new state -- clearing the stamps
(successful login) clears the block.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from netmon import dashboard as dashm
except Exception:
    dashm = None


@unittest.skipIf(dashm is None, "Flask not installed")
class TestLoginBlock(unittest.TestCase):
    def setUp(self):
        dashm._LOGIN_ATTEMPTS.clear()

    def tearDown(self):
        dashm._LOGIN_ATTEMPTS.clear()

    def _inject(self, ip, offsets):
        now = time.time()
        with dashm._LOGIN_LOCK:
            dashm._LOGIN_ATTEMPTS[ip] = [now + off for off in offsets]

    def test_block_survives_the_window(self):
        # 5 failures clustered within 5s, checked 61s after the first:
        # the old code allowed this; the 5-minute block must not.
        ip = "10.26.10.1"
        self._inject(ip, [-65, -64, -63, -62, -61])
        self.assertFalse(dashm._login_allowed(ip))

    def test_block_holds_near_its_end(self):
        ip = "10.26.10.2"
        self._inject(ip, [-299, -298, -297, -296, -295])
        self.assertFalse(dashm._login_allowed(ip))

    def test_block_expires(self):
        # Cluster's 5th failure is past _LOGIN_BLOCK: stamps age out
        # and guessing is allowed again.
        ip = "10.26.10.3"
        self._inject(ip, [-310, -309, -308, -307, -306])
        self.assertTrue(dashm._login_allowed(ip))

    def test_spread_failures_never_block(self):
        # 5 failures, but no 5 fall inside one 60s span.
        ip = "10.26.10.4"
        self._inject(ip, [-80, -60, -40, -20, 0])
        self.assertTrue(dashm._login_allowed(ip))

    def test_four_failures_never_block(self):
        ip = "10.26.10.5"
        self._inject(ip, [-4, -3, -2, -1])
        self.assertTrue(dashm._login_allowed(ip))

    def test_later_cluster_blocks_on_its_own(self):
        ip = "10.26.10.6"
        self._inject(ip, [-250, -190, -130])
        self.assertTrue(dashm._login_allowed(ip))
        now = time.time()
        with dashm._LOGIN_LOCK:
            dashm._LOGIN_ATTEMPTS[ip] += [now - 20, now - 15,
                                          now - 10, now - 5, now]
        self.assertFalse(dashm._login_allowed(ip))

    def test_success_clear_removes_block_mid_block(self):
        ip = "10.26.10.7"
        self._inject(ip, [-100, -99, -98, -97, -96])
        self.assertFalse(dashm._login_allowed(ip))
        dashm._clear_login_failures(ip)
        self.assertTrue(dashm._login_allowed(ip))

    def test_other_ips_unaffected_by_block(self):
        self._inject("10.26.10.8", [-50, -49, -48, -47, -46])
        self.assertFalse(dashm._login_allowed("10.26.10.8"))
        self.assertTrue(dashm._login_allowed("10.26.10.9"))


if __name__ == "__main__":
    unittest.main()
