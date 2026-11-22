"""Tests for the 2026-11-22 batch: UX U9 — quarantined device status.

Council UX verdicts 2026-11-08 and 2026-11-15 both flagged U9: the
Devices table Status cell was computed solely from probation
(`v.on_probation ? Probation : ✅ Trusted`) and never consulted
`v.quarantined`, even though the same row already carried that field
(the action button flips Isolate/Release on it). A device the user
deliberately cut off from the internet therefore still showed
"✅ Trusted" hours later, with no sign in the Status column of why it
had no internet.

Fix (isolation first, per the verdicts' prescribed wording): if
`v.quarantined`, the Status cell renders
"⛔ Cut off from the internet — click Release to bring it back"
(ahead of Probation and Trusted, using the existing `.badge.bad`
class); otherwise the previous Probation/Trusted badges are unchanged.
No backend, API, DB, or auth changes: /api/devices already returns
"quarantined" per device.

The status rendering is client-side JS, so these tests pin the served
page: the quarantined branch must be present, must be evaluated
before the probation branch in the status expression, and the exact
plain-language wording must ship. A companion API test confirms the
field the JS consults is the one the server actually returns.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

from helpers import ScratchDbTestCase

# Auth env vars are matched by prefix so no credential-shaped literal
# ever appears in this file (the staged-diff scan greps for them).
_AUTH_PREFIXES = ("BRUTEDASH_AUTH_", "NETMON_PASS")


def _auth_env_keys():
    return [k for k in os.environ if k.startswith(_AUTH_PREFIXES)]

_BADGE = ("⛔ Cut off from the internet — click Release to bring it back")


@unittest.skipIf(dashm is None, "Flask not installed")
class TestDeviceStatusU9(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _auth_env_keys()}
        for key in list(self._old_env):  # open-dashboard mode: no gate
            os.environ.pop(key, None)
        self.client = dashm.app.test_client()

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        super().tearDown()

    def _page(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        return r.get_data(as_text=True)

    def test_quarantined_badge_wording_ships_in_page(self):
        page = self._page()
        self.assertIn(_BADGE, page)
        self.assertIn('class="badge bad">⛔ Cut off', page)

    def test_quarantine_checked_before_probation_in_status(self):
        page = self._page()
        # Isolate the loadDevices status expression: from the status
        # assignment to the end of its ternary chain.
        start = page.index("const status = v.")
        end = page.index(";", start)
        expr = page[start:end]
        self.assertTrue(expr.startswith("const status = v.quarantined"),
                        f"status must check quarantined first, got: {expr[:80]}")
        self.assertIn("v.on_probation", expr)
        self.assertIn("✅ Trusted", expr)
        # Precedence: quarantined branch text precedes probation text.
        self.assertLess(expr.index("Cut off from the internet"),
                        expr.index("Probation"))

    def test_probation_and_trusted_badges_unchanged(self):
        page = self._page()
        self.assertIn("🟡 Probation · trusted in", page)
        self.assertIn("✅ Trusted", page)

    def test_api_devices_still_returns_quarantined_field(self):
        r = self.client.get("/api/devices")
        self.assertEqual(r.status_code, 200)
        for dev in r.get_json()["devices"]:
            self.assertIn("quarantined", dev)


if __name__ == "__main__":
    unittest.main()
