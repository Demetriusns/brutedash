"""Tests for the 2026-10-12 daily build: /brief per-IP rate limit (S2).

The /brief POST is unauthenticated, and in keyed deployments every call is
a paid LLM call. app._brief_allowed mirrors the dashboard's _ai_ask_allowed
pattern: per-IP sliding windows (ai.ask_per_min per 60s, ai.ask_per_hour
per 3600s in config.yaml), check-and-record in one lock. The limiter is
engaged only when the LLM path would actually be taken (OPENAI_API_KEY set
AND ai.enabled()); the rule-based fallback stays free.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

CANNED_BRIEF = {
    "severity": "High",
    "observed_pattern": "10.9.9.9 made 25 failed SSH login attempts.",
    "recommended_actions": ["Block the IP at the firewall."],
}

BRIEF_FORM = {"ip": "10.9.9.9", "count": "25", "severity": "High"}


def _post_brief(client):
    return client.post("/brief", data=BRIEF_FORM)


@unittest.skipIf(appm is None, "Flask not installed")
class TestBriefLimiterMath(unittest.TestCase):
    def setUp(self):
        appm._BRIEF_USAGE.clear()

    def test_fresh_ip_allowed(self):
        allowed, retry = appm._brief_allowed("10.8.8.1", now=1000.0,
                                             limits=(2, 5))
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def _spend(self, ip, times, now, limits):
        for _ in range(times):
            allowed, _ = appm._brief_allowed(ip, now=now, limits=limits)
            self.assertTrue(allowed, "setup spend unexpectedly denied")

    def test_per_min_window_blocks(self):
        now = 2000.0
        self._spend("10.8.8.2", 2, now, (2, 100))
        allowed, retry = appm._brief_allowed("10.8.8.2", now=now + 1,
                                             limits=(2, 100))
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertLessEqual(retry, 60)

    def test_denied_call_is_not_recorded(self):
        # After a denial, the budget must not shrink further.
        now = 2000.0
        self._spend("10.8.8.21", 2, now, (2, 100))
        self.assertFalse(appm._brief_allowed("10.8.8.21", now=now + 1,
                                             limits=(2, 100))[0])
        allowed, _ = appm._brief_allowed("10.8.8.21", now=now + 62,
                                         limits=(2, 100))
        self.assertTrue(allowed, "budget shrank on denied call")

    def test_per_hour_window_blocks(self):
        now = 3000.0
        self._spend("10.8.8.3", 3, now, (100, 3))
        allowed, retry = appm._brief_allowed("10.8.8.3", now=now + 61,
                                             limits=(100, 3))
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_window_expiry_restores_budget(self):
        now = 4000.0
        self._spend("10.8.8.4", 2, now, (2, 100))
        allowed, _ = appm._brief_allowed("10.8.8.4", now=now + 61,
                                         limits=(2, 100))
        self.assertTrue(allowed)

    def test_stale_ip_keys_pruned(self):
        appm._brief_allowed("10.8.8.5", now=1000.0, limits=(2, 5))
        self.assertIn("10.8.8.5", appm._BRIEF_USAGE)
        appm._brief_allowed("10.8.8.6", now=1000.0 + 7200, limits=(2, 5))
        self.assertNotIn("10.8.8.5", appm._BRIEF_USAGE)


@unittest.skipIf(appm is None, "Flask not installed")
class TestBriefLimiterGating(unittest.TestCase):
    def setUp(self):
        appm._BRIEF_USAGE.clear()
        self.client = appm.app.test_client()
        self._env = os.environ.pop("OPENAI_API_KEY", None)

    def tearDown(self):
        if self._env is not None:
            os.environ["OPENAI_API_KEY"] = self._env
        else:
            os.environ.pop("OPENAI_API_KEY", None)
        appm._BRIEF_USAGE.clear()

    def test_keyless_calls_unlimited(self):
        # No key -> LLM path off -> limiter stays out of the way.
        with mock.patch.object(appm, "write_brief",
                               return_value=(dict(CANNED_BRIEF),
                                             "rule-based")):
            for _ in range(25):
                resp = _post_brief(self.client)
                self.assertEqual(resp.status_code, 200)
                self.assertIn(b"origin: rule-based", resp.data)
        self.assertEqual(appm._BRIEF_USAGE, {})

    def test_keyed_calls_limited(self):
        # Key + ai.enabled() -> limiter engaged; past the cap -> 429.
        os.environ["OPENAI_API_KEY"] = "sk-test-fake"
        with mock.patch.object(appm, "write_brief",
                               return_value=(dict(CANNED_BRIEF), "llm")), \
             mock.patch.object(appm.cfgm, "ai_enabled", return_value=True), \
             mock.patch.object(appm, "_brief_limits", return_value=(2, 100)):
            resp1 = _post_brief(self.client)
            resp2 = _post_brief(self.client)
            self.assertEqual(resp1.status_code, 200)
            self.assertEqual(resp2.status_code, 200)
            resp3 = _post_brief(self.client)
            self.assertEqual(resp3.status_code, 429)
            self.assertIn("Retry-After", resp3.headers)
            self.assertGreater(int(resp3.headers["Retry-After"]), 0)

    def test_keyed_but_ai_off_calls_unlimited(self):
        # Key present but provider "off" -> no spend -> no limit.
        os.environ["OPENAI_API_KEY"] = "sk-test-fake"
        with mock.patch.object(appm, "write_brief",
                               return_value=(dict(CANNED_BRIEF),
                                             "rule-based")), \
             mock.patch.object(appm.cfgm, "ai_enabled", return_value=False):
            for _ in range(25):
                resp = _post_brief(self.client)
                self.assertEqual(resp.status_code, 200)

    def test_validation_still_runs_first(self):
        # Invalid form input is rejected before the limiter is even consulted.
        os.environ["OPENAI_API_KEY"] = "sk-test-fake"
        with mock.patch.object(appm.cfgm, "ai_enabled", return_value=True):
            resp = self.client.post("/brief", data={"ip": "not-an-ip",
                                                    "count": "5",
                                                    "severity": "High"})
            self.assertEqual(resp.status_code, 400)
        self.assertEqual(appm._BRIEF_USAGE, {})


if __name__ == "__main__":
    unittest.main()
