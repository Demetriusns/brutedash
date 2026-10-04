"""Tests for batch 18: AI-question rate limits (hardening checklist item).

Every /api/ask and /api/triage call with the LLM on is a paid API call.
Per-IP sliding windows (ai.ask_per_min per 60s, ai.ask_per_hour per 3600s
in config.yaml) guard the AI budget. The cheap fallback paths (no API
key configured) are never limited.

Run: python -m unittest discover -s tests -v
"""
import json
import os
import re
import subprocess
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

from helpers import ScratchDbTestCase, scratch_file


@unittest.skipIf(dashm is None, "Flask not installed")
class TestAiAskLimiterMath(unittest.TestCase):
    def setUp(self):
        dashm._AI_ASK_USAGE.clear()

    def test_fresh_ip_allowed(self):
        allowed, retry = dashm._ai_ask_allowed("10.8.8.1", now=1000.0,
                                              limits=(2, 5))
        self.assertTrue(allowed)
        self.assertEqual(retry, 0)

    def _spend(self, ip, times, now, limits):
        for _ in range(times):
            allowed, _ = dashm._ai_ask_allowed(ip, now=now, limits=limits)
            self.assertTrue(allowed, "setup spend unexpectedly denied")

    def test_per_min_window_blocks(self):
        now = 2000.0
        self._spend("10.8.8.2", 2, now, (2, 100))
        allowed, retry = dashm._ai_ask_allowed("10.8.8.2", now=now + 1,
                                              limits=(2, 100))
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)
        self.assertLessEqual(retry, 60)

    def test_denied_call_is_not_recorded(self):
        # After a denial, the budget must not shrink further.
        now = 2000.0
        self._spend("10.8.8.21", 2, now, (2, 100))
        self.assertFalse(dashm._ai_ask_allowed("10.8.8.21", now=now + 1,
                                              limits=(2, 100))[0])
        allowed, _ = dashm._ai_ask_allowed("10.8.8.21", now=now + 62,
                                          limits=(2, 100))
        self.assertTrue(allowed)

    def test_min_window_expires(self):
        now = 3000.0
        self._spend("10.8.8.3", 2, now, (2, 100))
        allowed, _ = dashm._ai_ask_allowed("10.8.8.3", now=now + 61,
                                          limits=(2, 100))
        self.assertTrue(allowed)

    def test_per_hour_window_blocks_when_min_fine(self):
        now = 4000.0
        # 3 calls, all more than a minute old: min window clear, hour full.
        for t in (now - 120, now - 300, now - 600):
            self._spend("10.8.8.4", 1, t, (10, 3))
        allowed, retry = dashm._ai_ask_allowed("10.8.8.4", now=now,
                                              limits=(10, 3))
        self.assertFalse(allowed)
        self.assertGreater(retry, 0)

    def test_stale_hour_stamps_pruned(self):
        self._spend("10.8.8.5", 1, 100.0, (1, 1))
        allowed, _ = dashm._ai_ask_allowed("10.8.8.5", now=5000.0,
                                          limits=(1, 1))
        self.assertTrue(allowed)

    def test_stale_ip_keys_do_not_accumulate(self):
        # One-shot visitors must not grow the dict forever.
        for i in range(50):
            dashm._ai_ask_allowed("10.9.0.%d" % i, now=100.0,
                                 limits=(10, 100))
        self.assertEqual(len(dashm._AI_ASK_USAGE), 50)
        allowed, _ = dashm._ai_ask_allowed("10.9.0.200", now=5000.0,
                                          limits=(10, 100))
        self.assertTrue(allowed)
        self.assertEqual(len(dashm._AI_ASK_USAGE), 1)

    def test_per_ip_isolation(self):
        now = 6000.0
        self._spend("10.8.8.6", 2, now, (2, 100))
        allowed, _ = dashm._ai_ask_allowed("10.8.8.7", now=now + 1,
                                          limits=(2, 100))
        self.assertTrue(allowed)

    def test_limits_floor_at_one(self):
        self.assertEqual(dashm._ai_ask_limits()[0] >= 1, True)


class _LlmOn:
    """Stub ai_assist with the paid path live, so the limiter engages."""
    def llm_available(self):
        return True

    def answer_question(self, question):
        return "stub answer"

    def triage_verdict(self, alert):
        return {"verdict": "likely noise", "reasoning": "stub"}


class _LlmOff:
    """Stub ai_assist with the free fallback path: never limited."""
    def llm_available(self):
        return False


@unittest.skipIf(dashm is None, "Flask not installed")
class TestAiAskRoutes(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        dashm._AI_ASK_USAGE.clear()
        self._real_assist = dashm._ai_assist
        self._real_limits = dashm._ai_ask_limits
        dashm._ai_ask_limits = lambda: (1, 2)  # tiny windows, fast tests

    def tearDown(self):
        dashm._ai_assist = self._real_assist
        dashm._ai_ask_limits = self._real_limits
        dashm._AI_ASK_USAGE.clear()
        super().tearDown()

    def _ask(self, c):
        return c.post("/api/ask", json={"question": "anything up?"},
                      environ_base={"REMOTE_ADDR": "10.9.9.9"})

    def test_ask_first_ok_then_429(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        first = self._ask(c)
        self.assertEqual(first.status_code, 200)
        second = self._ask(c)
        self.assertEqual(second.status_code, 429)
        body = second.get_json()
        self.assertEqual(body["error"], "slow_down")
        self.assertIn("retry_after", body)
        self.assertIn("Retry-After", second.headers)

    def test_triage_is_also_limited(self):
        dashm._ai_assist = lambda: _LlmOn()
        aid = dbm.add_alert("port_scan", "High", "t", "d")
        c = dashm.app.test_client()
        first = c.post(f"/api/triage/{aid}",
                       environ_base={"REMOTE_ADDR": "10.9.9.8"})
        self.assertEqual(first.status_code, 200)
        second = c.post(f"/api/triage/{aid}",
                        environ_base={"REMOTE_ADDR": "10.9.9.8"})
        self.assertEqual(second.status_code, 429)

    def test_free_fallback_path_never_limited(self):
        # LLM off: 15 rapid calls must all pass (limits are 1/min, 2/hr).
        dashm._ai_assist = lambda: _LlmOff()
        c = dashm.app.test_client()
        for _ in range(15):
            r = self._ask(c)
            self.assertNotEqual(r.status_code, 429)
        body = self._ask(c).get_json()
        self.assertTrue(body.get("unavailable"))

    def test_different_ips_have_separate_budgets(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        r1 = c.post("/api/ask", json={"question": "a"},
                    environ_base={"REMOTE_ADDR": "10.9.9.10"})
        self.assertEqual(r1.status_code, 200)
        r2 = c.post("/api/ask", json={"question": "a"},
                    environ_base={"REMOTE_ADDR": "10.9.9.11"})
        self.assertEqual(r2.status_code, 200)


@unittest.skipIf(dashm is None, "Flask not installed")
class TestAskPageServedJs(unittest.TestCase):
    def test_ask_page_script_parses(self):
        # The /ask page carries its own inline script (429 handling); the
        # suite-level node --check guard covers it too, not just index.
        html = dashm.app.test_client().get("/ask").get_data(as_text=True)
        m = re.search(r"<script>(.*?)</script>", html, re.S)
        self.assertIsNotNone(m)
        self.assertIn("status === 429", m.group(1))
        with scratch_file(suffix=".js") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(m.group(1))
            proc = subprocess.run(["node", "--check", path],
                                  capture_output=True, text=True,
                                  timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[:500])


if __name__ == "__main__":
    unittest.main()
