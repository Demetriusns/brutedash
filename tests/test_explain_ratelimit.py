"""Tests for the 2026-10-13 batch: /explain joins the AI rate limits.

POST /explain regenerates the plain-English summary on demand. With the
LLM on, every call is a paid explainer.summarize() call, but unlike
/api/ask and /api/triage it carried no rate limit -- a runaway script or
a shared-password machine could spend the AI budget through it. It now
carries the same @_ai_rate_limited decorator and draws on the same
per-IP budget (ai.ask_per_min / ai.ask_per_hour). The rule-based
fallback (no API key) is never limited.

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


class _LlmOn:
    """Stub ai_assist with the paid path live, so the limiter engages.

    explain_now itself never calls ai_assist -- the decorator consults
    llm_available() to decide whether this call would spend. The real
    summarize() stays on its free rule-based path in tests (no
    OPENAI_API_KEY in the test env), so responses are still 200/ok.
    """
    def llm_available(self):
        return True

    def answer_question(self, question):
        return "stub answer"


class _LlmOff:
    """Stub ai_assist with the free fallback path: never limited."""
    def llm_available(self):
        return False


@unittest.skipIf(dashm is None, "Flask not installed")
class TestExplainRateLimit(ScratchDbTestCase):
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

    def _explain(self, c, ip="10.7.7.7"):
        return c.post("/explain", environ_base={"REMOTE_ADDR": ip})

    def test_explain_first_ok_then_429(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        first = self._explain(c)
        self.assertEqual(first.status_code, 200)
        self.assertTrue(first.get_json()["ok"])
        second = self._explain(c)
        self.assertEqual(second.status_code, 429)
        body = second.get_json()
        self.assertEqual(body["error"], "slow_down")
        self.assertIn("Retry-After", second.headers)
        # Retry-After comes from the sliding window, not a static value:
        # with a 1-per-60s cap the wait is positive and at most a minute.
        self.assertGreaterEqual(body["retry_after"], 1)
        self.assertLessEqual(body["retry_after"], 60)
        self.assertEqual(int(second.headers["Retry-After"]),
                         body["retry_after"])

    def test_explain_free_fallback_never_limited(self):
        # LLM off: 15 rapid calls must all pass (limits are 1/min, 2/hr).
        dashm._ai_assist = lambda: _LlmOff()
        c = dashm.app.test_client()
        for _ in range(15):
            r = self._explain(c)
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.get_json()["ok"])

    def test_explain_shares_budget_with_ask(self):
        # One budget per IP across the AI routes: spending it on /api/ask
        # leaves nothing for /explain, and vice versa.
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        r = c.post("/api/ask", json={"question": "anything up?"},
                   environ_base={"REMOTE_ADDR": "10.7.7.8"})
        self.assertEqual(r.status_code, 200)
        r = self._explain(c, ip="10.7.7.8")
        self.assertEqual(r.status_code, 429)
        r = self._explain(c, ip="10.7.7.9")
        self.assertEqual(r.status_code, 200)
        r = c.post("/api/ask", json={"question": "anything up?"},
                   environ_base={"REMOTE_ADDR": "10.7.7.9"})
        self.assertEqual(r.status_code, 429)

    def test_explain_different_ips_separate_budgets(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        self.assertEqual(self._explain(c, ip="10.7.7.10").status_code, 200)
        self.assertEqual(self._explain(c, ip="10.7.7.11").status_code, 200)


if __name__ == "__main__":
    unittest.main()
