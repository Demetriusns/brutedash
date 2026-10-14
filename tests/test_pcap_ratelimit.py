"""Tests for the 2026-10-14 batch: /pcap joins the AI rate limits.

POST /pcap analyzes an uploaded capture and ends in an
explainer.summarize() call -- paid whenever the LLM is on -- but it was
the last paid-LLM route with no rate limit. It now draws on the same
per-IP budget as /api/ask, /api/triage and /explain
(ai.ask_per_min / ai.ask_per_hour) via _ai_spend_check. /pcap renders
HTML pages, so a breach returns an HTML slow-down page with HTTP 429
and a Retry-After header instead of the JSON shape the API routes use.
The upload form (GET) is never limited, a no-file POST (bare redirect)
spends nothing, and the rule-based fallback (no API key) is never
limited.

Run: python -m unittest discover -s tests -v
"""
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

try:
    from scapy.all import Ether, IP, TCP, wrpcap
    _HAVE_SCAPY = True
except ImportError:
    _HAVE_SCAPY = False

from helpers import ScratchDbTestCase


class _LlmOn:
    """Stub ai_assist with the paid path live, so the limiter engages.

    The real summarize() stays on its free rule-based path in tests
    (no OPENAI_API_KEY in the test env), so allowed uploads are 200.
    """
    def llm_available(self):
        return True

    def answer_question(self, question):
        return "stub answer"


class _LlmOff:
    """Stub ai_assist with the free fallback path: never limited."""
    def llm_available(self):
        return False


def _pcap_bytes():
    """A tiny valid pcap (3 SYN packets) as bytes, built once per test."""
    pkts = [Ether() / IP(src="10.0.0.5", dst="10.0.0.1")
            / TCP(dport=p, flags="S") for p in (22, 23, 445)]
    fd, path = tempfile.mkstemp(suffix=".pcap")
    os.close(fd)
    try:
        wrpcap(path, pkts)
        with open(path, "rb") as f:
            return f.read()
    finally:
        os.unlink(path)


@unittest.skipIf(dashm is None or not _HAVE_SCAPY,
                 "Flask/scapy not installed")
class TestPcapRateLimit(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        dashm._AI_ASK_USAGE.clear()
        self._real_assist = dashm._ai_assist
        self._real_limits = dashm._ai_ask_limits
        dashm._ai_ask_limits = lambda: (1, 2)  # tiny windows, fast tests
        self._bytes = _pcap_bytes()

    def tearDown(self):
        dashm._ai_assist = self._real_assist
        dashm._ai_ask_limits = self._real_limits
        dashm._AI_ASK_USAGE.clear()
        super().tearDown()

    def _upload(self, c, ip="10.8.8.8"):
        return c.post("/pcap",
                      data={"pcap": (io.BytesIO(self._bytes), "t.pcap")},
                      content_type="multipart/form-data",
                      environ_base={"REMOTE_ADDR": ip})

    def test_pcap_first_upload_ok_then_429_html(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        first = self._upload(c)
        self.assertEqual(first.status_code, 200)
        self.assertIn(b"pcap results", first.data)
        second = self._upload(c)
        self.assertEqual(second.status_code, 429)
        # HTML slow-down page, not the API routes' JSON shape.
        self.assertIn("text/html", second.content_type)
        self.assertIn(b"Slow down", second.data)
        self.assertIsNone(second.get_json(silent=True))
        self.assertIn("Retry-After", second.headers)
        # Retry-After comes from the sliding window, not a static value:
        # with a 1-per-60s cap the wait is positive and at most a minute.
        retry = int(second.headers["Retry-After"])
        self.assertGreaterEqual(retry, 1)
        self.assertLessEqual(retry, 60)
        self.assertIn(str(retry).encode(), second.data)

    def test_pcap_free_fallback_never_limited(self):
        # LLM off: rapid uploads must all pass (limits are 1/min, 2/hr).
        dashm._ai_assist = lambda: _LlmOff()
        c = dashm.app.test_client()
        for _ in range(3):
            r = self._upload(c)
            self.assertEqual(r.status_code, 200)

    def test_pcap_get_form_never_limited_or_recorded(self):
        # GET is the upload form: it spends nothing, so even with the
        # LLM on it stays 200 and leaves the budget untouched.
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        for _ in range(3):
            r = c.get("/pcap", environ_base={"REMOTE_ADDR": "10.8.8.8"})
            self.assertEqual(r.status_code, 200)
        self.assertEqual(self._upload(c).status_code, 200)

    def test_pcap_no_file_redirect_does_not_spend(self):
        # A POST with no file just redirects back to the form; it must
        # not eat budget, so the real upload after it still passes.
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        r = c.post("/pcap", data={},
                   environ_base={"REMOTE_ADDR": "10.8.8.8"})
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._upload(c).status_code, 200)

    def test_pcap_shares_budget_with_ask(self):
        # One budget per IP across the AI routes: spending it on
        # /api/ask leaves nothing for a /pcap upload, and vice versa.
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        r = c.post("/api/ask", json={"question": "anything up?"},
                   environ_base={"REMOTE_ADDR": "10.8.8.9"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self._upload(c, ip="10.8.8.9").status_code, 429)
        self.assertEqual(self._upload(c, ip="10.8.8.10").status_code, 200)
        r = c.post("/api/ask", json={"question": "anything up?"},
                   environ_base={"REMOTE_ADDR": "10.8.8.10"})
        self.assertEqual(r.status_code, 429)

    def test_pcap_different_ips_separate_budgets(self):
        dashm._ai_assist = lambda: _LlmOn()
        c = dashm.app.test_client()
        self.assertEqual(self._upload(c, ip="10.8.8.11").status_code, 200)
        self.assertEqual(self._upload(c, ip="10.8.8.12").status_code, 200)


if __name__ == "__main__":
    unittest.main()
