"""Secret-scrubbing tests for the diagnostics bundle (netmon/health.py).

The bundle is designed to be safe to email to support: no API keys,
passwords, tokens, or other secrets may survive _scrub(). These tests
pin that guarantee. Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from netmon.health import _scrub


class TestScrub(unittest.TestCase):
    def test_api_key_assignment(self):
        self.assertNotIn("sk-abc123",
                         _scrub("openai_api_key=sk-abc123"))

    def test_password_colon(self):
        out = _scrub("dashboard password: s3cr3t!")
        self.assertNotIn("s3cr3t!", out)
        self.assertIn("password=***", out)

    def test_token_equals(self):
        self.assertNotIn("ghp_xyz",
                         _scrub("github_token=ghp_xyz"))

    def test_secret_mixed_case(self):
        self.assertNotIn("hunter2",
                         _scrub("Client_Secret: hunter2"))

    def test_key_with_spaces(self):
        self.assertNotIn("abcdef",
                         _scrub("api key : abcdef"))

    def test_normal_text_untouched(self):
        text = "capture interface: eth0\nport: 8080\nwhole_network: false"
        self.assertEqual(_scrub(text), text)

    def test_word_key_in_normal_sentence_untouched(self):
        # "key" as an English word without a value must survive.
        text = "press any key to continue"
        self.assertEqual(_scrub(text), text)

    def test_multiline_bundle(self):
        bundle = ("config:\n  api_key=sk-live-999\n  port: 8080\n"
                  "log:\n  password = p@ssw0rd\n  ok=true\n")
        out = _scrub(bundle)
        self.assertNotIn("sk-live-999", out)
        self.assertNotIn("p@ssw0rd", out)
        self.assertIn("port: 8080", out)
        self.assertIn("ok=true", out)


if __name__ == "__main__":
    unittest.main()
