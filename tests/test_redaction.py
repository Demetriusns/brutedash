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

    # Council review: _scrub used to miss these real secret shapes.

    def test_quoted_json_password(self):
        out = _scrub('{"password": "VALUE9"}')
        self.assertNotIn("VALUE9", out)

    def test_env_pass_name(self):
        out = _scrub("NETMON_SMTP_PASS=VALUE9")
        self.assertNotIn("VALUE9", out)

    def test_bare_pass_colon(self):
        out = _scrub("pass: VALUE9")
        self.assertNotIn("VALUE9", out)

    def test_url_userinfo(self):
        out = _scrub("https://user:VALUE9@host/x")
        self.assertNotIn("VALUE9", out)
        self.assertIn("https://user:***@host/x", out)

    def test_authorization_header(self):
        out = _scrub("Authorization: Basic VALUE9")
        self.assertNotIn("VALUE9", out)
        out = _scrub("Authorization: Bearer tok123")
        self.assertNotIn("tok123", out)

    def test_url_with_port_untouched(self):
        # No userinfo: the port must survive (no over-redaction).
        text = "http://192.168.1.1:8080/status"
        self.assertEqual(_scrub(text), text)


if __name__ == "__main__":
    unittest.main()
