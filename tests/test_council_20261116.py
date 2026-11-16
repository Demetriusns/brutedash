"""Council review 2026-11-15 residuals -- shipped 2026-11-16.

Batch (security seat, both Low, head-verified at HEAD 58740f3):

  S3-residual -- health._scrub redacted only the first word of an
     UNQUOTED secret value (the fallback alternative was \\S+), so a
     YAML plain multi-word passphrase in the config / log tail leaked
     every word after the first into the shareable diagnostics
     bundle. The fallback now consumes to end-of-line; it only fires
     after a known secret keyword, and the bundle's standing rule is
     that over-redaction on that line beats a leak. Quoted values
     (quote-specific, escape-aware since 2026-11-09) are untouched.
  S4-residual -- envscrub's marker list missed HEARTBEAT / WEBHOOK /
     AUTH / CREDENTIAL / PRIVATE, so BRUTEDASH_MONITOR_HEARTBEAT_URL
     (a capability URL: holding it can ping/fail the health check)
     and any future *_AUTH / *_CREDENTIAL / *_WEBHOOK_* variable
     passed untouched to the nuclei/amass scanner subprocesses.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon.envscrub import is_secret_name, scrubbed_env
from netmon.health import _scrub


class ScrubUnquotedMultiwordTests(unittest.TestCase):
    def test_unquoted_multiword_passphrase_fully_redacted(self):
        out = _scrub("password: hunter two words")
        self.assertNotIn("hunter", out)
        self.assertNotIn("two", out)
        self.assertNotIn("words", out)

    def test_unquoted_apostrophe_passphrase_fully_redacted(self):
        # The exact shape reproduced by the 2026-11-15 security seat.
        out = _scrub("password: don't tell")
        self.assertNotIn("tell", out)

    def test_unquoted_env_assignment_trailing_words_redacted(self):
        out = _scrub("NETMON_SMTP_PASS=abc123 extra words")
        self.assertNotIn("abc123", out)
        self.assertNotIn("extra", out)
        self.assertNotIn("words", out)

    def test_unquoted_colon_value_trailing_words_redacted(self):
        out = _scrub("api_key: abc def ghi")
        for word in ("abc", "def", "ghi"):
            self.assertNotIn(word, out)

    def test_redaction_stops_at_end_of_line(self):
        # Per-line scope: the NEXT lines of the bundle survive intact.
        bundle = "password: hunter two words\nport: 8080\nok=true\n"
        out = _scrub(bundle)
        self.assertNotIn("hunter", out)
        self.assertIn("port: 8080", out)
        self.assertIn("ok=true", out)

    def test_non_secret_lines_untouched(self):
        # The fallback only fires after a known secret keyword.
        text = "capture interface: eth0\nport: 8080\nwhole_network: false"
        self.assertEqual(_scrub(text), text)
        self.assertEqual(_scrub("press any key to continue"),
                         "press any key to continue")
        self.assertEqual(_scrub("http://192.168.1.1:8080/status"),
                         "http://192.168.1.1:8080/status")

    def test_quoted_value_still_fully_redacted(self):
        out = _scrub('owner_password: "don\'t tell anyone"')
        self.assertNotIn("tell", out)
        self.assertNotIn("anyone", out)

    def test_single_token_secret_still_redacted(self):
        out = _scrub("password: hunter2")
        self.assertNotIn("hunter2", out)
        self.assertIn("password=***", out)


class EnvscrubResidualMarkerTests(unittest.TestCase):
    def test_new_markers_are_secret_names(self):
        for name in ("BRUTEDASH_MONITOR_HEARTBEAT_URL",
                     "HEARTBEAT_URL",
                     "APP_WEBHOOK_URL",
                     "WEBHOOK_SECRET_URL",
                     "SERVICE_AUTH",
                     "OAUTH_CLIENT",
                     "DB_CREDENTIAL",
                     "APP_CREDENTIALS_FILE",
                     "MY_PRIVATE",
                     "PRIVATE_DATA"):
            self.assertTrue(is_secret_name(name), name)

    def test_plain_names_still_pass(self):
        for name in ("PATH", "HOME", "SystemRoot", "LANG",
                     "BRUTEDASH_HOME", "NETMON_WHOLE_NETWORK"):
            self.assertFalse(is_secret_name(name), name)

    def test_scrubbed_env_strips_heartbeat_keeps_rest(self):
        env_in = {"PATH": "/usr/bin:/bin",
                  "BRUTEDASH_MONITOR_HEARTBEAT_URL": "https://hc/x",
                  "ZZ_WEBHOOK_URL": "https://hook/x",
                  "ZZ_CREDENTIAL": "cred",
                  "ZZ_PLAIN": "keepme"}
        with mock.patch.dict(os.environ, env_in, clear=True):
            env = scrubbed_env()
        self.assertEqual(env, {"PATH": "/usr/bin:/bin",
                               "ZZ_PLAIN": "keepme"})


if __name__ == "__main__":
    unittest.main()
