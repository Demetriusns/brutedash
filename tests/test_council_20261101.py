"""Council review 2026-11-01 -- shipped batch regression tests.

Batch (head-verified, reproduced by the reviewing seats):

  L1 (security, Low) health._scrub redacted only the first token of a
     secret value: a quoted multi-word passphrase in the diagnostics
     bundle leaked every word after the first. The KV pattern now
     consumes a quoted string whole.
  L2 (security, Low) /reports/compliance.html and .csv were not
     owner-gated while the weekly/incident PDF downloads were. All
     report downloads now follow one owner-only policy.
  L3 (security, Low) /api/health bypassed the password gate and told
     any unauthenticated LAN host when traffic last flowed and
     whether the sensor was stale. It is behind the gate like every
     other data route.
  M3 (robustness, Medium) selfcheck's canary-port exclusion compared
     the protocol string to the port number, so it never excluded
     anything and brutedash's own trap could trip the drift alert.
  M2 (robustness, Medium) capture.run_pcap had no guard around the
     reader loop: a corrupt/wrong-format file raised straight out and
     lost the whole analysis. It now keeps what was aggregated.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import capture as capm
from netmon import config as cfgm
from netmon import health as healthm
from netmon import selfcheck as selfm

from helpers import ScratchDbTestCase
from helpers import fresh_db as _fresh_db, restore_db as _restore_db

try:
    from netmon import dashboard as dashm
except Exception:
    dashm = None


# --- L1: diagnostics scrubbing -------------------------------------------


class ScrubTests(unittest.TestCase):
    def test_multiword_quoted_passphrase_fully_redacted(self):
        out = healthm._scrub('owner_password: "alpha bravo charlie"')
        self.assertNotIn("bravo", out)
        self.assertNotIn("charlie", out)
        self.assertNotIn("alpha", out)

    def test_multiword_json_passphrase_fully_redacted(self):
        out = healthm._scrub('{"password": "alpha bravo charlie"}')
        self.assertNotIn("bravo", out)
        self.assertNotIn("charlie", out)

    def test_single_token_secret_still_redacted(self):
        out = healthm._scrub('api_key: "VALUE9"')
        self.assertNotIn("VALUE9", out)


# --- M3: canary port exclusion --------------------------------------------


class SelfcheckCanaryExclusionTests(ScratchDbTestCase):
    def test_canary_port_excluded_from_current_set(self):
        from netmon import canary as canarym
        trap = 23231
        with mock.patch.object(canarym, "_config",
                               return_value=(True, trap, "127.0.0.1")), \
                mock.patch.object(selfm, "_is_windows",
                                  return_value=False), \
                mock.patch.object(
                    selfm, "_linux_listening_ports",
                    return_value={("TCP", trap), ("TCP", 5001)}):
            status, _, current = selfm.check_listening_ports()
        self.assertEqual(status, "ok")
        self.assertNotIn(("TCP", trap), current)
        self.assertIn(("TCP", 5001), current)


# --- M2: garbage pcap does not crash the analysis --------------------------


@unittest.skipUnless(capm.HAVE_SCAPY, "run_pcap needs scapy")
class PcapGarbageTests(ScratchDbTestCase):
    def test_garbage_pcap_returns_empty_aggregator(self):
        tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
        try:
            tmp.write(b"this is not a capture file at all\n" * 4)
            tmp.close()
            agg = capm.run_pcap(tmp.name)
            self.assertEqual(agg.packets_seen, 0)
        finally:
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


# --- L2 + L3: dashboard gate consistency -----------------------------------


@unittest.skipUnless(dashm is not None, "dashboard module unavailable")
class GateConsistencyTests(unittest.TestCase):
    OWNER_PW = "owner-pw-council-1101"
    VIEWER_PW = "viewer-pw-council-1101"

    def setUp(self):
        self._db = _fresh_db()
        self._old_env = {}
        for key in ("BRUTEDASH_AUTH_OWNER_PASSWORD",
                    "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD"):
            self._old_env[key] = os.environ.get(key)
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = self.OWNER_PW
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = self.VIEWER_PW
        os.environ.pop("NETMON_PASSWORD", None)
        dashm._LOGIN_ATTEMPTS.clear()
        dashm.app.config["TESTING"] = True
        cfgm._CACHE.clear()

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        dashm._LOGIN_ATTEMPTS.clear()
        cfgm._CACHE.clear()
        _restore_db(*self._db)

    def _login_client(self, password):
        c = dashm.app.test_client()
        r = c.post("/login", data={"password": password})
        self.assertEqual(r.status_code, 302)
        return c

    def test_health_requires_signin_when_auth_on(self):
        c = dashm.app.test_client()
        r = c.get("/api/health")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers.get("Location", ""))

    def test_owner_health_still_works(self):
        c = self._login_client(self.OWNER_PW)
        r = c.get("/api/health")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_viewer_cannot_download_compliance_reports(self):
        c = self._login_client(self.VIEWER_PW)
        for url in ("/reports/compliance.html", "/reports/compliance.csv"):
            r = c.get(url)
            self.assertEqual(r.status_code, 403, url)


if __name__ == "__main__":
    unittest.main()
