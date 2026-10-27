"""Security M1 (2026-10-25 weekly review) -- viewer intel route
burned the AbuseIPDB budget.

GET /api/intel/ip/<ip> had no owner gate on its external calls: any
viewer could enumerate arbitrary IPs, each cache miss costing one
unit of the 50/day AbuseIPDB budget (with the owner's API key in the
header) plus a live reverse-DNS lookup proxied off the box. After 50
IPs the owner's real lookups returned no score for the rest of the
day.

Fix (2026-10-27): external enrichment is owner-only. The handler
computes external_ok = (auth disabled) or (role == owner), passes
include_abuseipdb=external_ok to lookup_ip(), and only calls
reverse_dns() when external_ok. Viewers still get the full local
rap sheet (listed/tags/alerts/flows). Owner and open-mode responses
are unchanged.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import config as cfgm
from netmon import threatintel as tim

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

try:
    from netmon import dashboard as dashm
except Exception:
    dashm = None

_ABUSE = {"score": 90, "country": "Exampleland", "isp": "Example ISP",
          "usage": "Data Center", "asn": "AS64500",
          "domain": "example.com", "reports": 12,
          "last_reported": "2026-10-01T00:00:00+00:00"}


def _fake_lookup(calls):
    def lookup(ip, include_abuseipdb=True):
        calls.append(include_abuseipdb)
        return {"listed": [],
                "abuseipdb": dict(_ABUSE) if include_abuseipdb else None}
    return lookup


@unittest.skipIf(dashm is None, "Flask not installed")
class IntelExternalGateTests(unittest.TestCase):
    OWNER_PW = "owner-pw-intel"
    VIEWER_PW = "viewer-pw-intel"

    def setUp(self):
        self._db = _fresh_db()
        self._old_env = {}
        for key in ("BRUTEDASH_AUTH_OWNER_PASSWORD",
                    "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD"):
            self._old_env[key] = os.environ.get(key)
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

    def _enable_auth(self):
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = self.OWNER_PW
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = self.VIEWER_PW
        os.environ.pop("NETMON_PASSWORD", None)
        cfgm._CACHE.clear()

    def _login_client(self, password):
        c = dashm.app.test_client()
        r = c.post("/login", data={"password": password})
        self.assertEqual(r.status_code, 302)
        return c

    def _get_with_spies(self, client):
        calls, rdns_calls = [], []

        def rdns(ip):
            rdns_calls.append(ip)
            return "host.example.com"

        with mock.patch.object(tim, "lookup_ip", _fake_lookup(calls)), \
                mock.patch.object(tim, "reverse_dns", rdns):
            r = client.get("/api/intel/ip/203.0.113.7")
        return r, calls, rdns_calls

    def test_viewer_gets_local_sheet_without_external_calls(self):
        self._enable_auth()
        c = self._login_client(self.VIEWER_PW)
        r, calls, rdns_calls = self._get_with_spies(c)
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertEqual(d["listed"], [])
        # The budget-burning / off-box calls must not happen.
        self.assertEqual(calls, [False])
        self.assertEqual(rdns_calls, [])
        self.assertNotIn("abuse_score", d)
        self.assertNotIn("reverse_dns", d)

    def test_owner_gets_external_enrichment(self):
        self._enable_auth()
        c = self._login_client(self.OWNER_PW)
        r, calls, rdns_calls = self._get_with_spies(c)
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(calls, [True])
        self.assertEqual(rdns_calls, ["203.0.113.7"])
        self.assertEqual(d["abuse_score"], 90)
        self.assertEqual(d["reverse_dns"], "host.example.com")

    def test_open_mode_is_ungated(self):
        # No passwords configured: existing unauthenticated behaviour.
        for key in ("BRUTEDASH_AUTH_OWNER_PASSWORD",
                    "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD"):
            os.environ.pop(key, None)
        cfgm._CACHE.clear()
        c = dashm.app.test_client()
        r, calls, rdns_calls = self._get_with_spies(c)
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(calls, [True])
        self.assertEqual(rdns_calls, ["203.0.113.7"])
        self.assertEqual(d["abuse_score"], 90)


if __name__ == "__main__":
    unittest.main()
