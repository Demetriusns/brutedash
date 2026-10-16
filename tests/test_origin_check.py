"""Tests for the 2026-10-16 batch: cross-site mutation check.

The dashboard's session cookie gained SameSite=Lax on 2026-10-15, but
Lax is a browser policy, not a server verdict: same-site subdomain
requests still carry the cookie, and any cookie-config regression
would reopen the cross-site path. A before_request gate now rejects
state-changing requests (POST/PUT/PATCH/DELETE) on POSITIVE cross-site
evidence only -- Sec-Fetch-Site: cross-site, or an Origin whose
host:port does not match the request Host (opaque "null" included).
Requests with neither header (curl, probes, the test client) pass:
a non-browser client cannot ride the owner's browser session.

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

_AUTH_ENV = ("BRUTEDASH_AUTH_OWNER_PASSWORD",
             "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD")
OWNER_PW = "owner-secret-pw"
VIEWER_PW = "viewer-secret-pw"
ADD = {"kind": "ip", "pattern": "10.9.9.9"}


def _blocked(case, resp):
    case.assertEqual(resp.status_code, 403)
    body = resp.get_json()
    case.assertFalse(body["ok"])
    case.assertIn("Cross-site request blocked", body["error"])


@unittest.skipIf(dashm is None, "Flask not installed")
class TestOriginCheckOpenMode(ScratchDbTestCase):
    """No passwords configured: the gate alone decides."""

    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _AUTH_ENV}
        for key in _AUTH_ENV:
            os.environ.pop(key, None)
        self.client = dashm.app.test_client()

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        super().tearDown()

    def test_headerless_post_unchanged(self):
        r = self.client.post("/api/allowlist", json=ADD)
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_same_origin_post_allowed(self):
        r = self.client.post("/api/allowlist", json=ADD,
                             headers={"Origin": "http://localhost"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_same_origin_sec_fetch_allowed(self):
        r = self.client.post(
            "/api/allowlist", json=ADD,
            headers={"Origin": "http://localhost",
                     "Sec-Fetch-Site": "same-origin"})
        self.assertEqual(r.status_code, 200)

    def test_cross_site_sec_fetch_blocked(self):
        r = self.client.post("/api/allowlist", json=ADD,
                             headers={"Sec-Fetch-Site": "cross-site"})
        _blocked(self, r)

    def test_mismatched_origin_blocked(self):
        r = self.client.post(
            "/api/allowlist", json=ADD,
            headers={"Origin": "http://evil.example:9999"})
        _blocked(self, r)

    def test_subdomain_origin_blocked_despite_same_site_fetch(self):
        # The Lax bypass this batch exists for: a same-site subdomain
        # still sends the cookie, but its Origin host is not the
        # dashboard's Host, so the server refuses.
        r = self.client.post(
            "/api/allowlist", json=ADD,
            headers={"Origin": "http://sub.localhost",
                     "Sec-Fetch-Site": "same-site"})
        _blocked(self, r)

    def test_opaque_null_origin_blocked(self):
        r = self.client.post("/api/allowlist", json=ADD,
                             headers={"Origin": "null"})
        _blocked(self, r)

    def test_cross_site_get_still_served(self):
        r = self.client.get("/api/stats",
                            headers={"Sec-Fetch-Site": "cross-site",
                                     "Origin": "http://evil.example"})
        self.assertEqual(r.status_code, 200)

    def test_delete_covered(self):
        r = self.client.post("/api/allowlist", json=ADD)
        eid = r.get_json()["id"]
        r = self.client.delete(f"/api/allowlist/{eid}",
                               headers={"Sec-Fetch-Site": "cross-site"})
        _blocked(self, r)
        # The row survived the blocked delete; a clean delete works.
        r = self.client.delete(f"/api/allowlist/{eid}")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])


@unittest.skipIf(dashm is None, "Flask not installed")
class TestOriginCheckWithAuth(ScratchDbTestCase):
    """With passwords on: the gate runs before the login/owner checks."""

    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _AUTH_ENV}
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = OWNER_PW
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = VIEWER_PW
        os.environ.pop("NETMON_PASSWORD", None)
        dashm._LOGIN_ATTEMPTS.clear()

    def tearDown(self):
        dashm._LOGIN_ATTEMPTS.clear()
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        super().tearDown()

    def _login(self, client, pw):
        r = client.post("/login", data={"password": pw})
        self.assertEqual(r.status_code, 302)

    def test_cross_site_post_blocked_even_for_owner(self):
        c = dashm.app.test_client()
        self._login(c, OWNER_PW)
        r = c.post("/api/allowlist", json=ADD,
                   headers={"Sec-Fetch-Site": "cross-site"})
        _blocked(self, r)

    def test_same_origin_post_still_works_for_owner(self):
        c = dashm.app.test_client()
        self._login(c, OWNER_PW)
        r = c.post("/api/allowlist", json=ADD,
                   headers={"Origin": "http://localhost"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])

    def test_viewer_headerless_post_still_owner_checked(self):
        # No cross-site evidence: the request passes this gate and is
        # refused by _owner_required instead -- a different 403.
        c = dashm.app.test_client()
        self._login(c, VIEWER_PW)
        r = c.post("/api/allowlist", json=ADD)
        self.assertEqual(r.status_code, 403)
        self.assertIn("Owner sign-in required", r.get_json()["error"])

    def test_cross_site_login_post_blocked(self):
        c = dashm.app.test_client()
        r = c.post("/login", data={"password": OWNER_PW},
                   headers={"Origin": "http://evil.example"})
        _blocked(self, r)
        with c.session_transaction() as sess:
            self.assertIsNone(sess.get("role"))


if __name__ == "__main__":
    unittest.main()
