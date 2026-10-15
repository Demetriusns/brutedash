"""Tests for the 2026-10-15 batch: security headers + cookie hardening.

Neither Flask app set any browser security headers, and the dashboard
session cookie had no explicit SameSite. Now every response from both
apps carries X-Content-Type-Options: nosniff, X-Frame-Options: DENY and
Referrer-Policy: no-referrer, and the dashboard session cookie is
HttpOnly + SameSite=Lax (Secure deliberately unset -- the dashboard
binds LAN/localhost over plain HTTP, so a Secure cookie would never
be sent and sign-in would break). SameSite=Lax keeps the cookie off
cross-site POSTs, which is every mutating route, while top-level GET
navigation (links to the dashboard) still carries it.

Run: python -m unittest discover -s tests -v
"""
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
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None

from helpers import ScratchDbTestCase

HEADERS = {
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
}

_AUTH_ENV = ("BRUTEDASH_AUTH_OWNER_PASSWORD",
             "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD")
OWNER_PW = "owner-secret-pw"


def _assert_headers(case, resp):
    for name, value in HEADERS.items():
        case.assertEqual(resp.headers.get(name), value,
                         f"{name} missing/wrong on {resp.status_code}")


@unittest.skipIf(dashm is None, "Flask not installed")
class TestDashboardHeaders(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _AUTH_ENV}
        for key in _AUTH_ENV:  # open-dashboard mode: no gate in the way
            os.environ.pop(key, None)

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        super().tearDown()

    def test_headers_on_dashboard_html(self):
        r = dashm.app.test_client().get("/")
        self.assertEqual(r.status_code, 200)
        _assert_headers(self, r)
        # The pre-existing no-cache behavior for HTML is unchanged.
        self.assertIn("no-store", r.headers.get("Cache-Control", ""))

    def test_headers_on_api_json(self):
        r = dashm.app.test_client().get("/api/stats")
        self.assertEqual(r.status_code, 200)
        _assert_headers(self, r)

    def test_headers_on_login_page(self):
        r = dashm.app.test_client().get("/login")
        self.assertEqual(r.status_code, 200)
        _assert_headers(self, r)

    def test_cookie_config(self):
        self.assertTrue(dashm.app.config["SESSION_COOKIE_HTTPONLY"])
        self.assertEqual(dashm.app.config["SESSION_COOKIE_SAMESITE"],
                         "Lax")
        # Secure must stay off or LAN/localhost HTTP sign-in breaks.
        self.assertFalse(dashm.app.config.get("SESSION_COOKIE_SECURE"))


@unittest.skipIf(dashm is None, "Flask not installed")
class TestDashboardLoginCookie(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _AUTH_ENV}
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = OWNER_PW
        os.environ.pop("BRUTEDASH_AUTH_VIEWER_PASSWORD", None)
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

    def test_login_still_works_and_cookie_is_hardened(self):
        c = dashm.app.test_client()
        r = c.post("/login", data={"password": OWNER_PW})
        self.assertEqual(r.status_code, 302)  # signed in, sent home
        _assert_headers(self, r)
        cookie = r.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Lax", cookie)
        self.assertNotIn("Secure", cookie)
        with c.session_transaction() as sess:
            self.assertEqual(sess.get("role"), "owner")

    def test_auth_gate_redirect_carries_headers(self):
        r = dashm.app.test_client().get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        _assert_headers(self, r)


@unittest.skipIf(appm is None, "Flask not installed")
class TestDemoAppHeaders(unittest.TestCase):
    def setUp(self):
        # Point the demo app at a throwaway DB so /history never
        # touches the repo's real detections.db.
        fd, self._db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._old_db_path = appm.DB_PATH
        appm.DB_PATH = self._db_path
        self.client = appm.app.test_client()

    def tearDown(self):
        appm.DB_PATH = self._old_db_path
        try:
            os.unlink(self._db_path)
        except OSError:
            pass

    def test_headers_on_index(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        _assert_headers(self, r)

    def test_headers_on_history(self):
        r = self.client.get("/history")
        self.assertEqual(r.status_code, 200)
        _assert_headers(self, r)

    def test_headers_on_brief_error(self):
        r = self.client.post("/brief", data={"ip": "not-an-ip"})
        self.assertEqual(r.status_code, 400)
        _assert_headers(self, r)


if __name__ == "__main__":
    unittest.main()
