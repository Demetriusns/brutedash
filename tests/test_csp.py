"""Tests for the 2026-10-17 batch: Content-Security-Policy on both apps.

The 2026-10-15 security-headers batch explicitly deferred CSP to its own
batch because the dashboard loads external fonts and large inline
scripts/styles. Verified resource profile (2026-10-17): the dashboard's
only external resources are the Fontshare stylesheet
(https://api.fontshare.com) and its font files (https://cdn.fontshare.com,
per Fontshare's own CSS); all ~70 fetch() calls are same-origin relative
paths; pages use inline <script>/<style> and inline onclick handlers, so
script/style keep 'unsafe-inline'. The demo app has no scripts and no
external resources at all, so script-src is 'none' there. Both policies
wall off cross-origin script/connect/object/form/frame targets, and
frame-ancestors 'none' is the modern twin of X-Frame-Options: DENY.

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

_AUTH_ENV = ("BRUTEDASH_AUTH_OWNER_PASSWORD",
             "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD")


def _csp(case, resp):
    value = resp.headers.get("Content-Security-Policy")
    case.assertIsNotNone(value, f"CSP missing on {resp.status_code}")
    directives = {}
    for part in value.split(";"):
        part = part.strip()
        if part:
            name, _, rest = part.partition(" ")
            directives[name] = rest.strip()
    return directives


@unittest.skipIf(dashm is None, "Flask not installed")
class TestDashboardCsp(ScratchDbTestCase):
    def setUp(self):
        super().setUp()
        self._old_env = {k: os.environ.get(k) for k in _AUTH_ENV}
        for key in _AUTH_ENV:  # open-dashboard mode: no gate in the way
            os.environ.pop(key, None)
        self.client = dashm.app.test_client()

    def tearDown(self):
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        super().tearDown()

    def _assert_dashboard_policy(self, resp):
        self.assertEqual(resp.headers.get("Content-Security-Policy"),
                         dashm.DASHBOARD_CSP)
        d = _csp(self, resp)
        self.assertEqual(d["default-src"], "'self'")
        self.assertEqual(d["object-src"], "'none'")
        self.assertEqual(d["frame-ancestors"], "'none'")
        self.assertEqual(d["form-action"], "'self'")
        self.assertEqual(d["connect-src"], "'self'")
        self.assertEqual(d["base-uri"], "'self'")
        # Fontshare is the ONLY external allowance, split by resource
        # type: styles from api, font files from cdn.
        self.assertIn("https://api.fontshare.com", d["style-src"])
        self.assertEqual(d["font-src"],
                         "'self' https://cdn.fontshare.com")
        self.assertNotIn("fontshare", d["script-src"])
        self.assertNotIn("fontshare", d["connect-src"])
        # Inline pages/handlers are the current posture, stated openly.
        self.assertIn("'unsafe-inline'", d["script-src"])
        self.assertIn("'unsafe-inline'", d["style-src"])

    def test_csp_on_dashboard_html(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self._assert_dashboard_policy(r)

    def test_csp_on_api_json(self):
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 200)
        self._assert_dashboard_policy(r)

    def test_csp_on_login_page(self):
        r = self.client.get("/login")
        self.assertEqual(r.status_code, 200)
        self._assert_dashboard_policy(r)


@unittest.skipIf(appm is None, "Flask not installed")
class TestDemoAppCsp(unittest.TestCase):
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

    def _assert_demo_policy(self, resp):
        self.assertEqual(resp.headers.get("Content-Security-Policy"),
                         appm.DEMO_CSP)
        d = _csp(self, resp)
        self.assertEqual(d["default-src"], "'self'")
        # The demo ships no scripts at all: refuse them outright.
        self.assertEqual(d["script-src"], "'none'")
        self.assertEqual(d["object-src"], "'none'")
        self.assertEqual(d["frame-ancestors"], "'none'")
        self.assertEqual(d["form-action"], "'self'")
        self.assertEqual(d["connect-src"], "'self'")
        # No external host is allowed anywhere in the demo policy.
        self.assertNotIn("http", resp.headers["Content-Security-Policy"])

    def test_csp_on_index(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self._assert_demo_policy(r)

    def test_csp_on_history(self):
        r = self.client.get("/history")
        self.assertEqual(r.status_code, 200)
        self._assert_demo_policy(r)

    def test_csp_on_brief_error(self):
        r = self.client.post("/brief", data={"ip": "not-an-ip"})
        self.assertEqual(r.status_code, 400)
        self._assert_demo_policy(r)


if __name__ == "__main__":
    unittest.main()
