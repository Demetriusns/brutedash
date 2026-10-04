"""Tests for the 2026-10-03 bug-fix batch (council review + security review).

Covers, without root/network/Flask where possible:
- B1: notify queue is non-blocking, never raises
- B2: isolated_db + notifications_paused keep pcap analysis out of prod
- B3: env_compat prefix rule (BRUTEDASH_* canonical, NETMON_* warns)
- B4: writability_probe rolls back, no _healthcheck table
- H1: _bind_allowed fail-closed rule
- H2: login rate-limit helpers (needs Flask; skipped if unavailable)
- L3: _clean strips newlines from email fields
- L5: _scrub redacts heartbeat_url
- L6: ensure_bootstrap chmod 600

Run: python -m unittest discover -s tests -v
"""
import io
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import config as cfgm
from netmon import db as dbm
from netmon import notify as notifm
from netmon.health import _scrub
from netmon.run import _bind_allowed

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

try:
    from scapy.all import Ether, IP, TCP, wrpcap  # noqa
    _HAVE_SCAPY = True
except ImportError:
    _HAVE_SCAPY = False


from helpers import fresh_db as _fresh_db, restore_db as _restore_db

class TestEnvCompat(unittest.TestCase):
    def _run(self, env):
        old = dict(os.environ)
        os.environ.clear()
        os.environ.update(env)
        try:
            return cfgm.env_compat("BRUTEDASH_DASHBOARD_PORT", "NETMON_PORT")
        finally:
            os.environ.clear()
            os.environ.update(old)

    def test_new_name_wins(self):
        self.assertEqual(
            self._run({"BRUTEDASH_DASHBOARD_PORT": "9090",
                       "NETMON_PORT": "1234"}), "9090")

    def test_old_name_warns_but_works(self):
        err = io.StringIO()
        old_err = sys.stderr
        sys.stderr = err
        try:
            val = self._run({"NETMON_PORT": "1234"})
        finally:
            sys.stderr = old_err
        self.assertEqual(val, "1234")
        self.assertIn("NETMON_PORT", err.getvalue())
        self.assertIn("deprecated", err.getvalue())

    def test_default_when_neither(self):
        self.assertEqual(self._run({}), "")


class TestBindAllowed(unittest.TestCase):
    def _run(self, host, pw=None):
        old = os.environ.get("NETMON_PASSWORD")
        if pw is None:
            os.environ.pop("NETMON_PASSWORD", None)
        else:
            os.environ["NETMON_PASSWORD"] = pw
        try:
            return _bind_allowed(host)
        finally:
            if old is None:
                os.environ.pop("NETMON_PASSWORD", None)
            else:
                os.environ["NETMON_PASSWORD"] = old

    def test_loopback_always_allowed(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            self.assertTrue(self._run(host), host)

    def test_lan_refused_without_password(self):
        for host in ("0.0.0.0", "192.168.1.10", ""):
            self.assertFalse(self._run(host or "0.0.0.0"), host)

    def test_lan_allowed_with_password(self):
        self.assertTrue(self._run("0.0.0.0", pw="s3cret"))


class TestWritabilityProbe(unittest.TestCase):
    def test_probe_true_and_no_persist(self):
        path, old_path, old_conn = _fresh_db()
        try:
            self.assertTrue(dbm.writability_probe())
            rows = dbm.query("SELECT COUNT(*) FROM meta WHERE key='_probe'")
            self.assertEqual(rows[0][0], 0)
            tables = dbm.query(
                "SELECT name FROM sqlite_master WHERE name='_healthcheck'")
            self.assertEqual(tables, [])
        finally:
            _restore_db(path, old_path, old_conn)


class TestIsolatedDb(unittest.TestCase):
    def test_writes_stay_in_scratch(self):
        prod, old_path, old_conn = _fresh_db()
        scratch = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        scratch.close()
        try:
            dbm.add_alert("test_kind", "Low", "prod alert", "d")
            with dbm.isolated_db(scratch.name):
                # inside: we see the scratch DB (empty), not prod
                rows = dbm.query("SELECT COUNT(*) FROM alerts")
                self.assertEqual(rows[0][0], 0)
                dbm.add_alert("pcap_kind", "High", "pcap alert", "d")
                rows = dbm.query("SELECT COUNT(*) FROM alerts")
                self.assertEqual(rows[0][0], 1)
            # outside: prod has only its own alert
            rows = dbm.query(
                "SELECT kind FROM alerts ORDER BY id")
            self.assertEqual([r[0] for r in rows], ["test_kind"])
        finally:
            _restore_db(prod, old_path, old_conn)
            for _p in (scratch.name, scratch.name + "-wal",
                       scratch.name + "-shm", scratch.name + "-journal"):
                try:
                    os.unlink(_p)
                except OSError:
                    pass

    def test_notifications_paused_suppresses_hook(self):
        calls = []
        orig = notifm.maybe_send_alert
        notifm.maybe_send_alert = lambda a: calls.append(a) or True
        try:
            with dbm.notifications_paused():
                dbm._notify_hook({"kind": "k"})
            self.assertEqual(calls, [])
            dbm._notify_hook({"kind": "k"})
            self.assertEqual(len(calls), 1)
        finally:
            notifm.maybe_send_alert = orig


class TestNotifyQueue(unittest.TestCase):
    def test_queues_without_blocking_or_raising(self):
        # No SMTP configured here: must still return fast, never raise.
        import time
        start = time.time()
        ok = notifm.maybe_send_alert(
            {"severity": "High", "kind": "k", "title": "t"})
        self.assertTrue(ok)
        self.assertLess(time.time() - start, 5)

    def test_rejects_non_sendable(self):
        self.assertFalse(notifm.maybe_send_alert(
            {"severity": "Low", "kind": "k"}))
        self.assertFalse(notifm.maybe_send_alert("not a dict"))
        self.assertFalse(notifm.maybe_send_alert(None))

    def test_clean_strips_newlines(self):
        subject, _body = notifm.build_email(
            {"title": "evil\nHeader: injected", "detail": "a\rb",
             "ts": 1728000000})
        self.assertNotIn("\n", subject)
        self.assertNotIn("\r", subject)

    def test_digest_async_queues(self):
        self.assertTrue(notifm.send_digest_async())


class TestScrubHeartbeat(unittest.TestCase):
    def test_heartbeat_url_redacted(self):
        out = _scrub("heartbeat_url: https://hc.example.com/abc123")
        self.assertNotIn("abc123", out)
        self.assertIn("***", out)

    def test_existing_patterns_still_work(self):
        out = _scrub("password: hunter2")
        self.assertNotIn("hunter2", out)


class TestBootstrapChmod(unittest.TestCase):
    def test_config_created_0600(self):
        d = tempfile.mkdtemp()
        p = os.path.join(d, "config.yaml")
        try:
            from pathlib import Path
            cfgm.ensure_bootstrap(Path(p))
            mode = os.stat(p).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            try:
                os.unlink(p)
                os.rmdir(d)
            except OSError:
                pass

    def test_db_created_0600(self):
        # Council review: netmon.db holds DNS/flow history -- not
        # world-readable. _connect() fixes up perms on open.
        path, old_path, old_conn = _fresh_db()
        try:
            mode = os.stat(path).st_mode & 0o777
            self.assertEqual(mode, 0o600)
        finally:
            _restore_db(path, old_path, old_conn)


class TestAiAssistTimeout(unittest.TestCase):
    def test_openai_client_has_timeout(self):
        # Council review: a hung API call must not wedge the dashboard
        # worker thread (explainer.py already passes timeout=30).
        import types
        from netmon import ai_assist as aam
        captured = {}

        class FakeOpenAI:
            def __init__(self, **kwargs):
                captured.update(kwargs)

        fake = types.ModuleType("openai")
        fake.OpenAI = FakeOpenAI
        old_key = os.environ.get("OPENAI_API_KEY")
        old_mod = sys.modules.get("openai")
        os.environ["OPENAI_API_KEY"] = "sk-test"
        sys.modules["openai"] = fake
        try:
            client = aam._client()
            self.assertIsNotNone(client)
            self.assertEqual(captured.get("timeout"), 30)
        finally:
            if old_key is None:
                os.environ.pop("OPENAI_API_KEY", None)
            else:
                os.environ["OPENAI_API_KEY"] = old_key
            if old_mod is None:
                sys.modules.pop("openai", None)
            else:
                sys.modules["openai"] = old_mod


@unittest.skipIf(dashm is None or not _HAVE_SCAPY,
                 "Flask/scapy not installed")
class TestPcapIsolationEndToEnd(unittest.TestCase):
    """B2: POST /pcap must return 200 while writing nothing to prod and
    queueing no emails."""

    def test_pcap_leaves_prod_untouched(self):
        prod, old_path, old_conn = _fresh_db()
        pcap_path = os.path.join(tempfile.gettempdir(), "t-e2e.pcap")
        try:
            pkts = [Ether() / IP(src="10.0.0.5", dst="10.0.0.1")
                    / TCP(dport=p, flags="S") for p in (22, 23, 445)]
            wrpcap(pcap_path, pkts)
            client = dashm.app.test_client()
            with open(pcap_path, "rb") as f:
                r = client.post("/pcap", data={"pcap": (f, "t.pcap")},
                                content_type="multipart/form-data")
            self.assertEqual(r.status_code, 200)
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM flows")[0][0], 0)
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)
            self.assertEqual(notifm._job_queue.qsize(), 0)
        finally:
            _restore_db(prod, old_path, old_conn)
            try:
                os.unlink(pcap_path)
            except OSError:
                pass


@unittest.skipIf(dashm is None, "Flask not installed")
class TestLoginRateLimit(unittest.TestCase):
    def setUp(self):
        dashm._LOGIN_ATTEMPTS.clear()

    def test_allows_then_blocks(self):
        ip = "10.9.9.9"
        self.assertTrue(dashm._login_allowed(ip))
        for _ in range(5):
            dashm._record_login_failure(ip)
        self.assertFalse(dashm._login_allowed(ip))

    def test_success_clears(self):
        ip = "10.9.9.10"
        for _ in range(5):
            dashm._record_login_failure(ip)
        self.assertFalse(dashm._login_allowed(ip))
        dashm._clear_login_failures(ip)
        self.assertTrue(dashm._login_allowed(ip))

    def test_other_ips_unaffected(self):
        for _ in range(5):
            dashm._record_login_failure("10.9.9.11")
        self.assertTrue(dashm._login_allowed("10.9.9.12"))


if __name__ == "__main__":
    unittest.main()
