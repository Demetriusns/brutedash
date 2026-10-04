"""Tests for Phase 3.5 batch 16 (2026-10-04): product.

Three items:

1. Data retention (netmon/retention.py):
   - expired rows pruned per data type, recent rows kept;
   - alerts attached to OPEN/ESCALATED cases are NEVER pruned, even when
     old; alerts on closed cases and unattached old alerts ARE pruned;
   - the incident_alerts mapping rows for pruned alerts are cleaned too;
   - ongoing outages (end_ts NULL) are never pruned;
   - deletes run in bounded batches (LIMIT in the SQL + a multi-batch
     functional test);
   - scheduled maybe_prune respects prune_enabled + the interval;
   - every prune pass logs what was deleted.

2. Sensor-down alerting:
   - loop tick watermark: fresh / stale / unknown (never stale);
   - no pid file -> no loop expected -> never pages;
   - stale tick + pid file -> ONE High self_drift alert per episode,
     cleared on recovery;
   - external heartbeat: pings a mock URL, /fail when sick, non-http(s)
     URLs refused (fail closed, never fetched).

3. Owner/viewer roles (netmon/dashboard.py):
   - login sets the server-side role; wrong passwords rejected;
   - EVERY mutating route (all POST/PUT/DELETE except /login) carries
     @_owner_required (structural: functools __wrapped__) AND returns 403
     for viewers (behavioral);
   - owners are not locked out (representative safe routes);
   - single-password mode: the lone password is the owner, viewer sign-in
     disabled with a clear message on the login page;
   - legacy NETMON_PASSWORD still works as the owner password;
   - session fixation: pre-login session contents are dropped at login;
   - _bind_allowed accepts a viewer password for non-loopback binds;
   - the dashboard renders the "View only" badge for viewers and hides
     owner-only controls;
   - /api/retention is readable by viewers; /api/retention/prune is
     owner-only.

Run: python -m unittest discover -s tests
"""
import contextlib
import http.server
import io
import os
import re
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import config as cfgm
from netmon import retention as retm
from netmon import pipeline as pipelinem
from netmon import health as healthm
from netmon.run import _bind_allowed

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None


# --- scratch-DB harness (same pattern as the other test files) -------------

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

class _DbTest(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)


def _raw_write(sql, params=()):
    """Direct write with commit (dbm.query is read-only, no commit)."""
    with dbm._lock:
        conn = dbm._db()
        conn.execute(sql, params)
        conn.commit()


# --- data retention ----------------------------------------------------------

class RetentionTests(_DbTest):
    def _old_ts(self, days):
        return time.time() - days * 86400

    def _flow(self, ts):
        return (ts, "192.168.1.10", "93.184.216.34", 12345, 443, "tcp",
                10, 5000, "outbound")

    def test_expired_flows_pruned_recent_kept(self):
        dbm.insert_flows([self._flow(self._old_ts(40)),
                          self._flow(self._old_ts(10))])
        counts = retm.prune_once()
        self.assertEqual(counts.get("flows"), 1)
        left = dbm.query("SELECT COUNT(*) FROM flows")[0][0]
        self.assertEqual(left, 1)

    def test_each_configured_type_prunes(self):
        old = self._old_ts(400)
        dbm.insert_dns_queries([(old, "192.168.1.10", "example.com", 1)])
        dbm.insert_arp_observations([(old, "192.168.1.5", "aa:bb:cc:dd:ee:05")])
        _raw_write("INSERT INTO summaries (ts, window_min, headline)"
                   " VALUES (?,?,?)", (old, 15, "old"))
        _raw_write("INSERT INTO outages (target, start_ts, end_ts)"
                   " VALUES (?,?,?)", ("gw", old, old + 60))
        _raw_write("INSERT INTO score_snapshots (day, ts, score)"
                   " VALUES (?,?,?)", ("2020-01-01", old, 80))
        dbm.audit("test", "test", "test", "old audit row")
        counts = retm.prune_once()
        # Literal COUNT queries: the release gate forbids interpolated
        # table names even in tests.
        count_sql = {
            "dns_queries": "SELECT COUNT(*) FROM dns_queries",
            "arp_observations": "SELECT COUNT(*) FROM arp_observations",
            "summaries": "SELECT COUNT(*) FROM summaries",
            "outages": "SELECT COUNT(*) FROM outages",
            "score_snapshots": "SELECT COUNT(*) FROM score_snapshots",
        }
        for table, sql in count_sql.items():
            self.assertEqual(counts.get(table), 1, table)
            self.assertEqual(dbm.query(sql)[0][0], 0, table)
        # The audit trail is append-only by design (batch 9): retention
        # never prunes it, however old the rows are.
        self.assertNotIn("audit_log", counts)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM audit_log")[0][0], 1)

    def test_ongoing_outage_never_pruned(self):
        old = self._old_ts(400)
        _raw_write("INSERT INTO outages (target, start_ts, end_ts)"
                   " VALUES (?,?,?)", ("gw", old, None))
        counts = retm.prune_once()
        self.assertEqual(counts.get("outages"), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM outages")[0][0], 1)

    def test_alerts_on_open_and_escalated_cases_preserved(self):
        with dbm.notifications_paused():
            for status in ("open", "escalated"):
                aid = dbm.add_alert(
                    "port_scan", "High",
                    f"Suspicious activity involving 203.0.113.{7 if status == 'open' else 8}",
                    "detail", ts=self._old_ts(400))
                cases = dbm.list_incidents(status="open")
                self.assertTrue(cases, "alert should open a case")
                if status == "escalated":
                    self.assertTrue(dbm.set_incident_status(cases[0]["id"],
                                                           "escalated"))
        counts = retm.prune_once()
        self.assertEqual(counts.get("alerts"), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 2)

    def test_closed_case_and_unattached_old_alerts_pruned(self):
        # Every alert lands in a case (even a keyless one); closing the
        # case makes its old alerts prunable history.
        with dbm.notifications_paused():
            dbm.add_alert("port_scan", "High",
                          "Suspicious activity involving 203.0.113.9",
                          "detail", ts=self._old_ts(400))
            dbm.add_alert("unusual_port", "Low", "old unattached",
                          "detail", ts=self._old_ts(400))
            for case in dbm.list_incidents(status="open"):
                self.assertTrue(dbm.set_incident_status(case["id"], "closed"))
        counts = retm.prune_once()
        self.assertEqual(counts.get("alerts"), 2)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)
        # The case-mapping rows for pruned alerts are cleaned too.
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM incident_alerts")[0][0], 0)
        # The case rows themselves stay: they are the record, and they
        # are small (one keyed case + one keyless case here).
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM incidents")[0][0], 2)

    def test_prune_runs_in_bounded_batches(self):
        # 2500 expired flows with batch=1000: the pass must loop (3
        # DELETEs) instead of one giant delete. The LIMIT is structural
        # (asserted on the source); this proves the loop terminates and
        # deletes everything.
        rows = [self._flow(self._old_ts(40)) for _ in range(2500)]
        dbm.insert_flows(rows)
        counts = retm.prune_once(batch=1000)
        self.assertEqual(counts.get("flows"), 2500)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM flows")[0][0], 0)

    def test_delete_statements_carry_limit(self):
        # Every prune DELETE must be batch-bounded, and every identifier
        # in the prune SQL must be a module literal (the release gate's
        # B-SQL audit forbids interpolated identifiers).
        for name in ("_PRUNE_SQL", "_PRUNE_ALERT_MAPPINGS", "_PRUNE_ALERTS"):
            sql = getattr(retm, name)
            texts = sql.values() if isinstance(sql, dict) else [sql]
            for text in texts:
                self.assertIn("LIMIT ?", text, name)
                self.assertNotIn("{", text, f"{name}: no interpolation holes")

    def test_prune_logs_what_was_deleted(self):
        dbm.insert_flows([self._flow(self._old_ts(40))])
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            retm.prune_once()
        self.assertIn("netmon retention:", buf.getvalue())
        self.assertIn("flows: 1", buf.getvalue())

    def test_maybe_prune_respects_interval_and_switch(self):
        dbm.set_meta(retm._LAST_RUN_KEY, str(time.time()))
        self.assertIsNone(retm.maybe_prune(),
                          "a fresh last-run must not prune again")
        dbm.set_meta(retm._LAST_RUN_KEY,
                     str(time.time() - 25 * 3600))
        dbm.insert_flows([self._flow(self._old_ts(40))])
        counts = retm.maybe_prune()
        self.assertIsNotNone(counts)
        self.assertEqual(counts.get("flows"), 1)
        # Disabled via config: no prune even when due.
        cfg = {s: dict(keys) for s, keys in cfgm.DEFAULTS.items()}
        cfg["retention"]["prune_enabled"] = False
        dbm.insert_flows([self._flow(self._old_ts(40))])
        dbm.set_meta(retm._LAST_RUN_KEY, str(time.time() - 25 * 3600))
        self.assertIsNone(retm.maybe_prune(cfg=cfg))
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM flows")[0][0], 1)

    def test_last_prune_recorded(self):
        ts, counts = retm.last_prune()
        self.assertIsNone(ts)
        retm.prune_once()
        ts, counts = retm.last_prune()
        self.assertIsNotNone(ts)
        self.assertIsInstance(counts, dict)
        self.assertIn("flows", counts)

    def test_zero_days_disables_that_type(self):
        cfg = {s: dict(keys) for s, keys in cfgm.DEFAULTS.items()}
        cfg["retention"]["flows_days"] = 0
        dbm.insert_flows([self._flow(self._old_ts(400))])
        counts = retm.prune_once(cfg=cfg)
        self.assertNotIn("flows", counts)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM flows")[0][0], 1)


# --- sensor-down alerting: the loop watchdog ----------------------------------

class LoopWatchdogTests(_DbTest):
    def setUp(self):
        super().setUp()
        self._tmpdir = tempfile.mkdtemp()
        self._old_pid_path = pipelinem._loop_pid_path
        pid_path = os.path.join(self._tmpdir, "loop.pid")
        pipelinem._loop_pid_path = lambda: __import__("pathlib").Path(pid_path)
        self._pid_path = pid_path
        # The scratch DB lives on a tmpfs with <512MB free: without this,
        # the disk-pressure suppressor (correctly) silences the watchdog.
        self._disk_patcher = mock.patch.object(
            pipelinem, "disk_pressure", return_value=False)
        self._disk_patcher.start()

    def tearDown(self):
        self._disk_patcher.stop()
        pipelinem._loop_pid_path = self._old_pid_path
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        super().tearDown()

    def _write_pid(self):
        pipelinem.write_loop_pid()
        self.assertTrue(os.path.exists(self._pid_path))

    def test_no_pid_file_never_pages(self):
        down, _ = pipelinem.check_loop_down()
        self.assertFalse(down)
        self.assertFalse(pipelinem.check_and_alert_loop_down())
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

    def test_fresh_tick_is_healthy(self):
        self._write_pid()
        pipelinem.note_loop_tick()
        down, _ = pipelinem.check_loop_down()
        self.assertFalse(down)
        self.assertIs(pipelinem.loop_tick_fresh(), True)

    def test_missing_tick_is_unknown_never_stale(self):
        self._write_pid()
        self.assertIsNone(pipelinem.loop_tick_fresh())
        down, _ = pipelinem.check_loop_down()
        self.assertFalse(down,
                         "a loop that never ticked must not page on day one")

    def test_stale_tick_alerts_once_per_episode(self):
        self._write_pid()
        pipelinem.note_loop_tick(time.time() - 20 * 60)
        self.assertTrue(pipelinem.check_and_alert_loop_down())
        rows = dbm.query(
            "SELECT severity, kind FROM alerts WHERE kind='self_drift'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "High")
        # Second check: still down, but no second alert (one per episode).
        self.assertTrue(pipelinem.check_and_alert_loop_down())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")[0][0],
            1)

    def test_recovery_clears_the_episode(self):
        self._write_pid()
        pipelinem.note_loop_tick(time.time() - 20 * 60)
        self.assertTrue(pipelinem.check_and_alert_loop_down())
        pipelinem.note_loop_tick()  # the loop is back
        self.assertFalse(pipelinem.check_and_alert_loop_down())
        self.assertFalse(dbm.get_meta(pipelinem._LOOP_DOWN_FLAG))
        # A new outage alerts anew.
        pipelinem.note_loop_tick(time.time() - 20 * 60)
        self.assertTrue(pipelinem.check_and_alert_loop_down())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")[0][0],
            2)

    def test_clean_shutdown_removes_pid_file(self):
        self._write_pid()
        pipelinem.clear_loop_pid()
        self.assertFalse(os.path.exists(self._pid_path))
        pipelinem.note_loop_tick(time.time() - 20 * 60)
        down, _ = pipelinem.check_loop_down()
        self.assertFalse(down,
                         "a cleanly-stopped loop must not page")

    def test_disk_pressure_suppresses_loop_down(self):
        # A full disk can break the tick write itself; the disk-full
        # self-alert owns that episode, not a misleading "loop stopped".
        self._write_pid()
        pipelinem.note_loop_tick(time.time() - 20 * 60)
        with mock.patch.object(pipelinem, "disk_pressure",
                               return_value=True):
            down, _ = pipelinem.check_loop_down()
            self.assertFalse(down)
            self.assertFalse(pipelinem.check_and_alert_loop_down())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

    def test_alert_copy_is_plain_spoken(self):
        title = pipelinem._SELF_COPY["loop"][0]
        self.assertNotIn("doctor", title.lower())
        self.assertIn("stopped", title.lower())


# --- sensor-down alerting: the external heartbeat ------------------------------

class _PingRecorder(http.server.BaseHTTPRequestHandler):
    paths = []

    def do_GET(self):
        type(self).paths.append(self.path)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *args):
        pass


class HeartbeatTests(unittest.TestCase):
    def setUp(self):
        _PingRecorder.paths = []
        self._server = http.server.HTTPServer(("127.0.0.1", 0),
                                             _PingRecorder)
        self._port = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever,
                                        daemon=True)
        self._thread.start()

    def tearDown(self):
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=5)

    def _url(self):
        return f"http://127.0.0.1:{self._port}/pingkey123"

    def test_healthy_ping_hits_root(self):
        hb = healthm.Heartbeat(self._url(), 60,
                               health_fn=lambda: (True, "ok"))
        hb._ping_once()
        self.assertIn("/pingkey123", _PingRecorder.paths)

    def test_sick_ping_hits_fail_path(self):
        hb = healthm.Heartbeat(self._url(), 60,
                               health_fn=lambda: (False, "capture died"))
        hb._ping_once()
        self.assertIn("/pingkey123/fail", _PingRecorder.paths)

    def test_scheme_allowlist(self):
        self.assertTrue(healthm._heartbeat_url_ok("https://hc.example/x"))
        self.assertTrue(healthm._heartbeat_url_ok("http://127.0.0.1:1/x"))
        for bad in ("ftp://127.0.0.1/x", "file:///etc/passwd", "",
                    "gopher://x", "httpss://x"):
            self.assertFalse(healthm._heartbeat_url_ok(bad), bad)

    def test_non_http_url_is_never_fetched(self):
        with mock.patch("urllib.request.urlopen") as mock_open:
            hb = healthm.Heartbeat("ftp://127.0.0.1:9/pingkey", 5)
            hb.run()  # returns immediately: scheme check fails first
            mock_open.assert_not_called()

    def test_empty_url_is_disabled(self):
        hb = healthm.Heartbeat("", 5)
        hb.run()  # must return immediately, not block
        self.assertEqual(_PingRecorder.paths, [])


# --- owner/viewer roles ---------------------------------------------------------

OWNER_PW = "owner-secret-pw"
VIEWER_PW = "viewer-secret-pw"

# Mutating routes whose owner-side live fire has heavy side effects
# (network fetches, LAN scans, email sends). The viewer-403 direction is
# still asserted for every one of them; the owner direction is covered by
# the structural check (functools __wrapped__) instead.
_HEAVY_OWNER_SKIP = {
    "/api/intel/refresh",
    "/api/scan/run",
    "/api/nuclei/run",
    "/api/amass/run",
    "/api/devices/quarantine",
    "/api/devices/quarantine/release",
    "/api/incidents/<int:iid>/escalate",
    "/pcap",
}


@unittest.skipIf(dashm is None, "Flask not installed")
class RoleTests(_DbTest):
    """Dashboard roles: owner (everything) vs viewer (read-only)."""

    def setUp(self):
        super().setUp()
        self._old_env = {}
        for key in ("BRUTEDASH_AUTH_OWNER_PASSWORD",
                    "BRUTEDASH_AUTH_VIEWER_PASSWORD", "NETMON_PASSWORD"):
            self._old_env[key] = os.environ.get(key)
        os.environ["BRUTEDASH_AUTH_OWNER_PASSWORD"] = OWNER_PW
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = VIEWER_PW
        os.environ.pop("NETMON_PASSWORD", None)
        dashm._LOGIN_ATTEMPTS.clear()
        # Keep the loop watchdog away from the real config dir.
        self._tmpdir = tempfile.mkdtemp()
        self._old_pid_path = pipelinem._loop_pid_path
        pid_path = os.path.join(self._tmpdir, "loop.pid")
        pipelinem._loop_pid_path = lambda: __import__("pathlib").Path(pid_path)

    def tearDown(self):
        pipelinem._loop_pid_path = self._old_pid_path
        import shutil
        shutil.rmtree(self._tmpdir, ignore_errors=True)
        for key, val in self._old_env.items():
            if val is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = val
        dashm._LOGIN_ATTEMPTS.clear()
        super().tearDown()

    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def _login(self, client, password):
        return client.post("/login", data={"password": password})

    def _role_of(self, client):
        with client.session_transaction() as sess:
            return sess.get("role")

    # -- login & roles --

    def test_owner_login_sets_owner_role(self):
        c = self._client()
        r = self._login(c, OWNER_PW)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._role_of(c), "owner")

    def test_viewer_login_sets_viewer_role(self):
        c = self._client()
        r = self._login(c, VIEWER_PW)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._role_of(c), "viewer")

    def test_wrong_password_rejected(self):
        c = self._client()
        r = self._login(c, "nope")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"Wrong password", r.data)
        self.assertIsNone(self._role_of(c))

    def test_login_drops_prelogin_session(self):
        # Session fixation: anything planted before login is gone after.
        c = self._client()
        with c.session_transaction() as sess:
            sess["planted"] = "evil"
        self._login(c, OWNER_PW)
        with c.session_transaction() as sess:
            self.assertNotIn("planted", sess)
            self.assertEqual(sess.get("role"), "owner")

    def test_rate_limit_still_applies(self):
        c = self._client()
        for _ in range(6):
            r = self._login(c, "wrong")
        self.assertEqual(r.status_code, 429)

    # -- single-password mode --

    def test_single_password_is_owner_viewer_disabled(self):
        os.environ.pop("BRUTEDASH_AUTH_VIEWER_PASSWORD", None)
        c = self._client()
        r = c.get("/login")
        self.assertIn(b"Viewer sign-in isn", r.data)
        r = self._login(c, OWNER_PW)
        self.assertEqual(r.status_code, 302)
        self.assertEqual(self._role_of(c), "owner")

    def test_legacy_netmon_password_is_owner(self):
        os.environ.pop("BRUTEDASH_AUTH_OWNER_PASSWORD", None)
        os.environ.pop("BRUTEDASH_AUTH_VIEWER_PASSWORD", None)
        os.environ["NETMON_PASSWORD"] = "legacy-pw"
        try:
            c = self._client()
            r = self._login(c, "legacy-pw")
            self.assertEqual(r.status_code, 302)
            self.assertEqual(self._role_of(c), "owner")
        finally:
            os.environ.pop("NETMON_PASSWORD", None)

    def test_bind_allowed_accepts_viewer_password(self):
        os.environ.pop("BRUTEDASH_AUTH_OWNER_PASSWORD", None)
        os.environ["BRUTEDASH_AUTH_VIEWER_PASSWORD"] = VIEWER_PW
        # A lone viewer password promotes to owner (single-password rule).
        self.assertTrue(_bind_allowed("0.0.0.0"))
        os.environ.pop("BRUTEDASH_AUTH_VIEWER_PASSWORD", None)
        self.assertFalse(_bind_allowed("0.0.0.0"))
        self.assertTrue(_bind_allowed("127.0.0.1"))

    # -- the audit: every mutating route requires the owner --

    def _mutating_routes(self):
        """(rule, endpoint, methods) for every route accepting POST/PUT/DELETE,
        except the login itself. Endpoint-level (not rule-level): GET and
        POST on the same path are different view functions. This is the
        audit list: if a future batch adds a mutating route without
        @_owner_required, the tests below fail."""
        out = []
        for rule in dashm.app.url_map.iter_rules():
            if rule.rule == "/login":
                continue
            mut = [m for m in (rule.methods or ())
                   if m in ("POST", "PUT", "DELETE")]
            if mut:
                out.append((rule.rule, rule.endpoint, mut))
        return sorted(out)

    def _concrete_url(self, rule):
        url = re.sub(r"<int:(aid|iid|eid|sid)>", "999991", rule)
        url = re.sub(r"<(int:)?[^>]+>", "x", url)
        return url

    def test_every_mutating_route_has_owner_decorator(self):
        missing = []
        for rule, endpoint, _methods in self._mutating_routes():
            view = dashm.app.view_functions[endpoint]
            if not hasattr(view, "__wrapped__"):
                missing.append(f"{rule} ({endpoint})")
        self.assertEqual(missing, [],
                         f"routes without @_owner_required: {missing}")

    def test_viewer_gets_403_on_every_mutating_route(self):
        c = self._client()
        self._login(c, VIEWER_PW)
        self.assertEqual(self._role_of(c), "viewer")
        failures = []
        for rule, _endpoint, methods in self._mutating_routes():
            url = self._concrete_url(rule)
            for method in methods:
                if method == "DELETE":
                    r = c.delete(url)
                else:
                    r = c.post(url, json={})
                if r.status_code != 403:
                    failures.append(f"{method} {url} -> {r.status_code}")
        self.assertEqual(failures, [],
                         f"viewer not blocked: {failures}")

    def test_owner_not_locked_out_of_safe_routes(self):
        c = self._client()
        self._login(c, OWNER_PW)
        self.assertEqual(self._role_of(c), "owner")
        with dbm.notifications_paused():
            aid = dbm.add_alert("port_scan", "Low", "audit probe",
                                "detail")
        failures = []
        for rule, _endpoint, methods in self._mutating_routes():
            if rule in _HEAVY_OWNER_SKIP:
                continue
            url = self._concrete_url(rule)
            for method in methods:
                if method == "DELETE":
                    r = c.delete(url)
                else:
                    r = c.post(url, json={})
                if r.status_code == 403:
                    failures.append(f"{method} {url} -> 403 for owner")
        self.assertEqual(failures, [],
                         f"owner locked out: {failures}")

    def test_unauthenticated_redirects_to_login(self):
        c = self._client()
        r = c.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertIn("/login", r.headers["Location"])
        r = c.post("/api/alerts/1/ack", json={})
        self.assertEqual(r.status_code, 302)

    # -- viewer UI --

    def test_viewer_dashboard_shows_badge_and_hides_controls(self):
        c = self._client()
        self._login(c, VIEWER_PW)
        r = c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"View only", r.data)
        self.assertIn(b'class="viewonly"', r.data)
        self.assertIn(b'var ORION_ROLE = "viewer"', r.data)

    def test_owner_dashboard_has_no_viewer_badge(self):
        c = self._client()
        self._login(c, OWNER_PW)
        r = c.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertNotIn(b"View only", r.data)
        self.assertIn(b'var ORION_ROLE = "owner"', r.data)

    def test_viewer_ask_and_pcap_pages_refuse(self):
        c = self._client()
        self._login(c, VIEWER_PW)
        self.assertEqual(c.get("/ask").status_code, 403)
        self.assertEqual(c.get("/pcap").status_code, 403)

    def test_owner_ask_and_pcap_pages_open(self):
        c = self._client()
        self._login(c, OWNER_PW)
        self.assertEqual(c.get("/ask").status_code, 200)
        self.assertEqual(c.get("/pcap").status_code, 200)

    # -- retention endpoints respect roles --

    def test_retention_status_readable_by_viewer(self):
        c = self._client()
        self._login(c, VIEWER_PW)
        r = c.get("/api/retention")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("flows_days", data["policy"])
        self.assertEqual(data["policy"]["flows_days"], 30)
        self.assertEqual(data["policy"]["alerts_days"], 365)

    def test_retention_prune_owner_only(self):
        viewer = self._client()
        self._login(viewer, VIEWER_PW)
        r = viewer.post("/api/retention/prune")
        self.assertEqual(r.status_code, 403)
        owner = self._client()
        self._login(owner, OWNER_PW)
        r = owner.post("/api/retention/prune")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])


if __name__ == "__main__":
    unittest.main()
