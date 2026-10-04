"""Tests for the Phase 3.5 batch 14 pipeline-robustness work
(repo-learning item 4: failure-mode enumeration + fallback chains +
trace_id observability).

Covers, without root/network where possible:
- trace_id minted at rule-fire time, well-formed, caller-supplied ids
  honored, propagated alert -> incident -> notify hook, backfilled on
  old rows, and NEVER present in outgoing emails.
- DB write retry: transient "database is locked" retried with backoff,
  strictly bounded (no retry storms), non-lock errors raise at once;
  add_alert survives a transient lock at the integration level.
- Feed refresh failure: cached feed keeps serving, staleness is
  reported (per-feed "stale" + global failed_recently), success clears
  the flag.
- LLM unavailable: triage_verdict returns a labeled rule-based take
  (never None, never raises); answer_question says so plainly.
- Capture watchdog: dead thread restarted, bounded per hour, window
  slides clear, start failures counted.
- Disk guard: pressure pauses non-essentials (signaled), one self-alert
  per episode ("self_drift"), recovery re-arms; stat failure is not
  pressure; detection still runs under pressure.
- Watermarks: stale stage -> one self-alert then quiet; unknown stage
  (fresh install) never pages; recovery clears flags; rule-pass
  failure streak alerts at 3 and resets on success.
- detect.run_all: one crashing rule doesn't cancel the pass.
- Dashboard: /api/pipeline_health shape, trace_id on /api/stats
  alerts, intel status staleness fields.

Scratch DBs only; every test cleans up its /tmp files (db, -wal, -shm)
in tearDown -- the suite has filled /tmp with leaked WAL files before.

Run: python -m unittest discover -s tests -v
"""
import contextlib
import io
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import pipeline as pipelinem
from netmon import notify as notifm
from netmon import threatintel as tim
from netmon import ai_assist as assistm
from netmon import detect as detm

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

_TRACE_RE = re.compile(r"^[0-9a-f]{32}$")


from helpers import fresh_db as _fresh_db, restore_db as _restore_db

class _ScratchDbTest(unittest.TestCase):
    def setUp(self):
        self.path, self.old_path, self.old_conn = _fresh_db()

    def tearDown(self):
        _restore_db(self.path, self.old_path, self.old_conn)
        for p in (self.path, self.path + "-wal", self.path + "-shm"):
            self.assertFalse(os.path.exists(p),
                             f"scratch file leaked: {p}")


# --- trace_id ---------------------------------------------------------------

class TraceIdTests(_ScratchDbTest):
    def test_trace_id_minted_and_well_formed(self):
        with dbm.notifications_paused():
            aid = dbm.add_alert("port_scan", "Low", "t", "d")
        alert = dbm.get_alert(aid)
        self.assertTrue(_TRACE_RE.match(alert["trace_id"] or ""),
                        f"bad trace_id: {alert['trace_id']!r}")
        self.assertTrue(pipelinem.is_trace_id(alert["trace_id"]))
        self.assertFalse(pipelinem.is_trace_id("not-an-id"))
        self.assertFalse(pipelinem.is_trace_id(None))

    def test_trace_id_unique_per_alert(self):
        with dbm.notifications_paused():
            a1 = dbm.add_alert("port_scan", "Low", "t1", "d")
            a2 = dbm.add_alert("port_scan", "Low", "t2", "d")
        self.assertNotEqual(dbm.get_alert(a1)["trace_id"],
                            dbm.get_alert(a2)["trace_id"])

    def test_caller_supplied_trace_id_honored(self):
        tid = "ab" * 16
        with dbm.notifications_paused():
            aid = dbm.add_alert("port_scan", "Low", "t", "d",
                                trace_id=tid)
        self.assertEqual(dbm.get_alert(aid)["trace_id"], tid)

    def test_trace_id_propagates_alert_to_incident_to_notify(self):
        seen = {}

        def _hook(alert):
            seen.update(alert)
            return False

        with mock.patch.object(notifm, "maybe_send_alert",
                               side_effect=_hook):
            aid = dbm.add_alert("port_scan", "High",
                                "Port scan from 93.184.216.34",
                                "93.184.216.34 knocked on 50 ports.")
        tid = dbm.get_alert(aid)["trace_id"]
        # incident leg: the case timeline carries the same id
        incidents = dbm.list_incidents()
        self.assertTrue(incidents)
        case = dbm.get_incident(incidents[0]["id"])
        member_ids = [a["trace_id"] for a in case["alerts"]]
        self.assertIn(tid, member_ids)
        # notify leg: the hook dict carries the id
        self.assertEqual(seen.get("trace_id"), tid)
        self.assertEqual(seen.get("id"), aid)

    def test_trace_id_backfilled_for_old_rows(self):
        # Rows predating the column (NULL trace_id) get one on connect.
        conn = dbm._db()
        conn.execute(
            "INSERT INTO alerts (ts, kind, severity, title, detail)"
            " VALUES (?,?,?,?,?)",
            (time.time(), "port_scan", "Low", "old", "old row"))
        conn.execute("UPDATE alerts SET trace_id=NULL")
        conn.commit()
        try:
            conn.close()
        except Exception:
            pass
        dbm._conn = None  # force _connect (and its backfill) to rerun
        row = dbm.query("SELECT trace_id FROM alerts")[0][0]
        self.assertTrue(_TRACE_RE.match(row or ""),
                        f"backfill missed: {row!r}")

    def test_trace_id_never_in_outgoing_emails(self):
        tid = "cd" * 16
        alert = {"id": 7, "severity": "High", "title": "Port scan",
                 "detail": "93.184.216.34 knocked.", "meaning": "m",
                 "is_normal": "n", "what_to_do": "w",
                 "ts": time.time(), "trace_id": tid}
        subject, body = notifm.build_email(alert)
        self.assertNotIn(tid, subject)
        self.assertNotIn(tid, body)
        esub, ebody = notifm.build_escalation_email(alert, "port_scan")
        self.assertNotIn(tid, esub)
        self.assertNotIn(tid, ebody)
        dsub, dbody = notifm.build_digest(
            [("port_scan", "High", "Port scan", "d", time.time())])
        self.assertNotIn(tid, dsub)
        self.assertNotIn(tid, dbody)
        # The escalation bundle renders alert dicts with explicit keys
        # only -- a trace_id on the row must not reach the admin email.
        from netmon import escalate as escm
        with dbm.notifications_paused():
            aid = dbm.add_alert("port_scan", "High",
                                "Port scan from 93.184.216.34",
                                "93.184.216.34 knocked.", trace_id=tid)
        incident_id = dbm.list_incidents()[0]["id"]
        bundle = escm.build_escalation_email(
            escm.build_escalation_bundle(incident_id))
        self.assertNotIn(tid, bundle[0])
        self.assertNotIn(tid, bundle[1])


# --- DB write retry ------------------------------------------------------------

class DbRetryTests(_ScratchDbTest):
    def test_retry_succeeds_after_transient_locks(self):
        calls = {"n": 0}

        def _flaky():
            calls["n"] += 1
            if calls["n"] <= 2:
                raise sqlite3.OperationalError("database is locked")
            return "ok"

        self.assertEqual(dbm._write_with_retry(_flaky), "ok")
        self.assertEqual(calls["n"], 3)

    def test_retry_bounded_on_persistent_lock(self):
        calls = {"n": 0}

        def _stuck():
            calls["n"] += 1
            raise sqlite3.OperationalError("database is locked")

        with self.assertRaises(sqlite3.OperationalError):
            dbm._write_with_retry(_stuck)
        # Strictly bounded: exactly _DB_RETRY_MAX attempts, no storm.
        self.assertEqual(calls["n"], dbm._DB_RETRY_MAX)

    def test_retry_raises_immediately_on_other_errors(self):
        calls = {"n": 0}

        def _bad():
            calls["n"] += 1
            raise ValueError("not a lock")

        with self.assertRaises(ValueError):
            dbm._write_with_retry(_bad)
        self.assertEqual(calls["n"], 1)

    def test_add_alert_survives_transient_lock(self):
        # Integration: the alert INSERT hits "database is locked" twice,
        # then lands -- the detection is not lost.
        real_db = dbm._db
        real_conn = real_db()
        calls = {"n": 0}

        class _Proxy:
            def execute(self, *a, **k):
                calls["n"] += 1
                if calls["n"] <= 2:
                    raise sqlite3.OperationalError("database is locked")
                return real_conn.execute(*a, **k)

            def __getattr__(self, name):
                return getattr(real_conn, name)

        dbm._db = lambda: _Proxy()
        try:
            with dbm.notifications_paused():
                aid = dbm.add_alert("port_scan", "Low",
                                    "Port scan from 93.184.216.34",
                                    "93.184.216.34 knocked.")
        finally:
            dbm._db = real_db
        self.assertGreaterEqual(calls["n"], 3)
        alert = dbm.get_alert(aid)
        self.assertEqual(alert["kind"], "port_scan")
        self.assertTrue(_TRACE_RE.match(alert["trace_id"] or ""))


# --- feed refresh fallback -------------------------------------------------------

class FeedFallbackTests(_ScratchDbTest):
    def test_failed_refresh_keeps_cache_and_reports_stale(self):
        now = time.time()
        dbm.ti_replace_feed("urlhaus-domains", "domain",
                            [("evil.example", "listed")])
        # Backdate both the per-feed update stamp and the global one:
        # the cached data is 40h old.
        dbm.set_meta("ti_feed_updated_urlhaus-domains",
                     str(now - 40 * 3600))
        dbm.set_meta("ti_feeds_refreshed_ts", str(now - 40 * 3600))
        with mock.patch.object(tim, "_fetch_url",
                               side_effect=OSError("net down")):
            with contextlib.redirect_stderr(io.StringIO()):
                results = tim.refresh_feeds(now=now)
        # every feed failed...
        self.assertTrue(results)
        self.assertTrue(all(not r["ok"] for r in results.values()))
        # ...but the cached feed keeps serving lookups...
        hits = dbm.ti_lookup("domain", ["evil.example"])
        self.assertEqual(len(hits["evil.example"]), 1)
        # ...and the staleness is reported, not silent.
        status = dbm.ti_feed_status()
        self.assertEqual(len(status), 1)
        self.assertTrue(status[0]["stale"])
        health = dbm.ti_feed_health()
        self.assertTrue(health["failed_recently"])

    def test_successful_refresh_clears_failed_flag(self):
        now = time.time()
        dbm.set_meta("ti_feeds_refreshed_ts", str(now - 40 * 3600))
        with mock.patch.object(tim, "_fetch_url",
                               return_value="127.0.0.1 evil.example\n"):
            with contextlib.redirect_stderr(io.StringIO()):
                results = tim.refresh_feeds(now=now)
        self.assertTrue(all(r["ok"] for r in results.values()))
        health = dbm.ti_feed_health()
        self.assertFalse(health["failed_recently"])
        status = {s["feed"]: s for s in dbm.ti_feed_status()}
        self.assertFalse(status["urlhaus-domains"]["stale"])

    def test_maybe_refresh_backs_off_after_failure(self):
        base = time.time()
        with mock.patch.object(tim, "_fetch_url",
                               side_effect=OSError("net down")):
            with contextlib.redirect_stderr(io.StringIO()):
                r1 = tim.maybe_refresh_feeds(now=base)
                self.assertIsNotNone(r1)  # attempted...
                r2 = tim.maybe_refresh_feeds(now=base + 120)
                self.assertIsNone(r2)  # ...then backs off, no storm


# --- LLM fallback ------------------------------------------------------------------

class LlmFallbackTests(_ScratchDbTest):
    def _no_key(self):
        old = os.environ.pop("OPENAI_API_KEY", None)
        return old

    def _restore_key(self, old):
        if old is not None:
            os.environ["OPENAI_API_KEY"] = old

    def test_triage_falls_back_without_key(self):
        old = self._no_key()
        try:
            verdict = assistm.triage_verdict({
                "kind": "port_scan", "severity": "Low",
                "title": "Port scan from 93.184.216.34",
                "detail": "knocked on 50 ports.",
                "meaning": "Something scanned.", "is_normal": "n",
                "what_to_do": "w"})
        finally:
            self._restore_key(old)
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict["verdict"], "likely benign")
        self.assertIn("rule-based", verdict["reasoning"])

    def test_triage_falls_back_on_client_error(self):
        with mock.patch.object(assistm, "_client",
                               side_effect=RuntimeError("boom")):
            verdict = assistm.triage_verdict({
                "kind": "port_scan", "severity": "Critical",
                "title": "Port scan", "detail": "d"})
        self.assertIsNotNone(verdict)
        self.assertEqual(verdict["verdict"], "real concern")
        self.assertIn("rule-based", verdict["reasoning"])

    def test_triage_fallback_never_invents_facts(self):
        old = self._no_key()
        try:
            verdict = assistm.triage_verdict({"kind": "nope",
                                              "severity": "Medium"})
        finally:
            self._restore_key(old)
        self.assertEqual(verdict["verdict"], "uncertain")
        # No IPs, no device names, nothing invented.
        self.assertNotRegex(verdict["reasoning"], r"\d+\.\d+\.\d+\.\d+")

    def test_answer_question_without_key_says_so(self):
        old = self._no_key()
        try:
            ans = assistm.answer_question("is anything weird happening?")
        finally:
            self._restore_key(old)
        self.assertIsNotNone(ans)
        self.assertIn("unavailable", ans["answer"])


# --- capture watchdog ----------------------------------------------------------

class CaptureWatchdogTests(unittest.TestCase):
    def test_alive_thread_is_ok(self):
        state = {"thread": object(), "restarts": [], "gave_up": False}
        started = {"n": 0}
        out = pipelinem.ensure_capture(
            state, lambda: True,
            lambda: started.__setitem__("n", started["n"] + 1))
        self.assertEqual(out, "ok")
        self.assertEqual(started["n"], 0)

    def test_dead_thread_restarted_then_gave_up(self):
        state = {"thread": None, "restarts": [], "gave_up": False}
        now = time.time()
        started = {"n": 0}

        def _start():
            started["n"] += 1
            return object()

        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(
                pipelinem.ensure_capture(state, lambda: False, _start,
                                         now=now, max_restarts=2), "restarted")
            self.assertEqual(
                pipelinem.ensure_capture(state, lambda: False, _start,
                                         now=now + 1, max_restarts=2),
                "restarted")
            self.assertEqual(
                pipelinem.ensure_capture(state, lambda: False, _start,
                                         now=now + 2, max_restarts=2),
                "gave_up")
            # past the bound: no more restarts, quiet
            self.assertEqual(
                pipelinem.ensure_capture(state, lambda: False, _start,
                                         now=now + 3, max_restarts=2),
                "gave_up")
        self.assertEqual(started["n"], 2)
        self.assertIsNotNone(state["thread"])

    def test_window_sliding_clear_re_arms(self):
        old = time.time() - 4000
        state = {"thread": None, "restarts": [old, old], "gave_up": True}
        with contextlib.redirect_stderr(io.StringIO()):
            out = pipelinem.ensure_capture(state, lambda: False,
                                           lambda: object())
        self.assertEqual(out, "restarted")
        self.assertFalse(state["gave_up"])

    def test_start_failure_counts_toward_bound(self):
        state = {"thread": None, "restarts": [], "gave_up": False}

        def _boom():
            raise RuntimeError("no scapy")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            out = pipelinem.ensure_capture(state, lambda: False, _boom,
                                           max_restarts=1)
        self.assertEqual(out, "gave_up")
        self.assertIn("capture restart failed", err.getvalue())

    def test_safe_step_logs_and_continues(self):
        def _boom():
            raise RuntimeError("poison step")

        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertIsNone(pipelinem.safe_step("mystep", _boom))
        self.assertIn("mystep", err.getvalue())
        self.assertEqual(pipelinem.safe_step("ok", lambda: 42), 42)


# --- disk guard --------------------------------------------------------------------

class DiskGuardTests(_ScratchDbTest):
    def test_pressure_when_below_threshold(self):
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=10.0):
            self.assertTrue(pipelinem.disk_pressure(min_free_mb=512))
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=100000.0):
            self.assertFalse(pipelinem.disk_pressure(min_free_mb=512))

    def test_stat_failure_is_not_pressure(self):
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=None):
            self.assertFalse(pipelinem.disk_pressure(min_free_mb=512))


class PipelineSelfAlertTests(_ScratchDbTest):
    """Pipeline self-alerts reuse the self_drift kind (the monitor
    itself needs attention) -- one alert per episode, quiet on
    recovery."""

    def _self_drift_alerts(self):
        return dbm.query(
            "SELECT id, severity, title FROM alerts WHERE kind='self_drift'"
            " ORDER BY id")

    def test_disk_full_alerts_once(self):
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=10.0):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertTrue(pipelinem.disk_alert_once(
                        min_free_mb=512))
                    # second call: already alerted this episode
                    self.assertFalse(pipelinem.disk_alert_once(
                        min_free_mb=512))
        alerts = self._self_drift_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0][1], "Medium")
        self.assertIn("disk space", alerts[0][2])
        # the self-alert itself carries a trace id
        tid = dbm.get_alert(alerts[0][0])["trace_id"]
        self.assertTrue(_TRACE_RE.match(tid or ""))

    def test_disk_recovery_re_arms(self):
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=10.0):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    pipelinem.disk_alert_once(min_free_mb=512)
        self.assertTrue(dbm.get_meta("disk_full_alerted_ts"))
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=100000.0):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertFalse(pipelinem.disk_alert_once(
                    min_free_mb=512))
        self.assertFalse(dbm.get_meta("disk_full_alerted_ts"))
        # next episode alerts anew
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=10.0):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    self.assertTrue(pipelinem.disk_alert_once(
                        min_free_mb=512))
        self.assertEqual(len(self._self_drift_alerts()), 2)

    def test_detection_still_runs_under_pressure(self):
        # Detection never consults the disk guard: run_all completes
        # (on an empty DB: zero alerts, no crash) even when "full".
        with mock.patch.object(pipelinem, "disk_free_mb",
                               return_value=1.0):
            self.assertTrue(pipelinem.disk_pressure(min_free_mb=512))
            with dbm.notifications_paused():
                detm.run_all()  # must not raise
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)


# --- watermarks --------------------------------------------------------------------

class WatermarkTests(_ScratchDbTest):
    def test_stale_stage_alerts_once_then_quiet(self):
        now = time.time()
        dbm.set_meta("wm_rules_ts", str(now - 600))  # stale (>300s)
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now, capture_expected=False)
        self.assertEqual(alerted, ["rules"])
        rows = dbm.query(
            "SELECT severity, title FROM alerts WHERE kind='self_drift'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "Medium")
        # second pass: already alerted this episode -- quiet
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now + 60, capture_expected=False)
        self.assertEqual(alerted, [])
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")
            [0][0], 1)

    def test_recovery_clears_staleness_flag(self):
        now = time.time()
        dbm.set_meta("wm_rules_ts", str(now - 600))
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                pipelinem.check_and_alert_staleness(now=now,
                                                    capture_expected=False)
        self.assertTrue(dbm.get_meta("stale_alert_rules"))
        pipelinem.mark("rules")  # healthy again
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                pipelinem.check_and_alert_staleness(now=now + 61,
                                                    capture_expected=False)
        self.assertFalse(dbm.get_meta("stale_alert_rules"))

    def test_unknown_stage_never_pages(self):
        # Fresh install: no watermarks at all -- nothing is "stale".
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    capture_expected=False)
        self.assertEqual(alerted, [])
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

    def test_dashboard_only_skips_capture(self):
        now = time.time()
        dbm.set_meta("last_flow_ts", str(now - 3600))  # stale...
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now, capture_expected=False)
        # ...but capture wasn't requested, so no page.
        self.assertNotIn("capture", alerted)

    def test_capture_stale_pages_high(self):
        now = time.time()
        dbm.set_meta("last_flow_ts", str(now - 600))
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now, capture_expected=True)
        self.assertEqual(alerted, ["capture"])
        rows = dbm.query(
            "SELECT severity FROM alerts WHERE kind='self_drift'")
        self.assertEqual(rows[0][0], "High")

    def test_multi_stage_staleness_fires_one_combined_alert(self):
        # Two stages newly stale in one pass -> ONE alert, not two.
        now = time.time()
        dbm.set_meta("last_flow_ts", str(now - 600))
        dbm.set_meta("wm_rules_ts", str(now - 600))
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now, capture_expected=True)
        self.assertEqual(sorted(alerted), ["capture", "rules"])
        rows = dbm.query(
            "SELECT severity, title FROM alerts WHERE kind='self_drift'")
        self.assertEqual(len(rows), 1)
        # highest member severity wins (capture = High)
        self.assertEqual(rows[0][0], "High")
        self.assertIn("Several parts", rows[0][1])
        # both per-stage flags set; next pass stays quiet
        self.assertTrue(dbm.get_meta("stale_alert_capture"))
        self.assertTrue(dbm.get_meta("stale_alert_rules"))
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                alerted = pipelinem.check_and_alert_staleness(
                    now=now + 60, capture_expected=True)
        self.assertEqual(alerted, [])
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")
            [0][0], 1)

    def test_health_snapshot_states(self):
        now = time.time()
        pipelinem.mark("rules")
        snap = {s["stage"]: s for s in pipelinem.health_snapshot(
            now=now, capture_expected=False)}
        self.assertEqual(set(snap), {"capture", "rules", "feeds",
                                     "notify"})
        self.assertEqual(snap["rules"]["state"], "ok")
        self.assertEqual(snap["notify"]["state"], "unknown")
        self.assertEqual(snap["capture"]["state"], "unknown")
        self.assertIn("not running", snap["capture"]["note"])

    def test_clock_skew_never_reports_negative_age(self):
        now = time.time()
        dbm.set_meta("wm_rules_ts", str(now + 3600))  # clock jumped back
        last, age = pipelinem.watermark("rules", now=now)
        self.assertEqual(age, 0.0)
        self.assertFalse(pipelinem.is_stale("rules", now=now))

    def test_rules_failure_streak_alerts_at_three(self):
        with dbm.notifications_paused():
            with contextlib.redirect_stderr(io.StringIO()):
                pipelinem.note_rules_result(False, RuntimeError("x"))
                pipelinem.note_rules_result(False, RuntimeError("x"))
                self.assertEqual(
                    dbm.query("SELECT COUNT(*) FROM alerts"
                              " WHERE kind='self_drift'")[0][0], 0)
                pipelinem.note_rules_result(False, RuntimeError("x"))
        rows = dbm.query(
            "SELECT severity, title FROM alerts WHERE kind='self_drift'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "Medium")
        # recovery resets the streak and clears the flag
        with contextlib.redirect_stderr(io.StringIO()):
            pipelinem.note_rules_result(True)
        self.assertEqual(dbm.get_meta("pipeline_rules_fail_streak"), "0")
        self.assertFalse(dbm.get_meta("stale_alert_rules"))
        _last, age = pipelinem.watermark("rules")
        self.assertIsNotNone(age)


# --- SMTP failure fallback ------------------------------------------------------------

class NotifyFallbackTests(_ScratchDbTest):
    def setUp(self):
        super().setUp()
        self._old_env = dict(os.environ)
        os.environ["NETMON_SMTP_HOST"] = "mail.example"
        os.environ["NETMON_ALERT_TO"] = "owner@example"
        notifm._fail_streak = 0

    def tearDown(self):
        os.environ.clear()
        os.environ.update(self._old_env)
        notifm._fail_streak = 0
        super().tearDown()

    def _alert(self, kind="port_scan"):
        return {"id": 1, "kind": kind, "severity": "High",
                "title": "Port scan", "detail": "d", "meaning": "m",
                "is_normal": "n", "what_to_do": "w", "ts": time.time()}

    def test_send_failure_logs_and_alerts_once(self):
        with mock.patch.object(notifm, "_send",
                               side_effect=OSError("conn refused")):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    for _ in range(4):
                        self.assertFalse(
                            notifm._maybe_send_alert(self._alert()))
                    self.assertEqual(
                        dbm.query("SELECT COUNT(*) FROM alerts"
                                  " WHERE kind='self_drift'")[0][0], 0)
                    self.assertFalse(
                        notifm._maybe_send_alert(self._alert()))
        self.assertIn("email send failed", err.getvalue())
        rows = dbm.query(
            "SELECT severity, title FROM alerts WHERE kind='self_drift'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "Medium")
        self.assertIn("emails aren't going out", rows[0][1])
        # sixth failure: already alerted this episode -- quiet
        with mock.patch.object(notifm, "_send",
                               side_effect=OSError("conn refused")):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    notifm._maybe_send_alert(self._alert())
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")
            [0][0], 1)

    def test_success_resets_streak_and_re_arms(self):
        with mock.patch.object(notifm, "_send",
                               side_effect=OSError("conn refused")):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    for _ in range(5):
                        notifm._maybe_send_alert(self._alert())
        self.assertTrue(dbm.get_meta("notify_down_alerted"))
        # a successful send: streak reset, flag cleared, watermark set
        with mock.patch.object(notifm, "_send", return_value=None):
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertTrue(
                    notifm._maybe_send_alert(self._alert()))
        self.assertEqual(notifm._fail_streak, 0)
        self.assertFalse(dbm.get_meta("notify_down_alerted"))
        _last, age = pipelinem.watermark("notify")
        self.assertIsNotNone(age)
        # failing again alerts anew (fresh kinds: the successful send
        # set a per-kind email cooldown, which is correct behavior)
        with mock.patch.object(notifm, "_send",
                               side_effect=OSError("conn refused")):
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()):
                    for i in range(5):
                        notifm._maybe_send_alert(self._alert(
                            kind=f"port_scan_r{i}"))
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts WHERE kind='self_drift'")
            [0][0], 2)

    def test_unconfigured_smtp_stays_silent(self):
        os.environ.pop("NETMON_SMTP_HOST", None)
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertFalse(notifm._maybe_send_alert(self._alert()))
        self.assertEqual(err.getvalue(), "")
        self.assertEqual(notifm._fail_streak, 0)


# --- detect.run_all isolation -------------------------------------------------------

class DetectIsolationTests(_ScratchDbTest):
    def test_one_rule_crash_does_not_cancel_pass(self):
        ran = []

        def _boom(now=None):
            raise RuntimeError("poison input")

        def _recorder(now=None):
            ran.append("recorder")

        orig = detm._RULES
        detm._RULES = (_boom, _recorder)
        try:
            with dbm.notifications_paused():
                with contextlib.redirect_stderr(io.StringIO()) as err:
                    detm.run_all()  # must not raise
        finally:
            detm._RULES = orig
        self.assertEqual(ran, ["recorder"])
        self.assertIn("_boom failed", err.getvalue())


# --- dashboard surface -----------------------------------------------------------------

@unittest.skipIf(dashm is None, "Flask not installed")
class DashboardPipelineTests(_ScratchDbTest):
    def setUp(self):
        super().setUp()
        self.client = dashm.app.test_client()

    def test_pipeline_health_endpoint(self):
        pipelinem.mark("rules")
        r = self.client.get("/api/pipeline_health")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        stages = {s["stage"]: s for s in d["stages"]}
        self.assertEqual(set(stages),
                         {"capture", "rules", "feeds", "notify"})
        self.assertEqual(stages["rules"]["state"], "ok")
        self.assertEqual(stages["notify"]["state"], "unknown")

    def test_alerts_carry_trace_id(self):
        with dbm.notifications_paused():
            aid = dbm.add_alert("port_scan", "High",
                                "Port scan from 93.184.216.34",
                                "93.184.216.34 knocked.")
        tid = dbm.get_alert(aid)["trace_id"]
        r = self.client.get("/api/stats")
        self.assertEqual(r.status_code, 200)
        alerts = r.get_json()["alerts"]
        mine = [a for a in alerts if a["id"] == aid]
        self.assertEqual(len(mine), 1)
        self.assertEqual(mine[0]["trace_id"], tid)

    def test_intel_status_has_staleness_fields(self):
        dbm.ti_replace_feed("urlhaus-domains", "domain",
                            [("evil.example", "listed")])
        r = self.client.get("/api/intel/status")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("feed_health", d)
        self.assertIn("failed_recently", d["feed_health"])
        self.assertIn("stale", d["feeds"][0])


if __name__ == "__main__":
    unittest.main()
