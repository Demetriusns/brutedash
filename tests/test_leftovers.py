"""Batch 17 tests: leftovers + dashboard polish.

- A1 device naming: friendly names in alert titles, emails, case labels.
- A2 maintenance mode: notifications pause, detection continues, banner.
- A3 digest emails: the daily briefing + digest exist; per-alert mail is
  High/Critical only (verified, not rebuilt).
- A4 alert-fatigue circuit breaker: trip -> visible mute notice ->
  suppression counted -> expiry -> unmute.
- A5 per-rule precision: rule_health carries FP-profile notes + mutes.
- B6 canary/honeypot: fake port touch + bait file -> High alert.
- B9 DoH awareness: encrypted-DNS note per device.
- C dashboard polish: fonts link, new endpoints/JS paths render.
- D test hygiene: helpers remove db + WAL sidecars (this file uses them).

Run: python -m unittest discover -s tests
"""
import os
import re
import socket
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import ScratchDbTestCase, fresh_db, restore_db, scratch_file

from netmon import db as dbm
from netmon import detect as detm

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

try:
    from netmon import canary as canarym
except ImportError:
    canarym = None


def _flow(ts, src, dst, dport, nbytes=10**6, proto="TCP"):
    return (ts, src, dst, 12345, dport, proto, 10, nbytes, "outbound")


# --- A1: device naming -------------------------------------------------------

class DeviceNamingTests(ScratchDbTestCase):
    def test_device_label_uses_friendly_name(self):
        now = time.time()
        dbm.insert_arp_observations([(now, "192.168.1.50",
                                      "aa:bb:cc:dd:ee:50")])
        dbm.set_device_name("aa:bb:cc:dd:ee:50", "PS5")
        self.assertEqual(detm._device_label("192.168.1.50"),
                         "PS5 (192.168.1.50)")

    def test_device_label_falls_back_without_name(self):
        self.assertEqual(detm._device_label("192.168.1.51"),
                         "device 192.168.1.51")
        self.assertEqual(detm._device_label(""),
                         "a device on your network")

    def test_alert_detail_keeps_mac_for_cooldown(self):
        # Batch-3 invariant: renaming a device must not hide the MAC the
        # cooldown LIKE-match needs (behavior_deviation keys on MAC).
        dbm.add_alert("behavior_deviation", "Medium",
                      "PS5 moved far more than its usual",
                      "In the last hour PS5 (aa:bb:cc:dd:ee:50) moved"
                      " 900 MB -- about 9x its usual.")
        self.assertTrue(dbm.recent_alert_kind(
            "behavior_deviation", "aa:bb:cc:dd:ee:50", 86400))

    def test_case_title_uses_friendly_name(self):
        dbm.insert_arp_observations([(time.time(), "192.168.1.50",
                                      "aa:bb:cc:dd:ee:50")])
        dbm.set_device_name("aa:bb:cc:dd:ee:50", "PS5")
        aid = dbm.add_alert("new_device", "Low",
                            "New device joined: PS5 (192.168.1.50)",
                            "MAC aa:bb:cc:dd:ee:50 showed up at 192.168.1.50")
        iid = dbm.query("SELECT incident_id FROM incident_alerts"
                        " WHERE alert_id=?", (aid,))[0][0]
        case = dbm.get_incident(iid)
        self.assertIn("PS5 (192.168.1.50)", case["title"])

    def test_rename_from_device_list_still_works(self):
        dbm.set_device_name("aa:bb:cc:dd:ee:99", "Fridge")
        self.assertEqual(dbm.device_name_map()["aa:bb:cc:dd:ee:99"],
                         "Fridge")
        dbm.set_device_name("aa:bb:cc:dd:ee:99", "")
        self.assertNotIn("aa:bb:cc:dd:ee:99", dbm.device_name_map())


# --- A2: maintenance mode ----------------------------------------------------

class MaintenanceModeTests(ScratchDbTestCase):
    def test_off_by_default(self):
        st = dbm.get_maintenance()
        self.assertFalse(st["active"])

    def test_on_off_roundtrip(self):
        st = dbm.set_maintenance(True, None, "replacing the router")
        self.assertTrue(st["active"])
        self.assertEqual(st["reason"], "replacing the router")
        self.assertIsNone(st["until_ts"])
        self.assertTrue(dbm.maintenance_active())
        st = dbm.set_maintenance(False)
        self.assertFalse(st["active"])
        self.assertFalse(dbm.maintenance_active())

    def test_expired_until_auto_clears(self):
        dbm.set_maintenance(True, time.time() - 10, "old window")
        self.assertFalse(dbm.maintenance_active())
        self.assertFalse(dbm.get_maintenance()["active"])

    def test_future_until_stays_active(self):
        dbm.set_maintenance(True, time.time() + 3600, "work")
        self.assertTrue(dbm.maintenance_active())

    def test_audit_trail_records_toggle(self):
        dbm.set_maintenance(True, None, "test")
        dbm.set_maintenance(False)
        actions = [a["action"] for a in dbm.list_audit(limit=10)]
        self.assertIn("maintenance", actions)

    def test_detection_continues_while_notifications_pause(self):
        from netmon import notify as notifm
        old_host = os.environ.get("NETMON_SMTP_HOST")
        old_to = os.environ.get("NETMON_ALERT_TO")
        os.environ["NETMON_SMTP_HOST"] = "127.0.0.1"
        os.environ["NETMON_ALERT_TO"] = "owner@example.com"
        try:
            dbm.set_maintenance(True, None, "test")
            aid = dbm.add_alert("traffic_spike", "High", "t", "d")
            self.assertIsNotNone(aid)  # detection: still records
            # notification paths: all stay silent
            self.assertFalse(notifm._maybe_send_alert(
                {"kind": "x", "severity": "High", "title": "t"}))
            self.assertFalse(notifm._send_digest())
            from netmon import reporting as repm
            self.assertEqual(repm.maybe_daily_briefing(), "maintenance")
            ok, reason = repm.send_briefing()
            self.assertFalse(ok)
            self.assertIn("maintenance", reason)
        finally:
            for key, val in (("NETMON_SMTP_HOST", old_host),
                             ("NETMON_ALERT_TO", old_to)):
                if val is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = val

    def test_queue_time_check_closes_the_race(self):
        # An alert queued during maintenance must not email even if the
        # worker only gets to it after maintenance is switched off.
        from netmon import notify as notifm
        dbm.set_maintenance(True, None, "test")
        self.assertFalse(notifm.maybe_send_alert(
            {"kind": "x", "severity": "High", "title": "t"}))
        self.assertEqual(notifm._job_queue.qsize(), 0)


@unittest.skipIf(dashm is None, "Flask not installed")
class MaintenanceRouteTests(ScratchDbTestCase):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_get_maintenance(self):
        r = self._client().get("/api/settings/maintenance")
        self.assertEqual(r.status_code, 200)
        self.assertFalse(r.get_json()["maintenance"]["active"])

    def test_set_maintenance_roundtrip(self):
        c = self._client()
        r = c.post("/api/settings/maintenance",
                   json={"on": True, "reason": "r", "hours": 2})
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertTrue(body["maintenance"]["active"])
        self.assertLess(abs(body["maintenance"]["until_ts"]
                            - (time.time() + 7200)), 60)
        r = c.post("/api/settings/maintenance", json={"on": False})
        self.assertFalse(r.get_json()["maintenance"]["active"])

    def test_set_maintenance_rejects_bad_hours(self):
        c = self._client()
        r = c.post("/api/settings/maintenance",
                   json={"on": True, "hours": "many"})
        self.assertEqual(r.status_code, 400)
        r = c.post("/api/settings/maintenance",
                   json={"on": True, "hours": 1000})
        self.assertEqual(r.status_code, 400)

    def test_stats_carries_maintenance_for_banner(self):
        c = self._client()
        dbm.set_maintenance(True, None, "banner test")
        r = c.get("/api/stats")
        self.assertTrue(r.get_json()["maintenance"]["active"])

    def test_maintenance_route_is_owner_only(self):
        # Structural: the POST handler carries the owner gate.
        view = dashm.app.view_functions["api_maintenance_set"]
        wrapped = getattr(view, "__wrapped__", None)
        self.assertIsNotNone(wrapped,
                             "POST /api/settings/maintenance lost its"
                             " owner gate")


# --- A3: digest emails (verify existing, don't rebuild) -----------------------

class DigestExistsTests(ScratchDbTestCase):
    def test_per_alert_mail_is_high_critical_only(self):
        from netmon import notify as notifm
        self.assertEqual(notifm._SENDABLE, {"High", "Critical"})

    def test_digest_and_briefing_exist(self):
        from netmon import notify as notifm
        from netmon import reporting as repm
        for fn in (notifm.send_digest, notifm.build_digest,
                   repm.build_briefing, repm.send_briefing,
                   repm.maybe_daily_briefing):
            self.assertTrue(callable(fn), fn)

    def test_digest_covers_medium_up_not_critical_only(self):
        from netmon import notify as notifm
        now = time.time()
        dbm.add_alert("traffic_spike", "Medium", "m-title", "m-detail",
                      ts=now - 100)
        rows = dbm.query(
            "SELECT kind, severity, title, detail, ts FROM alerts"
            " WHERE ts > ? AND severity IN ('High','Critical','Medium')",
            (now - 3600,))
        subject, body = notifm.build_digest(rows)
        self.assertIn("m-title", body)


# --- A4: alert-fatigue circuit breaker ----------------------------------------

def _patch_circuit(testcase, fires=3, window_min=10, mute_min=60):
    return mock.patch.object(dbm, "_circuit_config",
                             return_value=(fires, window_min, mute_min))


class CircuitBreakerTests(ScratchDbTestCase):
    def _fire(self, kind, n, **kw):
        ids = []
        for i in range(n):
            ids.append(dbm.add_alert(kind, "Medium", f"t{i}", f"d{i}",
                                     **kw))
        return ids

    def test_trip_mutes_and_records_visible_notice(self):
        with _patch_circuit(self):
            self._fire("unusual_port", 4)  # 4th trips (more than 3)
            mutes = [m for m in dbm.list_rule_mutes()
                     if m["kind"] == "unusual_port"]
            self.assertEqual(len(mutes), 1)
            self.assertTrue(mutes[0]["active"])
            self.assertEqual(mutes[0]["fired_count"], 3)
            notice = dbm.query(
                "SELECT severity, title, detail FROM alerts"
                " WHERE kind='rule_muted' ORDER BY id DESC LIMIT 1")
            self.assertEqual(len(notice), 1)
            sev, title, detail = notice[0]
            self.assertEqual(sev, "Medium")
            self.assertIn("unusual_port", title)
            self.assertIn("3 times", detail)
            self.assertIn("60 minutes", detail)

    def test_muted_firings_suppressed_but_counted(self):
        with _patch_circuit(self):
            self._fire("unusual_port", 4)
            before = dbm.query(
                "SELECT COUNT(*) FROM alerts"
                " WHERE kind='unusual_port'")[0][0]
            self.assertIsNone(dbm.add_alert("unusual_port", "Medium",
                                            "t5", "d5"))
            after = dbm.query(
                "SELECT COUNT(*) FROM alerts"
                " WHERE kind='unusual_port'")[0][0]
            self.assertEqual(before, after)  # not stored...
            m = [x for x in dbm.list_rule_mutes()
                 if x["kind"] == "unusual_port"][0]
            self.assertGreaterEqual(m["suppressed"], 1)  # ...but counted

    def test_mute_notice_skips_incidents(self):
        with _patch_circuit(self):
            self._fire("unusual_port", 4)
            n = dbm.query(
                "SELECT COUNT(*) FROM incident_alerts ia"
                " JOIN alerts a ON a.id=ia.alert_id"
                " WHERE a.kind='rule_muted'")[0][0]
            self.assertEqual(n, 0)

    def test_mute_expires_and_rule_recovers(self):
        with _patch_circuit(self, mute_min=60):
            self._fire("unusual_port", 4)
            # Fast-forward: expire the mute row by hand.
            with dbm._lock:
                conn = dbm._db()
                conn.execute(
                    "UPDATE rule_mutes SET muted_until=? WHERE kind=?",
                    (time.time() - 1, "unusual_port"))
                conn.commit()
            # The tripped alert is >window old now too: clear the window.
            with dbm._lock:
                conn = dbm._db()
                conn.execute("DELETE FROM alerts WHERE kind='unusual_port'")
                conn.commit()
            aid = dbm.add_alert("unusual_port", "Medium", "t", "d")
            self.assertIsNotNone(aid)
            self.assertEqual(dbm.list_rule_mutes(), [])

    def test_clear_rule_mute_lifts_early(self):
        with _patch_circuit(self):
            self._fire("unusual_port", 4)
            self.assertTrue(dbm.clear_rule_mute("unusual_port"))
            self.assertFalse(dbm.clear_rule_mute("unusual_port"))
            self.assertIsNotNone(
                dbm.add_alert("unusual_port", "Medium", "t", "d"))

    def test_exempt_kinds_never_muted(self):
        with _patch_circuit(self, fires=1):
            for kind in ("self_drift", "rule_muted", "canary_touch"):
                for i in range(3):
                    self.assertIsNotNone(
                        dbm.add_alert(kind, "Medium", f"t{i}", f"d{i}"))
                self.assertEqual(
                    [m for m in dbm.list_rule_mutes()
                     if m["kind"] == kind], [])

    def test_quiet_rules_never_trip(self):
        with _patch_circuit(self):
            self._fire("unusual_port", 2)
            self.assertEqual(dbm.list_rule_mutes(), [])
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts"
                          " WHERE kind='rule_muted'")[0][0], 0)

    def test_failed_insert_untrips_the_mute(self):
        # Council R-3: if the alert that tripped the breaker is never
        # stored, the mute row must not be left behind silencing future
        # alerts with no visible record.
        import sqlite3
        with _patch_circuit(self, fires=1):
            with mock.patch.object(
                    dbm, "_write_with_retry",
                    side_effect=sqlite3.OperationalError("boom")):
                with self.assertRaises(sqlite3.OperationalError):
                    dbm.add_alert("unusual_port", "Medium", "t", "d")
            self.assertEqual(dbm.list_rule_mutes(), [])
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts"
                          " WHERE kind='rule_muted'")[0][0], 0)


@unittest.skipIf(dashm is None, "Flask not installed")
class CircuitRouteTests(ScratchDbTestCase):
    def test_unmute_route(self):
        c = dashm.app.test_client()
        with _patch_circuit(self):
            for i in range(4):
                dbm.add_alert("beaconing", "Medium", f"t{i}", "d")
            self.assertEqual(len(dbm.list_rule_mutes()), 1)
        r = c.post("/api/rule_health/unmute", json={"kind": "beaconing"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"ok": True, "cleared": True})
        self.assertEqual(dbm.list_rule_mutes(), [])

    def test_unmute_route_is_owner_only(self):
        view = dashm.app.view_functions["api_rule_unmute"]
        self.assertIsNotNone(getattr(view, "__wrapped__", None),
                             "unmute route lost its owner gate")

    def test_rule_health_carries_mutes_and_fp_notes(self):
        c = dashm.app.test_client()
        dbm.add_alert("traffic_spike", "Medium", "t", "d")
        dbm.set_alert_status(1, "dismissed")
        r = c.get("/api/rule_health")
        body = r.get_json()
        self.assertIn("mutes", body)
        row = next(x for x in body["rules"]
                   if x["kind"] == "traffic_spike")
        self.assertTrue(row["fp_note"])  # catalog FP profile, fed in


# --- B6: canary ----------------------------------------------------------------

@unittest.skipIf(canarym is None, "canary module missing")
class CanaryTests(ScratchDbTestCase):
    def _free_port(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        return port

    def _patched_config(self, port):
        return mock.patch.object(
            canarym, "_config", return_value=(True, port, "127.0.0.1"))

    def _wait_for_touches(self, n, timeout=5):
        """Wait until n canary_touch alerts are recorded. The accept
        thread records asynchronously -- never stop() or tear down the
        scratch DB while a touch is still in flight."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            count = dbm.query("SELECT COUNT(*) FROM alerts"
                              " WHERE kind='canary_touch'")[0][0]
            if count >= n:
                return count
            time.sleep(0.1)
        return dbm.query("SELECT COUNT(*) FROM alerts"
                         " WHERE kind='canary_touch'")[0][0]

    def test_touch_fires_high_alert(self):
        port = self._free_port()
        with self._patched_config(port):
            self.assertTrue(canarym.start())
            self.assertTrue(canarym.is_running())
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(("127.0.0.1", port))
                s.close()
                deadline = time.time() + 5
                rows = []
                while time.time() < deadline and not rows:
                    rows = dbm.query(
                        "SELECT severity, title, detail FROM alerts"
                        " WHERE kind='canary_touch' ORDER BY id DESC"
                        " LIMIT 1")
                    time.sleep(0.1)
                self.assertEqual(len(rows), 1)
                sev, title, detail = rows[0]
                self.assertEqual(sev, "High")
                self.assertIn("127.0.0.1", detail)
            finally:
                canarym.stop()
            self.assertFalse(canarym.is_running())

    def test_trap_closes_immediately_serves_nothing(self):
        port = self._free_port()
        with self._patched_config(port):
            canarym.start()
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(("127.0.0.1", port))
                # The trap closes at once: recv hits EOF, nothing served.
                data = s.recv(1024)
                self.assertEqual(data, b"")
                s.close()
                self.assertEqual(self._wait_for_touches(1), 1)
            finally:
                canarym.stop()

    def test_touch_cooldown_one_per_day(self):
        port = self._free_port()
        with self._patched_config(port):
            canarym.start()
            try:
                for _ in range(2):
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(5)
                    s.connect(("127.0.0.1", port))
                    s.close()
                    time.sleep(0.3)
                self.assertEqual(self._wait_for_touches(1), 1)
            finally:
                canarym.stop()

    def test_bind_failure_is_quiet_disable(self):
        port = self._free_port()
        blocker = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        blocker.bind(("127.0.0.1", port))
        blocker.listen(1)
        try:
            with self._patched_config(port):
                self.assertFalse(canarym.start())
                self.assertFalse(canarym.is_running())
                self.assertEqual(
                    dbm.query("SELECT COUNT(*) FROM alerts"
                              " WHERE kind='canary_touch'")[0][0], 0)
        finally:
            blocker.close()

    def test_wildcard_bind_refused(self):
        # Council S-1: the trap never takes a wildcard bind, even when
        # explicitly configured -- it watches the LAN only.
        for wildcard in ("0.0.0.0", "::"):
            with mock.patch.object(
                    canarym, "_config",
                    return_value=(True, self._free_port(), wildcard)):
                self.assertFalse(canarym.start())
                self.assertFalse(canarym.is_running())

    def test_bait_file_change_alerts(self):
        with scratch_file(suffix=".txt") as path:
            with self._patched_config(23231), \
                    mock.patch.object(canarym, "canary_file_path",
                                      return_value=path):
                if os.path.exists(path):
                    os.unlink(path)
                canarym.check_canary_file()  # creates + baselines
                self.assertTrue(os.path.exists(path))
                # Rewrite the bait (mtime moves on most filesystems;
                # force it in case of coarse granularity).
                with open(path, "a", encoding="utf-8") as fh:
                    fh.write("stolen?\n")
                os.utime(path, (time.time() + 5, time.time() + 5))
                canarym.check_canary_file()
                rows = dbm.query(
                    "SELECT severity, title FROM alerts"
                    " WHERE kind='canary_touch' ORDER BY id DESC LIMIT 1")
                self.assertEqual(len(rows), 1)
                self.assertEqual(rows[0][0], "High")
                self.assertIn("passwords file", rows[0][1])

    def test_selfcheck_excludes_trap_port(self):
        from netmon import selfcheck as selfm
        port = 23231
        with self._patched_config(port), \
                mock.patch.object(
                    selfm, "_linux_listening_ports",
                    return_value={(port, "python"), (80, "nginx")}):
            # Baseline learns both ports...
            with mock.patch.object(selfm, "_is_windows",
                                   return_value=False):
                status, _, _ = selfm.check_listening_ports()
                self.assertEqual(status, "ok")
                # ...then the trap port alone must not read as drift.
                with mock.patch.object(
                        selfm, "_linux_listening_ports",
                        return_value={(port, "python"), (80, "nginx"),
                                      (443, "nginx")}):
                    status, detail, _ = selfm.check_listening_ports()
                    self.assertEqual(status, "drift")
                    self.assertNotIn(str(port), detail)


# --- B9: DoH awareness ----------------------------------------------------------

class DohTests(ScratchDbTestCase):
    def test_doh_flow_fires_low_note(self):
        now = time.time()
        dbm.insert_flows([_flow(now, "192.168.1.60", "1.1.1.1", 443,
                                nbytes=2 * 10**6)])
        fired = detm.check_doh_usage(now=now)
        self.assertEqual(len(fired), 1)
        sev, title, detail, wtd = dbm.query(
            "SELECT severity, title, detail, what_to_do FROM alerts"
            " WHERE kind='doh_usage'")[0]
        self.assertEqual(sev, "Low")
        self.assertIn("encrypted DNS", title)
        self.assertIn("192.168.1.60", detail)
        self.assertIn("some DNS visibility is reduced", wtd)

    def test_doh_uses_friendly_name(self):
        now = time.time()
        dbm.insert_arp_observations([(now, "192.168.1.61",
                                      "aa:bb:cc:dd:ee:61")])
        dbm.set_device_name("aa:bb:cc:dd:ee:61", "KidLaptop")
        dbm.insert_flows([_flow(now, "192.168.1.61", "8.8.8.8", 443)])
        detm.check_doh_usage(now=now)
        title = dbm.query(
            "SELECT title FROM alerts WHERE kind='doh_usage'")[0][0]
        self.assertIn("KidLaptop (192.168.1.61)", title)

    def test_doh_cooldown_one_per_day(self):
        now = time.time()
        dbm.insert_flows([_flow(now, "192.168.1.62", "9.9.9.9", 443)])
        detm.check_doh_usage(now=now)
        detm.check_doh_usage(now=now + 60)
        n = dbm.query("SELECT COUNT(*) FROM alerts"
                      " WHERE kind='doh_usage'")[0][0]
        self.assertEqual(n, 1)

    def test_doh_ignores_plain_web_and_other_ports(self):
        now = time.time()
        # Port 80 to a resolver: not DoH.
        dbm.insert_flows([_flow(now, "192.168.1.63", "1.1.1.1", 80)])
        # Port 443 to a non-resolver: just web traffic.
        dbm.insert_flows([_flow(now, "192.168.1.64", "93.184.216.34", 443)])
        # Non-LAN source: not our device, no note.
        dbm.insert_flows([_flow(now, "93.184.216.34", "1.1.1.1", 443)])
        self.assertEqual(detm.check_doh_usage(now=now), [])
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM alerts"
                      " WHERE kind='doh_usage'")[0][0], 0)


@unittest.skipIf(dashm is None, "Flask not installed")
class DohBadgeTests(ScratchDbTestCase):
    def test_devices_carry_doh_flag(self):
        now = time.time()
        dbm.insert_arp_observations([(now, "192.168.1.70",
                                      "aa:bb:cc:dd:ee:70")])
        dbm.insert_flows([_flow(now, "192.168.1.70", "1.1.1.1", 443)])
        detm.check_doh_usage(now=now)
        c = dashm.app.test_client()
        devs = {d["last_ip"]: d for d in
                c.get("/api/devices").get_json()["devices"]}
        self.assertTrue(devs["192.168.1.70"]["doh"])


# --- C: dashboard polish --------------------------------------------------------

@unittest.skipIf(dashm is None, "Flask not installed")
class PolishTests(ScratchDbTestCase):
    def test_fonts_link_present_with_fallback(self):
        html = dashm.INDEX_HTML
        self.assertIn("fontshare", html)
        self.assertIn("display=swap", html)
        # Every custom stack ends in system fonts (graceful offline).
        self.assertIn("system-ui", dashm.STYLE)
        self.assertIn("ui-monospace", dashm.STYLE)

    def test_reduced_motion_respected(self):
        self.assertIn("prefers-reduced-motion", dashm.STYLE)

    def test_new_playbooks_render(self):
        c = dashm.app.test_client()
        for slug in ("rule-muted", "canary-touch", "encrypted-dns"):
            r = c.get(f"/playbook/{slug}")
            self.assertEqual(r.status_code, 200, slug)
            self.assertNotIn(b"still being written", r.data)

    def test_selfcheck_carries_canary(self):
        c = dashm.app.test_client()
        body = c.get("/api/selfcheck").get_json()
        self.assertIn("canary", body)
        self.assertIn("port", body["canary"])

    def test_index_has_new_mount_points(self):
        html = self._served_index()
        for marker in ('id="maintbanner"', 'id="canarystatus"',
                       'id="maintenance"'):
            self.assertIn(marker, html)

    def _served_index(self):
        return dashm.app.test_client().get("/").get_data(as_text=True)

    def test_served_js_parses(self):
        # The served page script must stay parseable (node --check also
        # runs in the smoke boot; this is the in-suite guard).
        import subprocess
        html = self._served_index()
        m = re.search(r"<script>(.*?)</script>", html, re.S)
        self.assertIsNotNone(m)
        with scratch_file(suffix=".js", mode="w") as path:
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(m.group(1))
            proc = subprocess.run(["node", "--check", path],
                                  capture_output=True, text=True,
                                  timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stderr[:500])


# --- D: test hygiene ------------------------------------------------------------

class HelpersTests(unittest.TestCase):
    def test_scratch_db_removes_wal_sidecars(self):
        import sqlite3  # noqa: F401 (documents the WAL-mode requirement)
        path_state = fresh_db()
        path = path_state[0]
        try:
            conn = dbm._db()
            conn.execute("CREATE TABLE t(x)")
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("INSERT INTO t VALUES (1)")
            conn.commit()
            # Force WAL sidecars to exist.
            conn.execute("INSERT INTO t VALUES (2)")
            conn.commit()
        finally:
            restore_db(*path_state)
        leftovers = [p for p in
                     (path, path + "-wal", path + "-shm", path + "-journal")
                     if os.path.exists(p)]
        self.assertEqual(leftovers, [])

    def test_scratch_file_and_dir_cleaned(self):
        with scratch_file(suffix=".log") as p:
            self.assertTrue(os.path.exists(p))
            saved = p
        self.assertFalse(os.path.exists(saved))
        from helpers import scratch_dir
        with scratch_dir() as d:
            self.assertTrue(os.path.isdir(d))
            saved_d = d
        self.assertFalse(os.path.exists(saved_d))


if __name__ == "__main__":
    unittest.main()
