"""Tests for the Phase 3.5 batch 12 (2026-10-04): reporting -- "prove it".

- Security score card: fixed fixtures -> exact expected scores; empty
  database -> neutral default (never 0-as-punishment); caps; dismissed
  alerts ignored; stale-data penalty; floor at 0; deterministic.
- Morning briefing: 24h window boundaries, quiet-night variant, quiet
  wins, quiet-hours deferral, fake-SMTP capture of the sent MIME with
  all sections present, CR/LF header-injection cleaning.
- Compliance reports: HTML/CSV field completeness (incidents + MITRE,
  response actions, dismissals with reasons, volume trends, scores);
  empty DB still renders.
- Forensic rewind: ring-buffer caps (size + time), time-window export
  correctness, empty-window pcap validity, low-disk pause, incident
  window padding, export route path-traversal safety.
- PDF writer: %PDF-1.4 header, parseable xref, page count, extractable
  text, malformed alert text (parens/backslashes/unicode/newlines)
  can't break the file; incident + weekly PDFs.

Run: python -m unittest discover -s tests
"""
import csv
import io
import json
import os
import re
import struct
import sys
import tempfile
import time
import unittest
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import reporting as repm
from netmon import rewind as rwm
from netmon import pdfgen

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None


from helpers import fresh_db as _fresh_db, restore_db as _restore_db

class _DbTest(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()
        self._old_send = repm._SEND_FUNC
        self._old_asm = None
        try:
            from netmon import attacksurface as asm
            self._old_asm = asm.build_report
        except ImportError:
            pass

    def tearDown(self):
        repm._SEND_FUNC = self._old_send
        if self._old_asm is not None:
            from netmon import attacksurface as asm
            asm.build_report = self._old_asm
        _restore_db(*self._db)

    # -- fixtures ------------------------------------------------------
    def _flow(self, ts, size=1000):
        dbm.insert_flows([(ts, "192.168.1.50", "93.184.216.34", 1234, 443,
                           "TCP", 10, size, "outbound")])

    def _alert(self, severity, ts, kind="unusual_port", title="t",
               status="new"):
        with dbm._lock:
            conn = dbm._db()
            cur = conn.execute(
                "INSERT INTO alerts (ts, kind, severity, title, detail,"
                " status) VALUES (?,?,?,?,?,?)",
                (ts, kind, severity, title, "d", status))
            conn.commit()
            return cur.lastrowid

    def _incident(self, title, severity, status, created_ts, alert_ids=()):
        with dbm._lock:
            conn = dbm._db()
            cur = conn.execute(
                "INSERT INTO incidents (created_ts, updated_ts, title,"
                " severity, status) VALUES (?,?,?,?,?)",
                (created_ts, created_ts, title, severity, status))
            iid = cur.lastrowid
            for aid in alert_ids:
                conn.execute(
                    "INSERT INTO incident_alerts (incident_id, alert_id)"
                    " VALUES (?,?)", (iid, aid))
            conn.commit()
            return iid

    def _no_exposures(self):
        from netmon import attacksurface as asm
        asm.build_report = lambda now=None: {
            "ok": True, "summary_line": "", "counts": {},
            "devices": [], "exposures": [], "lateral_paths": []}


# --- score card ---------------------------------------------------------------


class ScoreTests(_DbTest):
    def test_empty_db_is_neutral_not_zero(self):
        data = repm.compute_score(now=time.time())
        self.assertTrue(data["neutral"])
        self.assertIsNone(data["score"])  # never 0-as-punishment
        why = repm.explain_score(data)
        self.assertIn("Not enough data", why)

    def test_exact_score_fixture(self):
        # 2 High + 1 Medium alerts: 2*8 + 1*3 = 19
        # 1 open case: 5 ; 1 High exposure: 6 ; 1 open Medium finding: 4
        # fresh flows: health 0. Total lost = 34 -> score 66.
        now = time.time()
        self._flow(now - 60)
        self._alert("High", now - 3600, title="h1")
        self._alert("High", now - 7200, title="h2")
        self._alert("Medium", now - 3600, title="m1")
        self._incident("case", "High", "open", now - 3600)
        with dbm._lock:
            conn = dbm._db()
            conn.execute(
                "INSERT INTO scan_findings (run_ts, ip, port, service,"
                " risk, status) VALUES (?,?,?,?,?,?)",
                (now - 3600, "192.168.1.50", 23, "telnet",
                 "Medium", "open"))
            conn.commit()
        from netmon import attacksurface as asm
        asm.build_report = lambda now=None: {
            "ok": True, "summary_line": "",
            "counts": {"High": 1, "Medium": 0, "Low": 0},
            "devices": [], "exposures": [], "lateral_paths": []}
        data = repm.compute_score(now=now)
        self.assertFalse(data["neutral"])
        self.assertEqual(data["score"], 66)
        by_kind = {}
        for f in data["factors"]:
            by_kind.setdefault(f["kind"], 0)
            by_kind[f["kind"]] += f["points"]
        self.assertEqual(by_kind["alerts"], 19)
        self.assertEqual(by_kind["incidents"], 5)
        self.assertEqual(by_kind["exposures"], 6)
        self.assertEqual(by_kind["vulns"], 4)
        # deterministic: same state, same score
        self.assertEqual(repm.compute_score(now=now)["score"], 66)

    def test_perfect_score_when_quiet(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 100)
        why = repm.explain_score(data)
        self.assertIn("Nothing pulled points off", why)

    def test_alert_cap(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        for i in range(10):  # 10 * 15 = 150, capped at 40
            self._alert("Critical", now - 3600, title=f"c{i}")
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 60)

    def test_dismissed_alerts_ignored(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("Critical", now - 3600, title="dismissed one",
                    status="dismissed")
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 100)

    def test_stale_flows_cost_ten(self):
        now = time.time()
        self._flow(now - 3600)  # last data an hour ago: flying blind
        self._no_exposures()
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 90)
        self.assertTrue(any(f["kind"] == "health"
                            for f in data["factors"]))

    def test_floor_at_zero(self):
        now = time.time()
        self._flow(now - 3600)  # stale: -10
        for i in range(10):
            self._alert("Critical", now - 3600, title=f"c{i}")  # capped -40
        for i in range(5):
            self._incident(f"case{i}", "High", "open", now - 3600)  # -15 cap
        from netmon import attacksurface as asm
        asm.build_report = lambda now=None: {
            "ok": True, "summary_line": "",
            "counts": {"High": 10, "Medium": 10, "Low": 10},
            "devices": [], "exposures": [], "lateral_paths": []}  # -15 cap
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 20)  # 100-40-15-15-10, floor holds
        # and it never goes negative
        for i in range(10):
            self._incident(f"more{i}", "High", "open", now - 3600)
        data = repm.compute_score(now=now)
        self.assertGreaterEqual(data["score"], 0)

    def test_escalated_case_costs_less_than_open(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._incident("open one", "High", "open", now - 3600)
        self._incident("esc one", "High", "escalated", now - 3600)
        data = repm.compute_score(now=now)
        self.assertEqual(data["score"], 92)  # 100 - 5 - 3

    def test_snapshot_and_history(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self.assertTrue(repm.maybe_daily_score(now=now))
        self.assertFalse(repm.maybe_daily_score(now=now))  # idempotent
        hist = repm.score_history(days=14)
        self.assertEqual(len(hist), 1)
        self.assertEqual(hist[0]["score"], 100)
        self.assertEqual(hist[0]["day"],
                         datetime.fromtimestamp(now).strftime("%Y-%m-%d"))

    def test_explain_names_top_factor(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600, title="bad thing")
        data = repm.compute_score(now=now)
        why = repm.explain_score(data)
        self.assertIn(str(data["score"]), why)
        self.assertIn("high-urgency", why)
        self.assertIn("To bring it up", why)
        # voice rule: no medical/doctor language
        for banned in ("doctor", "diagnos", "clinic", "patient",
                       "prescription", "symptom"):
            self.assertNotIn(banned, why.lower())


# --- morning briefing ---------------------------------------------------------


class BriefingTests(_DbTest):
    def _enable_smtp(self):
        os.environ["NETMON_SMTP_HOST"] = "localhost"
        os.environ["NETMON_ALERT_TO"] = "owner@example.com"
        self.addCleanup(lambda: os.environ.pop("NETMON_SMTP_HOST", None))
        self.addCleanup(lambda: os.environ.pop("NETMON_ALERT_TO", None))

    def test_window_boundaries(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 24 * 3600 - 1, title="too old")
        self._alert("High", now - 24 * 3600 + 1, title="just inside")
        self._alert("Medium", now, title="right now")
        brief = repm.build_briefing(now=now)
        self.assertIn("just inside", brief["body"])
        self.assertIn("right now", brief["body"])
        self.assertNotIn("too old", brief["body"])

    def test_dismissed_excluded_from_alerts(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600, title="dismissed one",
                    status="dismissed")
        brief = repm.build_briefing(now=now)
        self.assertNotIn("dismissed one", brief["body"].split(
            "QUIET WINS:")[0])

    def test_quiet_night(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        brief = repm.build_briefing(now=now)
        self.assertIn("Quiet night", brief["subject"])
        self.assertIn("Nothing needed your eyes", brief["body"])

    def test_sections_present(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600, title="port knock")
        brief = repm.build_briefing(now=now)
        for section in ("YOUR SCORE:", "ALERTS:", "CASES:",
                        "Open your dashboard:"):
            self.assertIn(section, brief["body"])
        self.assertIn("http://localhost:", brief["body"])

    def test_quiet_wins(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("Medium", now - 3600, title="noisy", status="dismissed")
        brief = repm.build_briefing(now=now)
        self.assertIn("QUIET WINS:", brief["body"])
        self.assertIn("dismissed 1 alert", brief["body"])

    def test_score_delta(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        yesterday = now - 24 * 3600
        with dbm._lock:
            conn = dbm._db()
            conn.execute(
                "INSERT INTO score_snapshots (day, ts, score, factors)"
                " VALUES (?,?,?,?)",
                (datetime.fromtimestamp(yesterday).strftime("%Y-%m-%d"),
                 yesterday, 90, "[]"))
            conn.commit()
        brief = repm.build_briefing(now=now)
        self.assertIn("up 10 from yesterday", brief["body"])

    def test_not_yet_before_hour(self):
        # briefing_hour far in the future: not time yet
        self._enable_smtp()
        import netmon.config as cfgm
        old = cfgm.load_cached
        cfgm.load_cached = lambda path=None: {"reporting": {
            "briefing_enabled": True, "briefing_hour": 23}}
        try:
            now = datetime.now().replace(hour=6, minute=0).timestamp()
            self.assertEqual(repm.maybe_daily_briefing(now=now), "not_yet")
        finally:
            cfgm.load_cached = old

    def test_quiet_hours_deferral(self):
        self._enable_smtp()
        import netmon.config as cfgm
        old = cfgm.load_cached
        cfgm.load_cached = lambda path=None: {"reporting": {
            "briefing_enabled": True, "briefing_hour": 0}}
        dbm.set_quiet_hours([{"days": [0, 1, 2, 3, 4, 5, 6],
                              "start": "00:00", "end": "23:59",
                              "kinds": ["all"]}])
        try:
            self.assertEqual(repm.maybe_daily_briefing(), "deferred_quiet")
            # nothing was recorded as sent
            self.assertIsNone(dbm.get_meta("last_briefing_day"))
        finally:
            cfgm.load_cached = old
            dbm.set_quiet_hours([])

    def test_send_once_per_day(self):
        self._enable_smtp()
        sent = []
        repm._SEND_FUNC = lambda s, b: sent.append((s, b)) or True
        import netmon.config as cfgm
        old = cfgm.load_cached
        cfgm.load_cached = lambda path=None: {"reporting": {
            "briefing_enabled": True, "briefing_hour": 0}}
        try:
            self.assertEqual(repm.maybe_daily_briefing(), "sent")
            self.assertEqual(len(sent), 1)
            self.assertEqual(repm.maybe_daily_briefing(), "already_sent")
            self.assertEqual(len(sent), 1)
        finally:
            cfgm.load_cached = old

    def test_sent_mime_has_all_sections(self):
        self._enable_smtp()
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600, title="port knock")
        self._alert("Medium", now - 7200, title="noisy", status="dismissed")
        captured = {}
        repm._SEND_FUNC = lambda s, b: captured.update(
            subject=s, body=b) or True
        ok, _reason = repm.send_briefing(now=now)
        self.assertTrue(ok)
        for section in ("YOUR SCORE:", "ALERTS:", "CASES:", "QUIET WINS:",
                        "Open your dashboard:"):
            self.assertIn(section, captured["body"])
        self.assertIn("port knock", captured["body"])

    def test_header_injection_cleaned(self):
        self._enable_smtp()
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600,
                    title="evil\r\nBcc: attacker@evil.example")
        captured = {}
        repm._SEND_FUNC = lambda s, b: captured.update(
            subject=s, body=b) or True
        repm.send_briefing(now=now)
        # no raw CR/LF from the alert title survives into the MIME text
        self.assertNotIn("\r", captured["subject"])
        self.assertNotIn("\r", captured["body"])
        self.assertNotIn("Bcc:", captured["subject"])

    def test_voice_rule_in_briefing(self):
        now = time.time()
        self._flow(now - 60)
        self._no_exposures()
        self._alert("High", now - 3600, title="something odd")
        brief = repm.build_briefing(now=now)
        for banned in ("doctor", "diagnos", "clinic", "patient",
                       "prescription", "symptom"):
            self.assertNotIn(banned, brief["body"].lower())


# --- compliance reports -------------------------------------------------------


class ComplianceTests(_DbTest):
    def _seed(self, now):
        self._flow(now - 60)
        aid = self._alert("High", now - 3600, kind="port_scan",
                          title="port scan from 203.0.113.7")
        iid = self._incident(
            "Suspicious activity involving 203.0.113.7", "High",
            "open", now - 3600)
        with dbm._lock:
            conn = dbm._db()
            conn.execute(
                "UPDATE alerts SET mitre_id=?, mitre_name=?,"
                " mitre_tactic=? WHERE id=?",
                ("T1046", "Network Service Discovery", "Discovery", aid))
            conn.execute(
                "INSERT INTO incident_alerts (incident_id, alert_id)"
                " VALUES (?,?)", (iid, aid))
            conn.execute(
                "INSERT INTO quarantines (mac, ip, state, created_ts,"
                " updated_ts, actor, note) VALUES (?,?,?,?,?,?,?)",
                ("aa:bb:cc:dd:ee:50", "192.168.1.50", "active",
                 now - 1800, now - 1800, "dashboard", "beaconing"))
            conn.execute(
                "INSERT INTO escalations (incident_id, ts, actor,"
                " admin_email, subject, sent_ok) VALUES (?,?,?,?,?,?)",
                (1, now - 900, "dashboard", "admin@example.com",
                 "escalation", 1))
            conn.commit()
        self._alert("Medium", now - 7200, title="chatty rule",
                    status="dismissed")
        with dbm._lock:
            conn = dbm._db()
            conn.execute("UPDATE alerts SET note=? WHERE title=?",
                         ("recognized backup traffic", "chatty rule"))
            conn.execute(
                "INSERT INTO score_snapshots (day, ts, score, factors)"
                " VALUES (?,?,?,?)",
                (datetime.fromtimestamp(now).strftime("%Y-%m-%d"),
                 now, 88, "[]"))
            conn.commit()

    def test_html_field_completeness(self):
        now = time.time()
        self._seed(now)
        data = repm.compliance_report_data(period="weekly", now=now)
        html_out = repm.compliance_html(data)
        for expected in (
                "Suspicious activity involving 203.0.113.7",  # incident
                "T1046", "Network Service Discovery",          # MITRE tags
                "port_scan",                                  # category
                "quarantine", "aa:bb:cc:dd:ee:50",             # response
                "escalated",                                  # escalation
                "dismissed", "recognized backup traffic",     # w/ reason
                "Alert volume by day", "Security score history",
                "88"):                                        # score
            self.assertIn(expected, html_out)

    def test_csv_field_completeness(self):
        now = time.time()
        self._seed(now)
        data = repm.compliance_report_data(period="weekly", now=now)
        text = repm.compliance_csv(data)
        for marker in ("# incidents", "# response actions",
                       "# alert volume by day", "# score history"):
            self.assertIn(marker, text)
        rows = list(csv.reader(io.StringIO(text)))
        flat = "\n".join(c for r in rows for c in r)
        for expected in ("T1046", "quarantine", "dismissed",
                         "recognized backup traffic", "port_scan"):
            self.assertIn(expected, flat)

    def test_empty_db_still_renders(self):
        data = repm.compliance_report_data(period="monthly")
        html_out = repm.compliance_html(data)
        self.assertIn("No incidents in this period", html_out)
        text = repm.compliance_csv(data)
        self.assertIn("# incidents", text)

    def test_csv_neutralizes_formula_injection(self):
        # Council review: alert titles embed LAN-observed DNS names, so a
        # hostile hostname must not become a live spreadsheet formula.
        now = time.time()
        self._incident("=cmd|'/c calc'!A0", "High", "open", now - 60)
        data = repm.compliance_report_data(period="weekly", now=now)
        text = repm.compliance_csv(data)
        rows = list(csv.reader(io.StringIO(text)))
        title_cells = [c for r in rows for c in r if "calc" in c]
        self.assertTrue(title_cells, "seeded title missing from CSV")
        for cell in title_cells:
            self.assertTrue(cell.startswith("'="),
                            f"formula not neutralized: {cell!r}")

    def test_monthly_window(self):
        now = time.time()
        self._alert("High", now - 10 * 24 * 3600, title="old one")
        data = repm.compliance_report_data(period="weekly", now=now)
        self.assertEqual(data["volume"], [])
        data = repm.compliance_report_data(period="monthly", now=now)
        self.assertEqual(len(data["volume"]), 1)


# --- forensic rewind ----------------------------------------------------------


class RewindTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="rewind-test-")
        self._old_enabled = rwm._ENABLED
        self._old_dir = rwm.rewind_dir
        self._old_caps = rwm._caps
        self._old_seg = rwm.SEGMENT_SECONDS
        self._old_diskok = rwm._disk_ok
        rwm._ENABLED = True
        rwm.rewind_dir = lambda: __import__("pathlib").Path(self.tmp)
        # The sandbox /tmp may be nearly full; the disk guard is tested
        # separately in test_low_disk_pauses_recording.
        rwm._disk_ok = lambda _d: True

    def tearDown(self):
        rwm._reset_for_tests()
        rwm._ENABLED = self._old_enabled
        rwm.rewind_dir = self._old_dir
        rwm._caps = self._old_caps
        rwm.SEGMENT_SECONDS = self._old_seg
        rwm._disk_ok = self._old_diskok
        import shutil
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _rec(self, payload, ts):
        rwm.record_packet(payload, ts)

    def _parse(self, blob):
        # returns (packets, bad_header)
        self.assertTrue(blob.startswith(b"%PDF") is False)
        magic = struct.unpack("<I", blob[:4])[0]
        self.assertEqual(magic, 0xA1B2C3D4)
        off = 24
        pkts = []
        while off + 16 <= len(blob):
            sec, usec, incl, _orig = struct.unpack_from("<IIII", blob, off)
            off += 16
            pkts.append((sec + usec / 1e6, blob[off:off + incl]))
            off += incl
        return pkts

    def test_record_and_window_export(self):
        base = time.time()
        self._rec(b"pkt-old", base - 300)
        self._rec(b"pkt-in", base - 100)
        self._rec(b"pkt-new", base + 100)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        # Read the window end AFTER recording: segment files are named
        # by rotation wall-clock second, and export_window() prunes any
        # segment with start > end_ts. A whole-second boundary crossing
        # between the `base` capture and the recording rotation would
        # otherwise silently drop the segment and flake the count to 0.
        end = time.time()
        blob, count = rwm.export_window(base - 200, end)
        pkts = self._parse(blob)
        self.assertEqual(count, 1)
        self.assertEqual(len(pkts), 1)
        self.assertEqual(pkts[0][1], b"pkt-in")
        self.assertAlmostEqual(pkts[0][0], base - 100, places=3)

    def test_empty_window_is_valid_pcap(self):
        base = time.time()
        self._rec(b"pkt", base - 10)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        blob, count = rwm.export_window(base + 1000, base + 2000)
        self.assertEqual(count, 0)
        pkts = self._parse(blob)  # header only: still opens in Wireshark
        self.assertEqual(pkts, [])

    def test_size_cap_evicts_oldest(self):
        rwm.SEGMENT_SECONDS = 0  # rotate on every packet
        rwm._caps = lambda: (60.0, 3000)  # tiny disk cap
        base = time.time()
        for i in range(5):
            self._rec(b"x" * 800, base + i)
        rwm._reset_for_tests()  # flush everything to disk first
        rwm._ENABLED = True
        kept, _freed = rwm.enforce_caps(now=base + 10)
        # 5 segments ~840B each = ~4200B > 3000: oldest two go
        self.assertEqual(kept, 3)
        names = sorted(os.listdir(self.tmp))
        self.assertEqual(len(names), 3)

    def test_time_cap_evicts_old(self):
        base = time.time()
        self._rec(b"pkt", base)
        rwm._reset_for_tests()
        rwm._ENABLED = True
        rwm._caps = lambda: (0.0001, 10 * 1024 * 1024)  # ~instant expiry
        kept, _freed = rwm.enforce_caps(now=base + 3600)
        self.assertEqual(kept, 0)
        self.assertEqual(os.listdir(self.tmp), [])

    def test_low_disk_pauses_recording(self):
        old = rwm._disk_ok
        rwm._disk_ok = lambda _d: False
        try:
            self._rec(b"pkt", time.time())
            rwm._reset_for_tests()
            rwm._ENABLED = True
            self.assertEqual(os.listdir(self.tmp), [])
        finally:
            rwm._disk_ok = old

    def test_disabled_records_nothing(self):
        rwm._ENABLED = False
        self._rec(b"pkt", time.time())
        rwm._reset_for_tests()
        self.assertEqual(os.listdir(self.tmp), [])

    def test_status_labels(self):
        st = rwm.status()
        self.assertTrue(st["enabled"])
        self.assertIn("whichever fills first", st["retention"])
        self.assertIn("RAW packets", st["privacy_note"])
        self.assertIn("never sent", st["privacy_note"])


class RewindIncidentTests(_DbTest):
    def test_incident_window_padding_and_export(self):
        tmp = tempfile.mkdtemp(prefix="rewind-inc-")
        old_dir, old_en = rwm.rewind_dir, rwm._ENABLED
        old_diskok = rwm._disk_ok
        rwm.rewind_dir = lambda: __import__("pathlib").Path(tmp)
        rwm._ENABLED = True
        rwm._disk_ok = lambda _d: True
        try:
            # Record BEFORE capturing the reference clock: segment files
            # are named by rotation wall-clock second, and export_window()
            # prunes any segment with start > end_ts. Capturing `now`
            # first meant a whole-second boundary crossing before the
            # recording rotation silently dropped the segment and flaked
            # the export count to 0 (seen 2026-10-05: 0 != 1).
            rwm.record_packet(b"inside", time.time() - 500)
            rwm.record_packet(b"outside", time.time() - 3600 * 5)
            rwm._reset_for_tests()
            rwm._ENABLED = True
            now = time.time()
            a1 = self._alert("High", now - 600, title="first")
            a2 = self._alert("High", now - 300, title="second")
            iid = self._incident("case", "High", "open", now - 600,
                                 alert_ids=(a1, a2))
            # packet inside the padded window, packet outside it
            window = rwm.incident_window(iid)
            self.assertIsNotNone(window)
            start, end = window
            self.assertLessEqual(start, now - 600 - 300 + 1)
            self.assertGreaterEqual(end, now - 300 + 300 - 1)
            blob, count = rwm.export_window(start, end)
            self.assertEqual(count, 1)
            self.assertIn(b"inside", blob)
            self.assertNotIn(b"outside", blob)
            self.assertIsNone(rwm.incident_window(999999))
        finally:
            rwm._reset_for_tests()
            rwm.rewind_dir = old_dir
            rwm._ENABLED = old_en
            rwm._disk_ok = old_diskok
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)


@unittest.skipIf(dashm is None, "Flask not installed")
class RewindRouteTests(_DbTest):
    def test_export_path_traversal_blocked(self):
        client = dashm.app.test_client()
        r = client.get("/api/rewind/export?incident_id=../../etc/passwd")
        self.assertEqual(r.status_code, 400)
        r = client.get("/api/rewind/export?incident_id=-5")
        self.assertEqual(r.status_code, 400)
        r = client.get("/api/rewind/export")
        self.assertEqual(r.status_code, 400)
        r = client.get("/api/rewind/export?start=1&end=999999999")
        self.assertEqual(r.status_code, 400)  # >24h window refused
        r = client.get("/api/rewind/export?incident_id=424242")
        self.assertEqual(r.status_code, 404)

    def test_export_filename_is_safe(self):
        client = dashm.app.test_client()
        now = time.time()
        a1 = self._alert("High", now - 60, title="x")
        iid = self._incident("case", "High", "open", now - 60,
                             alert_ids=(a1,))
        tmp = tempfile.mkdtemp(prefix="rewind-route-")
        old_dir, old_en = rwm.rewind_dir, rwm._ENABLED
        old_diskok = rwm._disk_ok
        rwm.rewind_dir = lambda: __import__("pathlib").Path(tmp)
        rwm._ENABLED = True
        rwm._disk_ok = lambda _d: True
        try:
            rwm.record_packet(b"pkt", now - 30)
            rwm._reset_for_tests()
            rwm._ENABLED = True
            r = client.get(f"/api/rewind/export?incident_id={iid}")
            self.assertEqual(r.status_code, 200)
            cd = r.headers.get("Content-Disposition", "")
            self.assertIn(f"incident-{iid}-window.pcap", cd)
            self.assertNotIn("..", cd)
            self.assertEqual(r.headers.get("X-Packets"), "1")
            self.assertTrue(r.data.startswith(
                struct.pack("<I", 0xA1B2C3D4)))
        finally:
            rwm._reset_for_tests()
            rwm.rewind_dir = old_dir
            rwm._ENABLED = old_en
            rwm._disk_ok = old_diskok
            import shutil
            shutil.rmtree(tmp, ignore_errors=True)

    def test_score_and_briefing_routes(self):
        client = dashm.app.test_client()
        now = time.time()
        self._flow(now - 60)
        r = client.get("/api/score")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertEqual(d["score"], 100)
        self.assertIn("why", d)
        r = client.get("/api/briefing/preview")
        self.assertEqual(r.status_code, 200)
        d = json.loads(r.data)
        self.assertIn("subject", d)
        self.assertIn("body", d)

    def test_compliance_and_pdf_routes(self):
        client = dashm.app.test_client()
        r = client.get("/reports/compliance.csv?period=weekly")
        self.assertEqual(r.status_code, 200)
        self.assertIn("attachment", r.headers.get("Content-Disposition",
                                                  ""))
        r = client.get("/reports/compliance.csv?period=bogus")
        self.assertEqual(r.status_code, 400)
        r = client.get("/reports/compliance.html?period=monthly")
        self.assertEqual(r.status_code, 200)
        r = client.get("/reports/weekly.pdf")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.data.startswith(b"%PDF-1.4"))
        r = client.get("/reports/incident/424242.pdf")
        self.assertEqual(r.status_code, 404)

    def test_reports_section_renders(self):
        client = dashm.app.test_client()
        r = client.get("/")
        self.assertEqual(r.status_code, 200)
        for marker in ('id="reports"', 'id="scorecard"',
                       'id="briefingpreview"', 'id="rewindstatus"',
                       "/reports/weekly.pdf", "/api/score"):
            self.assertIn(marker, r.data.decode("utf-8", "replace"))


# --- PDF writer ----------------------------------------------------------------


def _validate_pdf(testcase, blob, expect_pages):
    testcase.assertTrue(blob.startswith(b"%PDF-1.4"), "header")
    # xref must parse: startxref points at "xref", each offset hits "N 0 obj"
    m = re.search(rb"startxref\s+(\d+)\s*%%EOF\s*$", blob)
    testcase.assertIsNotNone(m, "startxref trailer")
    xref_at = int(m.group(1))
    testcase.assertTrue(blob[xref_at:xref_at + 4] == b"xref", "xref table")
    m2 = re.search(rb"0 (\d+)\s*\n", blob[xref_at:xref_at + 40])
    testcase.assertIsNotNone(m2)
    count = int(m2.group(1))
    # xref entries are fixed 20-byte lines after the 3-line head
    # ("xref", "0 N", free entry)
    head_end = blob.index(b"\n", xref_at)  # "xref"
    head_end = blob.index(b"\n", head_end + 1)  # "0 N"
    head_end = blob.index(b"\n", head_end + 1)  # free entry
    for i in range(1, count):
        entry = blob[head_end + 1 + (i - 1) * 20:
                     head_end + 1 + i * 20]
        off = int(entry[:10])
        testcase.assertTrue(
            blob[off:off + len(f"{i} 0 obj".encode())] ==
            f"{i} 0 obj".encode(),
            f"xref entry {i}")
    m3 = re.search(rb"/Count (\d+)", blob)
    testcase.assertIsNotNone(m3)
    testcase.assertEqual(int(m3.group(1)), expect_pages)


class PdfTests(unittest.TestCase):
    def test_simple_doc(self):
        doc = pdfgen.PdfDoc(title="Test report", subtitle="demo")
        doc.heading("Heading one")
        doc.body("A plain body paragraph with some words in it.")
        doc.bullet("first bullet")
        doc.bullet("second bullet")
        blob = doc.build()
        _validate_pdf(self, blob, 1)
        text = pdfgen.extract_text(blob)
        for s in ("Test report", "Heading one",
                  "A plain body paragraph", "first bullet"):
            self.assertIn(s, text)

    def test_multipage(self):
        doc = pdfgen.PdfDoc(title="Long report")
        for i in range(120):
            doc.body(f"Line number {i} with enough words to fill space.")
        blob = doc.build()
        m = re.search(rb"/Count (\d+)", blob)
        self.assertGreater(int(m.group(1)), 1)
        _validate_pdf(self, blob, int(m.group(1)))
        text = pdfgen.extract_text(blob)
        self.assertIn("Line number 0", text)
        self.assertIn("Line number 119", text)

    def test_malicious_text_cannot_break_pdf(self):
        nasty = ("paren (attack) and \\ backslash \r\n newline"
                 " \u0001 control \U0001F600 emoji \xe9 latin")
        doc = pdfgen.PdfDoc(title=nasty)
        doc.body(nasty)
        doc.table(["H1", "H2"], [[nasty, "ok"], ["ok", nasty]])
        blob = doc.build()
        _validate_pdf(self, blob, 1)
        text = pdfgen.extract_text(blob)
        self.assertIn("paren", text)
        self.assertIn("attack", text)
        # raw control chars / newlines never leak into the content stream
        self.assertNotIn("\r", text)

    def test_table_layout(self):
        doc = pdfgen.PdfDoc(title="Tables")
        doc.table(["A", "B", "C"],
                  [["a1", "b1", "c1"],
                   ["a much longer cell that must wrap onto two lines", "b2",
                    "c2"]],
                  widths=[150, 150, 168])
        blob = doc.build()
        _validate_pdf(self, blob, 1)
        self.assertIn("a much longer cell", pdfgen.extract_text(blob))


class PdfReportTests(_DbTest):
    def test_incident_pdf(self):
        now = time.time()
        a1 = self._alert("High", now - 600, kind="port_scan",
                         title="port scan from 203.0.113.7")
        with dbm._lock:
            conn = dbm._db()
            conn.execute(
                "UPDATE alerts SET mitre_id=?, mitre_name=?,"
                " what_to_do=? WHERE id=?",
                ("T1046", "Network Service Discovery",
                 "Check whether you recognize the scanner.", a1))
            conn.commit()
        iid = self._incident("Suspicious activity involving 203.0.113.7",
                             "High", "open", now - 600, alert_ids=(a1,))
        blob = repm.incident_pdf_bytes(iid)
        self.assertIsNotNone(blob)
        _validate_pdf(self, blob, 1)
        text = pdfgen.extract_text(blob)
        self.assertIn("203.0.113.7", text)
        self.assertIn("T1046", text)

    def test_incident_pdf_missing(self):
        self.assertIsNone(repm.incident_pdf_bytes(424242))

    def test_weekly_pdf(self):
        now = time.time()
        self._flow(now - 3600, size=5_000_000)
        self._alert("Medium", now - 7200, title="something")
        blob = repm.weekly_pdf_bytes(now=now)
        self.assertIsNotNone(blob)
        _validate_pdf(self, blob, 1)
        text = pdfgen.extract_text(blob)
        self.assertIn("Your network this week", text)


if __name__ == "__main__":
    unittest.main()
