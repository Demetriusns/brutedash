"""Tests for the Phase 3.5 batch 11 Nuclei integration (2026-10-04):
Nuclei-powered self vulnerability scan of our OWN LAN.

- JSONL parsing with fixture data (real nuclei JSONL shape -- crafted
  fixtures, NEVER a live scan in tests).
- Target scoping: non-RFC1918 targets rejected by build_argv; the
  dashboard can never supply a target (the route ignores any body).
- Severity mapping + configurable filter behavior.
- -dut (and -duc, -silent) always present in argv; no shell=True.
- Missing-binary degrade path: clear install note, no errors.
- Storage + diffing: first run is the silent baseline; later runs alert
  only on genuinely new findings (capped); repeats stay quiet.
- MITRE tags exist for the new alert kind.

Live nuclei scans are NEVER run in tests (run_scan is mocked).
"""
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import nuclei as nucleim
from netmon import mitre as mitrem

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None


def _fresh_db():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    old_path, old_conn = dbm.DB_PATH, dbm._conn
    dbm.DB_PATH = tmp.name
    dbm._conn = None
    return tmp.name, old_path, old_conn


class _DbTest(unittest.TestCase):
    def setUp(self):
        self._db_tmp, self._old_path, self._old_conn = _fresh_db()

    def tearDown(self):
        dbm.DB_PATH, dbm._conn = self._old_path, self._old_conn
        try:
            os.unlink(self._db_tmp)
        except OSError:
            pass


# --- realistic fixture: nuclei -jsonl output shape (crafted, not live) --------

_FIXTURE_LINES = [
    # http template with CVE classification
    json.dumps({
        "template-id": "http-missing-security-headers",
        "info": {
            "name": "HTTP Missing Security Headers",
            "author": ["pd-team"],
            "tags": ["misconfig", "http"],
            "severity": "medium",
            "description": "The server is missing security headers.",
            "reference": ["https://example.com/headers"],
            "classification": {
                "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N",
                "cvss-score": 5.3,
                "cve-id": ["CVE-2024-12345"],
                "cwe-id": ["CWE-693"],
            },
        },
        "type": "http",
        "host": "http://192.168.1.10:8080",
        "matched-at": "http://192.168.1.10:8080/",
        "ip": "192.168.1.10",
        "timestamp": "2026-10-04T00:00:00.000Z",
        "matcher-status": True,
    }),
    # ssl template, severity high, ip must be derived from host URL
    json.dumps({
        "template-id": "ssl-deprecated-tls",
        "info": {
            "name": "Deprecated TLS Version",
            "severity": "high",
            "description": "TLS 1.0 is enabled.",
            "tags": ["ssl", "cve-2024-99999"],
        },
        "type": "ssl",
        "host": "https://192.168.1.11:443",
        "matched-at": "https://192.168.1.11:443",
        "timestamp": "2026-10-04T00:00:00.000Z",
    }),
    # info-severity: stored but must never alert
    json.dumps({
        "template-id": "tech-detect",
        "info": {"name": "Tech Detect", "severity": "info"},
        "type": "http",
        "host": "http://192.168.1.10",
        "matched-at": "http://192.168.1.10/",
        "ip": "192.168.1.10",
        "timestamp": "2026-10-04T00:00:00.000Z",
    }),
    # garbage lines are skipped, never fatal
    "this is not json",
    json.dumps(["not", "a", "dict"]),
    json.dumps({"no-template-id": True}),
]


class ParseTests(unittest.TestCase):
    def test_fixture_parses_to_findings(self):
        findings = nucleim.parse_jsonl_text("\n".join(_FIXTURE_LINES))
        self.assertEqual(len(findings), 3)
        by_id = {f["template_id"]: f for f in findings}
        http_f = by_id["http-missing-security-headers"]
        self.assertEqual(http_f["ip"], "192.168.1.10")
        self.assertEqual(http_f["name"], "HTTP Missing Security Headers")
        self.assertEqual(http_f["severity"], "Medium")  # medium -> Medium
        self.assertEqual(http_f["nuclei_severity"], "medium")
        self.assertEqual(http_f["cves"], "CVE-2024-12345")
        self.assertEqual(http_f["matched_at"],
                         "http://192.168.1.10:8080/")

    def test_ip_derived_from_host_when_missing(self):
        findings = nucleim.parse_jsonl_text("\n".join(_FIXTURE_LINES))
        by_id = {f["template_id"]: f for f in findings}
        ssl_f = by_id["ssl-deprecated-tls"]
        self.assertEqual(ssl_f["ip"], "192.168.1.11")
        self.assertEqual(ssl_f["severity"], "High")  # high -> High
        # CVE picked up from a tag shaped like one
        self.assertIn("CVE-2024-99999", ssl_f["cves"])

    def test_info_severity_never_alerts(self):
        findings = nucleim.parse_jsonl_text("\n".join(_FIXTURE_LINES))
        by_id = {f["template_id"]: f for f in findings}
        self.assertIsNone(by_id["tech-detect"]["severity"])

    def test_garbage_lines_skipped(self):
        self.assertEqual(nucleim.parse_jsonl_text(""), [])
        self.assertEqual(nucleim.parse_jsonl_text("not json\n{{{\n"), [])
        self.assertEqual(nucleim.parse_jsonl_file("/nonexistent/x.jsonl"),
                         [])

    def test_critical_maps_to_high_not_critical(self):
        line = json.dumps({
            "template-id": "rce-check",
            "info": {"name": "RCE", "severity": "CRITICAL"},
            "ip": "192.168.1.5", "matched-at": "http://192.168.1.5/"})
        f = nucleim.parse_jsonl_text(line)[0]
        self.assertEqual(f["severity"], "High")

    def test_unknown_severity_maps_to_none(self):
        line = json.dumps({
            "template-id": "weird",
            "info": {"name": "Weird", "severity": "banana"},
            "ip": "192.168.1.5", "matched-at": "http://192.168.1.5/"})
        f = nucleim.parse_jsonl_text(line)[0]
        self.assertIsNone(f["severity"])


class SeverityFilterTests(unittest.TestCase):
    def test_default_floor_is_medium(self):
        with mock.patch.object(nucleim, "_nuclei_cfg",
                               return_value="medium"):
            self.assertEqual(nucleim.min_severity(), "medium")
            self.assertTrue(nucleim.passes_filter("medium"))
            self.assertTrue(nucleim.passes_filter("high"))
            self.assertTrue(nucleim.passes_filter("critical"))
            self.assertFalse(nucleim.passes_filter("low"))
            self.assertFalse(nucleim.passes_filter("info"))
            self.assertFalse(nucleim.passes_filter("banana"))

    def test_floor_can_be_raised(self):
        with mock.patch.object(nucleim, "_nuclei_cfg",
                               return_value="high"):
            self.assertFalse(nucleim.passes_filter("medium"))
            self.assertTrue(nucleim.passes_filter("critical"))

    def test_bad_config_falls_back_to_medium(self):
        with mock.patch.object(nucleim, "_nuclei_cfg",
                               return_value="everything"):
            self.assertEqual(nucleim.min_severity(), "medium")

    def test_severity_csv_covers_floor_and_above(self):
        with mock.patch.object(nucleim, "_nuclei_cfg",
                               return_value="medium"):
            self.assertEqual(nucleim._severity_csv(),
                             "medium,high,critical")


class ArgvTests(unittest.TestCase):
    def _argv(self, targets, **cfg):
        with mock.patch.object(nucleim, "find_binary",
                               return_value="/usr/bin/nuclei"), \
             mock.patch.object(nucleim, "_nuclei_cfg",
                               side_effect=lambda k, d: cfg.get(k, d)):
            argv, timeout_min = nucleim.build_argv(
                targets, "/tmp/t.txt", "/tmp/o.jsonl")
        return argv

    def test_dut_always_present(self):
        argv = self._argv(["192.168.1.10", "10.0.0.5"])
        self.assertIn("-dut", argv)
        self.assertIn("-duc", argv)
        self.assertIn("-silent", argv)
        self.assertIn("-jsonl", argv)

    def test_targets_travel_in_file_not_argv(self):
        argv = self._argv(["192.168.1.10"])
        self.assertIn("-l", argv)
        # no target IP appears as its own argv element
        self.assertNotIn("192.168.1.10", argv)

    def test_no_shell(self):
        # build_argv returns a list -- callers must not shell-expand it.
        argv = self._argv(["192.168.1.10"])
        self.assertIsInstance(argv, list)

    def test_non_lan_targets_rejected(self):
        for bad in ["8.8.8.8", "93.184.216.34", "2001:db8::1",
                    "example.com", "192.168.1.10; rm -rf /",
                    "192.168.1.10\n8.8.8.8", "", None, "999.999.1.1"]:
            with self.assertRaises(ValueError, msg=f"target {bad!r}"):
                self._argv([bad])
            with self.assertRaises(ValueError,
                                   msg=f"mixed list with {bad!r}"):
                self._argv(["192.168.1.10", bad])

    def test_loopback_and_rfc1918_accepted(self):
        argv = self._argv(["127.0.0.1", "192.168.1.10", "10.1.2.3",
                           "172.16.5.5"])
        self.assertIn("-l", argv)

    def test_test_net_ranges_rejected(self):
        # documentation/test ranges are NOT scannable (same rule as the
        # built-in scan: explicit RFC1918, not is_private).
        with self.assertRaises(ValueError):
            self._argv(["192.0.2.10"])
        with self.assertRaises(ValueError):
            self._argv(["203.0.113.7"])

    def test_empty_targets_rejected(self):
        with self.assertRaises(ValueError):
            self._argv([])

    def test_missing_binary_rejected(self):
        with mock.patch.object(nucleim, "find_binary",
                               return_value=None):
            with self.assertRaises(ValueError):
                nucleim.build_argv(["192.168.1.10"], "/tmp/t", "/tmp/o")

    def test_severity_flag_matches_config(self):
        argv = self._argv(["192.168.1.10"], min_severity="high")
        i = argv.index("-severity")
        self.assertEqual(argv[i + 1], "high,critical")


class BinaryDegradeTests(unittest.TestCase):
    def test_check_binary_missing_gives_install_note(self):
        with mock.patch.object(nucleim, "find_binary", return_value=None):
            ok, note = nucleim.check_binary()
        self.assertFalse(ok)
        self.assertIn("not installed", note)
        self.assertIn("github.com/projectdiscovery/nuclei", note)

    def test_run_scan_without_binary_is_clean_error(self):
        with mock.patch.object(nucleim, "find_binary", return_value=None):
            res = nucleim.run_scan(["192.168.1.10"])
        self.assertFalse(res["ok"])
        self.assertIn("not installed", res["error"])

    def test_status_without_binary(self):
        with mock.patch.object(nucleim, "find_binary", return_value=None):
            st = nucleim.nuclei_status()
        self.assertFalse(st["installed"])
        self.assertIn("not installed", st["install_note"])
        self.assertEqual(st["findings"], [])
        self.assertIsNone(st["last_run"])

    def test_maybe_weekly_skips_silently_without_binary(self):
        with mock.patch.object(nucleim, "nuclei_enabled",
                               return_value=True), \
             mock.patch.object(nucleim, "find_binary", return_value=None):
            self.assertIsNone(nucleim.maybe_weekly_nuclei())

    def test_maybe_weekly_skips_when_disabled(self):
        with mock.patch.object(nucleim, "nuclei_enabled",
                               return_value=False), \
             mock.patch.object(nucleim, "find_binary",
                               return_value="/usr/bin/nuclei"):
            self.assertIsNone(nucleim.maybe_weekly_nuclei())


class StorageDiffTests(_DbTest):
    def _finding(self, ip="192.168.1.10", tid="t1", sev="Medium",
                 ma="http://192.168.1.10/"):
        return {"ip": ip, "template_id": tid, "name": "T " + tid,
                "severity": sev, "nuclei_severity": sev.lower(),
                "matched_at": ma, "description": "d", "cves": ""}

    def test_same_door_two_sources_coexist(self):
        # The findings identity is (source, ip, port): the built-in scan
        # and a template check may report the same door without an
        # IntegrityError (council review fix).
        now = time.time()
        dbm.record_scan_findings(now, [
            ("192.168.1.10", "aa:bb:cc:dd:ee:ff", 23, "Telnet",
             "Medium", "builtin says telnet")], source="builtin")
        dbm.record_scan_findings(now, [
            ("192.168.1.10", "aa:bb:cc:dd:ee:ff", 23, "Telnet",
             "Medium", "template says telnet")], source="template")
        rows = dbm.list_scan_findings(status="open", limit=10)
        self.assertEqual(len(rows), 2)
        self.assertEqual({r["source"] for r in rows},
                         {"builtin", "template"})

    def test_old_db_migrates_to_source_key(self):
        # Simulate a pre-batch-11 database: UNIQUE(ip, port), no source
        # column. Connecting must rebuild the table; old rows survive as
        # builtin.
        import sqlite3
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        tmp.close()
        old_path, old_conn = dbm.DB_PATH, dbm._conn
        try:
            raw = sqlite3.connect(tmp.name)
            raw.execute(
                "CREATE TABLE scan_findings(id INTEGER PRIMARY KEY,"
                " run_ts REAL, ip TEXT, mac TEXT, port INTEGER,"
                " service TEXT, risk TEXT, what_it_means TEXT,"
                " status TEXT NOT NULL DEFAULT 'open',"
                " UNIQUE(ip, port))")
            raw.execute(
                "INSERT INTO scan_findings (run_ts, ip, mac, port,"
                " service, risk, what_it_means, status)"
                " VALUES (1000.0, '192.168.1.10', 'aa:bb:cc:dd:ee:ff', 23,"
                " 'Telnet', 'Medium', 'old row', 'open')")
            raw.commit()
            raw.close()
            dbm.DB_PATH, dbm._conn = tmp.name, None
            migrated = dbm._connect()  # runs the schema + migrations
            migrated.close()
            rows = dbm.list_scan_findings(status="open")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["source"], "builtin")
            self.assertEqual(rows[0]["port"], 23)
            # and the new triple-key works on the migrated table
            dbm.record_scan_findings(
                2000.0, [("192.168.1.10", "aa:bb:cc:dd:ee:ff", 23,
                          "Telnet", "Medium", "template row")],
                source="template")
            self.assertEqual(
                len(dbm.list_scan_findings(status="open")), 2)
        finally:
            dbm.DB_PATH, dbm._conn = old_path, old_conn
            try:
                os.unlink(tmp.name)
            except OSError:
                pass


    def test_first_run_is_baseline_no_alerts(self):
        findings = [self._finding()]
        new, resolved, changed = dbm.record_nuclei_findings(1000.0,
                                                            findings)
        self.assertEqual(len(new), 1)
        self.assertEqual(resolved, [])
        # run_full_nuclei_scan treats the first-ever run as silent; the
        # storage layer reports what changed (the caller decides).
        rows = dbm.list_nuclei_findings()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["severity"], "Medium")

    def test_repeat_run_stays_quiet(self):
        f = [self._finding()]
        dbm.record_nuclei_findings(1000.0, f)
        new, resolved, changed = dbm.record_nuclei_findings(2000.0, f)
        self.assertEqual(new, [])
        self.assertEqual(resolved, [])
        self.assertEqual(changed, [])

    def test_vanished_finding_resolves(self):
        dbm.record_nuclei_findings(1000.0, [self._finding()])
        new, resolved, changed = dbm.record_nuclei_findings(2000.0, [])
        self.assertEqual(len(resolved), 1)
        self.assertEqual(dbm.list_nuclei_findings(), [])

    def test_severity_change_counts_as_changed(self):
        dbm.record_nuclei_findings(1000.0, [self._finding(sev="Medium")])
        new, resolved, changed = dbm.record_nuclei_findings(
            2000.0, [self._finding(sev="High")])
        self.assertEqual(new, [])
        self.assertEqual(len(changed), 1)

    def test_run_history(self):
        dbm.record_nuclei_run(1000.0, 12.5, 8, 3, 1, note="manual")
        lr = dbm.latest_nuclei_run()
        self.assertEqual(lr["targets"], 8)
        self.assertEqual(lr["findings"], 3)
        self.assertEqual(lr["new_findings"], 1)
        self.assertEqual(lr["note"], "manual")

    def test_min_severity_filter_on_listing(self):
        dbm.record_nuclei_findings(1000.0, [
            self._finding(tid="m", sev="Medium"),
            self._finding(tid="l", sev="Low"),
            self._finding(tid="h", sev="High")])
        got = {f["template_id"] for f in dbm.list_nuclei_findings(
            min_severity="Medium")}
        self.assertEqual(got, {"m", "h"})

    def test_open_counts_by_ip(self):
        dbm.record_nuclei_findings(1000.0, [
            self._finding(ip="192.168.1.10", tid="a", sev="Medium"),
            self._finding(ip="192.168.1.10", tid="b", sev="Low"),
            self._finding(ip="192.168.1.11", tid="c", sev="High")])
        counts = dbm.nuclei_open_counts_by_ip()
        # only Medium+ count toward the attack-surface view
        self.assertEqual(counts, {"192.168.1.10": 1, "192.168.1.11": 1})


class FullScanFlowTests(_DbTest):
    """run_full_nuclei_scan with a mocked subprocess: first run silent,
    second run alerts only on the new finding, third identical run
    silent again."""

    def _fake_run_scan(self, findings_text):
        def _fake(targets):
            work = tempfile.mkdtemp(prefix="test-nuclei-")
            out = os.path.join(work, "n.jsonl")
            with open(out, "w") as fh:
                fh.write(findings_text)
            return {"ok": True, "jsonl_path": out, "work_dir": work,
                    "duration_s": 1.0, "version": "v3.0.0-test"}
        return _fake

    def _line(self, tid, sev, ip="192.168.1.10"):
        return json.dumps({
            "template-id": tid,
            "info": {"name": "Name " + tid, "severity": sev},
            "ip": ip, "matched-at": f"http://{ip}/",
            "timestamp": "2026-10-04T00:00:00Z"})

    def test_baseline_then_new_then_quiet(self):
        run1 = self._line("t1", "medium")
        run2 = run1 + "\n" + self._line("t2", "high")
        with mock.patch.object(nucleim, "nuclei_targets",
                               return_value=["192.168.1.10"]), \
             mock.patch.object(nucleim, "run_scan",
                               side_effect=[self._fake_run_scan(run1)
                                            (["192.168.1.10"]),
                                            self._fake_run_scan(run2)
                                            (["192.168.1.10"]),
                                            self._fake_run_scan(run2)
                                            (["192.168.1.10"])]):
            r1 = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["alerts"], 0)  # baseline: silent
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

            r2 = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r2["ok"])
            self.assertEqual(r2["new"], 1)
            kinds = [row[0] for row in
                     dbm.query("SELECT kind FROM alerts")]
            self.assertEqual(kinds, ["nuclei_finding"])
            sev = dbm.query("SELECT severity FROM alerts")[0][0]
            self.assertEqual(sev, "High")  # high -> High
            self.assertIn("t2", dbm.query(
                "SELECT title FROM alerts")[0][0])

            r3 = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r3["ok"])
            self.assertEqual(r3["new"], 0)
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 1)

    def test_low_severity_finding_never_alerts(self):
        run = self._line("tlow", "low")
        with mock.patch.object(nucleim, "nuclei_targets",
                               return_value=["192.168.1.10"]), \
             mock.patch.object(nucleim, "run_scan",
                               side_effect=[self._fake_run_scan(run)
                                            (["192.168.1.10"]),
                                            self._fake_run_scan(run)
                                            (["192.168.1.10"])]):
            nucleim.run_full_nuclei_scan(note="test")
            nucleim.run_full_nuclei_scan(note="test")
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)
            # ...but it IS stored
            self.assertEqual(len(dbm.list_nuclei_findings()), 1)

    def test_non_lan_finding_dropped(self):
        evil = self._line("evil", "critical", ip="93.184.216.34")
        with mock.patch.object(nucleim, "nuclei_targets",
                               return_value=["192.168.1.10"]), \
             mock.patch.object(nucleim, "run_scan",
                               side_effect=[self._fake_run_scan(evil)
                                            (["192.168.1.10"]),
                                            self._fake_run_scan(evil)
                                            (["192.168.1.10"])]):
            r = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r["ok"])
            r2 = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r2["ok"])
            self.assertEqual(len(dbm.list_nuclei_findings()), 0)
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

    def test_failed_scan_is_missed_not_crash(self):
        with mock.patch.object(nucleim, "nuclei_targets",
                               return_value=["192.168.1.10"]), \
             mock.patch.object(nucleim, "run_scan",
                               return_value={"ok": False,
                                             "error": "boom"}):
            r = nucleim.run_full_nuclei_scan(note="test")
            self.assertFalse(r["ok"])
            self.assertIn("boom", r["error"])

    def test_alert_cap_with_summary(self):
        lines = "\n".join(self._line(f"t{i}", "medium",
                                     ip=f"192.168.1.{10 + i}")
                          for i in range(15))
        with mock.patch.object(
                nucleim, "nuclei_targets",
                return_value=[f"192.168.1.{10 + i}" for i in range(15)]), \
             mock.patch.object(nucleim, "run_scan",
                               side_effect=[self._fake_run_scan("")
                                            (["192.168.1.10"]),
                                            self._fake_run_scan(lines)
                                            (["192.168.1.10"])]):
            nucleim.run_full_nuclei_scan(note="test")  # baseline
            r = nucleim.run_full_nuclei_scan(note="test")
            self.assertTrue(r["ok"])
            titles = [row[0] for row in
                      dbm.query("SELECT title FROM alerts")]
            self.assertEqual(len(titles), 11)  # 10 + 1 summary
            self.assertTrue(any("more new vulnerability" in t
                                for t in titles))

    def test_mitre_tag_exists(self):
        tag = mitrem.tag_for("nuclei_finding")
        self.assertIsNotNone(tag)
        self.assertRegex(tag["id"], r"^T\d+")
        tag2 = mitrem.tag_for("cve_match")
        self.assertIsNotNone(tag2)


@unittest.skipIf(dashm is None, "Flask not installed")
class NucleiRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_scan_api_carries_nuclei_block(self):
        c = self._client()
        r = c.get("/api/scan")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("nuclei", d)
        self.assertIn("installed", d["nuclei"])
        self.assertIn("findings", d["nuclei"])

    def test_nuclei_run_ignores_client_supplied_target(self):
        # The UI can never supply a target: even a body naming an
        # external IP must not reach the scanner.
        with mock.patch.object(nucleim, "check_binary",
                               return_value=(True, "ok")), \
             mock.patch.object(nucleim, "_nuclei_already_running",
                               return_value=False), \
             mock.patch.object(nucleim, "start_nuclei_async",
                               return_value=True) as starter:
            c = self._client()
            r = c.post("/api/nuclei/run",
                       json={"target": "93.184.216.34",
                             "targets": ["8.8.8.8"]})
            self.assertEqual(r.status_code, 200)
            self.assertTrue(r.get_json()["started"])
            # started with NO arguments -- the scanner pulls its own
            # targets from the inventory inside run_full_nuclei_scan
            starter.assert_called_once_with()

    def test_nuclei_run_without_binary(self):
        with mock.patch.object(nucleim, "check_binary",
                               return_value=(False, "not installed")):
            c = self._client()
            r = c.post("/api/nuclei/run")
            d = r.get_json()
            self.assertFalse(d["started"])
            self.assertIn("not installed", d["error"])

    def test_nuclei_run_while_running(self):
        with mock.patch.object(nucleim, "check_binary",
                               return_value=(True, "ok")), \
             mock.patch.object(nucleim, "_nuclei_already_running",
                               return_value=True):
            c = self._client()
            r = c.post("/api/nuclei/run")
            self.assertFalse(r.get_json()["started"])


class ConfigDefaultsTests(unittest.TestCase):
    def test_nuclei_defaults(self):
        from netmon import config as cfgm
        self.assertFalse(cfgm.DEFAULTS["nuclei"]["enabled"])
        self.assertTrue(cfgm.DEFAULTS["nuclei"]["weekly"])
        self.assertEqual(cfgm.DEFAULTS["nuclei"]["min_severity"],
                         "medium")

    def test_swaudit_defaults(self):
        from netmon import config as cfgm
        self.assertTrue(cfgm.DEFAULTS["swaudit"]["enabled"])
        self.assertTrue(cfgm.DEFAULTS["swaudit"]["daily"])


if __name__ == "__main__":
    unittest.main()
