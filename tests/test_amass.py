"""Tests for the Phase 3.5 batch 8 scope addition (2026-10-03):
OWASP Amass external attack-surface mapping.

- Domain validation: strict hostname gate (injection attempts rejected).
- JSONL parsing: both address shapes, garbage lines, oversized lines,
  invalid IPs skipped; missing file -> [].
- Command construction: argv list, no shell, domain as one element.
- Storage + diffing: asset rows, new-subdomain/new-IP detection.
- Alerting: first run is the silent baseline; later runs alert Medium
  (capped) on genuinely new assets.
- Config boundary: targets come from config.yaml ONLY; the UI can never
  supply a scan target.
- Graceful degradation: missing binary -> clear install note, no errors.
- Dashboard: /api/amass and /api/amass/run behavior.

Live scans are NEVER run in tests (run_enum is mocked).

Run: python -m unittest discover -s tests
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
from netmon import amass as amassm
from netmon import mitre as mitrem

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None


from helpers import fresh_db as _fresh_db, restore_db as _restore_db

class _DbTest(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)


FIXTURE_JSONL = "\n".join([
    json.dumps({"name": "www.example.com", "domain": "example.com",
                "addresses": ["93.184.216.34"], "tag": "cert",
                "sources": ["crtsh"]}),
    json.dumps({"name": "api.example.com", "domain": "example.com",
                "addresses": [{"ip": "93.184.216.35",
                               "cidr": "93.184.216.0/24",
                               "asn": 15133, "desc": "EDGECAST"}],
                "tag": "dns", "source": "Hackertarget"}),
    json.dumps({"name": "vpn.example.com", "domain": "example.com",
                "addresses": [], "tag": "cert", "sources": []}),
    "this is not json",
    json.dumps({"name": "not a domain!!", "domain": "example.com"}),
    json.dumps(["a", "list", "not", "an", "object"]),
    json.dumps({"name": "badip.example.com", "domain": "example.com",
                "addresses": ["not-an-ip"]}),
    "x" * (amassm.MAX_JSONL_LINE + 10),
])


class DomainValidationTests(unittest.TestCase):
    def test_accepts_real_domains(self):
        for d in ("example.com", "sub.example.co.uk", "a-b.x.io",
                  "EXAMPLE.com"):
            self.assertTrue(amassm.valid_domain(d), d)

    def test_rejects_injection(self):
        for bad in ("evil.com; rm -rf /", "example.com && id",
                    "example.com\n-d other.com", "example.com`id`",
                    "$(id).example.com", "a b.com", "", None,
                    "http://example.com", "-bad.com", "bad-.com",
                    "x" * 300 + ".com", "single", 12345):
            self.assertFalse(amassm.valid_domain(bad), repr(bad))


class ParsingTests(unittest.TestCase):
    def test_fixture_parses(self):
        assets = amassm.parse_jsonl_text(FIXTURE_JSONL)
        by_name = {a["name"]: a for a in assets}
        # string address shape
        self.assertEqual(by_name["www.example.com"]["ips"],
                         ["93.184.216.34"])
        self.assertEqual(by_name["www.example.com"]["sources"], ["crtsh"])
        # object address shape (ip/cidr/asn/desc)
        api = by_name["api.example.com"]
        self.assertEqual(api["ips"], ["93.184.216.35"])
        self.assertEqual(api["cidrs"], ["93.184.216.0/24"])
        self.assertEqual(api["asns"], [15133])
        self.assertEqual(api["sources"], ["Hackertarget"])
        # empty addresses ok
        self.assertEqual(by_name["vpn.example.com"]["ips"], [])
        # garbage, invalid names, non-objects, oversized lines skipped
        self.assertNotIn("not a domain!!", by_name)
        self.assertEqual(len(assets), 4)  # 3 good + badip (no IPs kept)
        self.assertEqual(by_name["badip.example.com"]["ips"], [])

    def test_empty_and_missing(self):
        self.assertEqual(amassm.parse_jsonl_text(""), [])
        self.assertEqual(amassm.parse_jsonl_text(None), [])
        self.assertEqual(
            amassm.parse_jsonl_file("/nonexistent/path.jsonl"), [])

    def test_line_cap(self):
        big = "\n".join(
            json.dumps({"name": f"h{i}.example.com",
                        "domain": "example.com"})
            for i in range(amassm.MAX_JSONL_LINES + 100))
        self.assertLessEqual(len(amassm.parse_jsonl_text(big)),
                             amassm.MAX_JSONL_LINES)


class CommandConstructionTests(unittest.TestCase):
    def _cfg(self, **over):
        base = {"amass": {"passive": True, "timeout_min": 20}}
        base["amass"].update(over)
        return base

    def test_argv_no_shell_domain_single_element(self):
        with mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"), \
             mock.patch("netmon.config.load_cached",
                        return_value=self._cfg()):
            argv = amassm.build_argv("example.com", "/tmp/out.jsonl",
                                     "/tmp/work")
        self.assertEqual(argv[0], "/usr/bin/amass")
        self.assertIn("enum", argv)
        self.assertIn("-passive", argv)
        i = argv.index("-d")
        self.assertEqual(argv[i + 1], "example.com")  # one element
        j = argv.index("-json")
        self.assertEqual(argv[j + 1], "/tmp/out.jsonl")

    def test_build_argv_rejects_invalid_domain(self):
        with mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"):
            with self.assertRaises(ValueError):
                amassm.build_argv("evil.com; id", "/tmp/o", "/tmp/w")

    def test_run_enum_rejects_bad_domain_without_subprocess(self):
        with mock.patch("subprocess.run") as sr:
            res = amassm.run_enum("evil.com; touch /tmp/pwned")
        self.assertFalse(res["ok"])
        sr.assert_not_called()

    def test_run_enum_uses_argv_not_shell(self):
        with mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"), \
             mock.patch("netmon.amass.binary_version",
                        return_value="v4.2.0"), \
             mock.patch("subprocess.run") as sr, \
             mock.patch("os.path.exists", return_value=True):
            sr.return_value = mock.Mock(stdout="", stderr="",)
            res = amassm.run_enum("example.com")
        self.assertTrue(res["ok"])
        sr.assert_called_once()
        args, kwargs = sr.call_args
        self.assertNotIn("shell", kwargs)  # no shell=True, ever
        argv = args[0]
        self.assertIsInstance(argv, list)
        self.assertEqual(argv[argv.index("-d") + 1], "example.com")


class StorageDiffTests(_DbTest):
    def test_round_trip_and_diff(self):
        assets = amassm.parse_jsonl_text(FIXTURE_JSONL)
        rows = amassm.asset_rows("example.com", assets)
        cur = dbm.record_amass_assets("example.com", rows, time.time())
        self.assertIn(("subdomain", "www.example.com"), cur)
        self.assertIn(("ip", "93.184.216.34"), cur)
        self.assertIn(("asn", "15133"), cur)
        self.assertEqual(dbm.amass_asset_set("example.com"), cur)

        # Second run: one new subdomain, one new IP.
        assets2 = assets + [{
            "name": "newapp.example.com", "domain": "example.com",
            "ips": ["93.184.216.99"], "cidrs": [], "asns": [],
            "tag": "cert", "sources": ["crtsh"]}]
        rows2 = amassm.asset_rows("example.com", assets2)
        new_subs, new_ips, new_asns = amassm.diff_assets(cur, rows2)
        self.assertEqual(new_subs, ["newapp.example.com"])
        self.assertEqual(new_ips, ["93.184.216.99"])
        self.assertEqual(new_asns, [])

    def test_asset_rows_deduped(self):
        assets = amassm.parse_jsonl_text(FIXTURE_JSONL)
        rows = amassm.asset_rows("example.com", assets + assets)
        keys = [(k, v) for k, v, _ in rows]
        self.assertEqual(len(keys), len(set(keys)))


class AlertingTests(_DbTest):
    def _write_fixture(self, text):
        tmp = tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False,
                                          mode="w")
        tmp.write(text)
        tmp.close()
        self.addCleanup(os.unlink, tmp.name)
        return tmp.name

    def test_first_run_is_silent_baseline(self):
        path = self._write_fixture(FIXTURE_JSONL)
        with mock.patch("netmon.amass.run_enum",
                        return_value={"ok": True, "jsonl_path": path,
                                      "work_dir": None, "duration_s": 1.0,
                                      "version": "v4.2.0"}):
            res = amassm.run_domain_scan("example.com", note="test")
        self.assertTrue(res["ok"])
        self.assertGreater(res["subdomains"], 0)
        # Baseline: no alerts fired.
        n = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE kind='amass_new_asset'")[0][0]
        self.assertEqual(n, 0)
        self.assertIsNotNone(dbm.latest_amass_run("example.com"))

    def test_second_run_alerts_on_new_assets(self):
        path1 = self._write_fixture(FIXTURE_JSONL)
        extra = FIXTURE_JSONL + "\n" + json.dumps(
            {"name": "secretvpn.example.com", "domain": "example.com",
             "addresses": ["93.184.216.77"], "tag": "cert",
             "sources": ["crtsh"]})
        path2 = self._write_fixture(extra)
        with mock.patch("netmon.amass.run_enum",
                        return_value={"ok": True, "jsonl_path": path1,
                                      "work_dir": None, "duration_s": 1.0,
                                      "version": ""}):
            amassm.run_domain_scan("example.com", note="test")
        with mock.patch("netmon.amass.run_enum",
                        return_value={"ok": True, "jsonl_path": path2,
                                      "work_dir": None, "duration_s": 1.0,
                                      "version": ""}):
            res = amassm.run_domain_scan("example.com", note="test")
        self.assertTrue(res["ok"])
        self.assertEqual(res["new_subdomains"], ["secretvpn.example.com"])
        self.assertEqual(res["new_ips"], ["93.184.216.77"])
        alerts = dbm.query(
            "SELECT severity, title, meaning, is_normal, what_to_do,"
            " mitre_id FROM alerts WHERE kind='amass_new_asset'"
            " ORDER BY id")
        self.assertEqual(len(alerts), 2)
        for sev, title, meaning, normal, wtd, mitre in alerts:
            self.assertEqual(sev, "Medium")
            self.assertTrue(meaning and normal and wtd)  # plain-English
        self.assertTrue(any("secretvpn.example.com" in t for _, t, *_ in
                            alerts))
        self.assertTrue(any("93.184.216.77" in t for _, t, *_ in alerts))
        # MITRE tag exists for the new kind (enforced by mitre tests).
        self.assertIsNotNone(mitrem.tag_for("amass_new_asset"))
        self.assertTrue(all(m == "T1590.002" for *_, m in alerts))

    def test_alert_cap_with_summary(self):
        path1 = self._write_fixture(FIXTURE_JSONL)
        many = FIXTURE_JSONL + "\n" + "\n".join(
            json.dumps({"name": f"host{i}.example.com",
                        "domain": "example.com", "addresses": [],
                        "tag": "cert", "sources": []})
            for i in range(amassm.MAX_ALERTS_PER_RUN + 5))
        path2 = self._write_fixture(many)
        with mock.patch("netmon.amass.run_enum",
                        return_value={"ok": True, "jsonl_path": path1,
                                      "work_dir": None, "duration_s": 1,
                                      "version": ""}):
            amassm.run_domain_scan("example.com", note="test")
        with mock.patch("netmon.amass.run_enum",
                        return_value={"ok": True, "jsonl_path": path2,
                                      "work_dir": None, "duration_s": 1,
                                      "version": ""}):
            res = amassm.run_domain_scan("example.com", note="test")
        self.assertTrue(res["ok"])
        n = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE kind='amass_new_asset'")[0][0]
        # individual alerts capped + 1 summary alert.
        self.assertEqual(n, amassm.MAX_ALERTS_PER_RUN + 1)

    def test_invalid_domain_rejected(self):
        res = amassm.run_domain_scan("evil.com; id", note="test")
        self.assertFalse(res["ok"])

    def test_mitre_tag_registered(self):
        self.assertIn("amass_new_asset", mitrem.all_kinds())


class ConfigBoundaryTests(unittest.TestCase):
    def _cfg(self, amass_cfg):
        return {"amass": amass_cfg}

    def test_domains_only_from_config(self):
        with mock.patch("netmon.config.load_cached", return_value=self._cfg(
                {"domains": ["example.com", "bad;injection",
                             "example.com", "Sub.Other.org"]})):
            self.assertEqual(amassm.configured_domains(),
                             ["example.com", "sub.other.org"])

    def test_string_form_tolerated(self):
        with mock.patch("netmon.config.load_cached", return_value=self._cfg(
                {"domains": "example.com, other.org"})):
            self.assertEqual(amassm.configured_domains(),
                             ["example.com", "other.org"])

    def test_no_domains_by_default(self):
        with mock.patch("netmon.config.load_cached",
                        return_value={"amass": {}}):
            self.assertEqual(amassm.configured_domains(), [])

    def test_disabled_by_default(self):
        with mock.patch("netmon.config.load_cached",
                        return_value={"amass": {}}):
            self.assertFalse(amassm.amass_enabled())

    def test_maybe_weekly_skips_quietly(self):
        # Disabled.
        with mock.patch("netmon.config.load_cached",
                        return_value={"amass": {"enabled": False}}):
            self.assertIsNone(amassm.maybe_weekly_amass())
        # Enabled but no binary.
        with mock.patch("netmon.config.load_cached", return_value=self._cfg(
                {"enabled": True, "domains": ["example.com"]})), \
             mock.patch("netmon.amass.find_binary", return_value=None):
            self.assertIsNone(amassm.maybe_weekly_amass())
        # Enabled + binary but no domains.
        with mock.patch("netmon.config.load_cached",
                        return_value=self._cfg(
                            {"enabled": True, "domains": []})), \
             mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"):
            self.assertIsNone(amassm.maybe_weekly_amass())


class BinaryCheckTests(unittest.TestCase):
    def test_missing_binary_graceful(self):
        with mock.patch("shutil.which", return_value=None):
            ok, note = amassm.check_binary()
        self.assertFalse(ok)
        self.assertIn("not installed", note)
        self.assertIn("config.yaml", note)  # install instructions

    def test_present_binary(self):
        with mock.patch("shutil.which", return_value="/usr/bin/amass"), \
             mock.patch("netmon.amass.binary_version",
                        return_value="v4.2.0"):
            ok, note = amassm.check_binary()
        self.assertTrue(ok)
        self.assertIn("v4.2.0", note)


@unittest.skipIf(dashm is None, "Flask not installed")
class AmassRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_api_amass_missing_binary(self):
        with mock.patch("shutil.which", return_value=None):
            r = self._client().get("/api/amass")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertFalse(d["installed"])
        self.assertIn("install", d["install_note"].lower())

    def test_api_amass_run_ignores_request_body(self):
        # The UI can never supply a scan target: even a body naming an
        # attacker's domain must not be honored.
        with mock.patch("netmon.amass.amass_enabled",
                        return_value=True), \
             mock.patch("netmon.amass.find_binary",
                        return_value="/usr/bin/amass"), \
             mock.patch("netmon.amass.start_amass_async",
                        return_value=["example.com"]) as starter, \
             mock.patch("netmon.amass.configured_domains",
                        return_value=["example.com"]):
            r = self._client().post("/api/amass/run",
                                    json={"domain": "victim.example.net"})
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["started"])
        self.assertEqual(d["domains"], ["example.com"])
        starter.assert_called_once_with()  # no args: config-only targets

    def test_api_amass_run_disabled(self):
        with mock.patch("netmon.amass.amass_enabled",
                        return_value=False):
            r = self._client().post("/api/amass/run", json={})
        d = r.get_json()
        self.assertFalse(d["started"])


if __name__ == "__main__":
    unittest.main()
