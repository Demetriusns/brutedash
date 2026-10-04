"""Tests for the Phase 3.5 batch 11 software inventory + CVE correlation
(2026-10-04): the Wazuh-pattern complement to active scanning.

- CISA KEV JSON parsing (crafted fixture, never a live download).
- Product matching: exact, whole-word, stopword guards.
- Correlation logic (pure function) + match storage: alert once per
  (package, CVE), repeats quiet, vanished matches cleaned up.
- Inventory collectors: Python metadata (mocked) + OS fallbacks.
- Alerting: Medium alert with CVE id and plain-English text, capped.
- MITRE tag exists for the new alert kind.

No network access in tests (feed download is mocked).
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
from netmon import swaudit as swam
from netmon import threatintel as tim
from netmon import mitre as mitrem


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


# --- KEV feed parsing --------------------------------------------------------

_KEV_FIXTURE = {
    "title": "CISA Catalog of Known Exploited Vulnerabilities",
    "catalogVersion": "2026.10.04",
    "dateReleased": "2026-10-04T00:00:00.000Z",
    "count": 3,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 Remote Code Execution",
            "dateAdded": "2021-12-10",
            "shortDescription": "Log4j2 has a remote code execution flaw.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
            "notes": "",
        },
        {
            "cveID": "CVE-2024-21887",
            "vendorProject": "Ivanti",
            "product": "Connect Secure",
            "vulnerabilityName": "Ivanti Connect Secure Command Injection",
            "dateAdded": "2024-01-16",
            "shortDescription": "Command injection in the web component.",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2024-01-31",
            "knownRansomwareCampaignUse": "Unknown",
            "notes": "",
        },
        # garbage entry: skipped, never fatal
        {"cveID": "not-a-cve", "product": "Bogus"},
    ],
}


class KevParseTests(unittest.TestCase):
    def test_fixture_parses(self):
        rows = tim._parse_kev_json(json.dumps(_KEV_FIXTURE))
        self.assertEqual(len(rows), 2)
        by_cve = {k: json.loads(d) for k, d in rows}
        e = by_cve["CVE-2021-44228"]
        self.assertEqual(e["v"], "Apache")
        self.assertEqual(e["p"], "Log4j2")
        self.assertEqual(e["due"], "2021-12-24")
        self.assertIn("remote code execution", e["d"].lower())

    def test_malformed_feed_returns_empty(self):
        self.assertEqual(tim._parse_kev_json(""), [])
        self.assertEqual(tim._parse_kev_json("not json"), [])
        self.assertEqual(tim._parse_kev_json(json.dumps({"nope": 1})), [])

    def test_feed_registered_with_ssrf_guard(self):
        spec = tim._FEEDS["kev-cves"]
        self.assertEqual(spec["kind"], "cve")
        self.assertIn("cisa.gov", spec["url"])
        from urllib.parse import urlparse
        host = urlparse(spec["url"]).hostname
        self.assertIn(host, tim._FEED_HOSTS)

    def test_feed_roundtrip_into_db(self):
        tmp, old_path, old_conn = _fresh_db()
        try:
            rows = tim._parse_kev_json(json.dumps(_KEV_FIXTURE))
            n = dbm.ti_replace_feed("kev-cves", "cve", rows)
            self.assertEqual(n, 2)
            entries = dbm.list_kev_entries()
            self.assertEqual(len(entries), 2)
            by_cve = {e["cve_id"]: e for e in entries}
            self.assertEqual(by_cve["CVE-2024-21887"]["product"],
                             "Connect Secure")
            self.assertEqual(by_cve["CVE-2024-21887"]["due_date"],
                             "2024-01-31")
        finally:
            dbm.DB_PATH, dbm._conn = old_path, old_conn
            try:
                os.unlink(tmp)
            except OSError:
                pass


# --- matching ----------------------------------------------------------------

class MatchTests(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(swam.product_matches("Log4j2", "Log4j2"))
        self.assertTrue(swam.product_matches("log4j2", "Log4j2"))
        self.assertTrue(swam.product_matches("google-chrome",
                                            "Google Chrome"))

    def test_whole_word_match(self):
        self.assertTrue(swam.product_matches("Chrome", "Google Chrome"))
        self.assertTrue(swam.product_matches("Secure",
                                            "Ivanti Connect Secure"))

    def test_no_partial_word_match(self):
        self.assertFalse(swam.product_matches("Log", "Log4j2"))
        self.assertFalse(swam.product_matches("rome", "Google Chrome"))

    def test_stopwords_never_match_alone(self):
        self.assertFalse(swam.product_matches("Server",
                                              "Microsoft Exchange Server"))
        self.assertFalse(swam.product_matches("Windows", "Windows 10"))
        self.assertFalse(swam.product_matches("app", "My App Pro"))

    def test_short_tokens_need_exact(self):
        # len < 4: only exact normalized equality counts
        self.assertFalse(swam.product_matches("go", "MongoDB Go Driver"))
        self.assertTrue(swam.product_matches("go", "go"))

    def test_empty_inputs(self):
        self.assertFalse(swam.product_matches("", "Chrome"))
        self.assertFalse(swam.product_matches("Chrome", ""))
        self.assertFalse(swam.product_matches(None, None))

    def test_normalize(self):
        self.assertEqual(swam.normalize_name("Google_Chrome!! 99"),
                         "google chrome 99")


class CorrelateTests(_DbTest):
    def _seed_kev(self):
        rows = tim._parse_kev_json(json.dumps(_KEV_FIXTURE))
        dbm.ti_replace_feed("kev-cves", "cve", rows)

    def test_correlate_finds_matches(self):
        self._seed_kev()
        index = swam.build_kev_index()
        inv = [("Log4j2", "2.14.0", "os"),
               ("Google Chrome", "120.0", "os"),
               ("flask", "3.1.0", "python")]
        matches = swam.correlate(inv, index)
        self.assertEqual(len(matches), 1)
        m = matches[0]
        self.assertEqual(m["package"], "Log4j2")
        self.assertEqual(m["cve_id"], "CVE-2021-44228")
        self.assertEqual(m["source"], "os")

    def test_correlate_quiet_without_kev_data(self):
        index = swam.build_kev_index()  # empty feed
        self.assertEqual(index, {})
        matches = swam.correlate([("Log4j2", "2.14", "os")], index)
        self.assertEqual(matches, [])

    def test_match_once_then_quiet(self):
        self._seed_kev()
        inv = [("Log4j2", "2.14.0", "os")]
        index = swam.build_kev_index()
        m1 = swam.correlate(inv, index)
        new1 = dbm.record_cve_matches(1000.0, m1)
        self.assertEqual(len(new1), 1)
        m2 = swam.correlate(inv, index)
        new2 = dbm.record_cve_matches(2000.0, m2)
        self.assertEqual(new2, [])
        # stored row survives
        self.assertEqual(len(dbm.list_cve_matches()), 1)

    def test_vanished_match_cleaned_up(self):
        self._seed_kev()
        index = swam.build_kev_index()
        m1 = swam.correlate([("Log4j2", "2.14.0", "os")], index)
        dbm.record_cve_matches(1000.0, m1)
        # package updated away / CVE left the list: no matches now
        new = dbm.record_cve_matches(2000.0, [])
        self.assertEqual(new, [])
        self.assertEqual(dbm.list_cve_matches(), [])

    def test_run_swaudit_alerts_once(self):
        self._seed_kev()
        with mock.patch.object(swam, "collect_inventory",
                               return_value=[("Log4j2", "2.14.0",
                                              "os")]):
            r1 = swam.run_swaudit()
            self.assertTrue(r1["ok"])
            self.assertEqual(r1["new"], 1)
            self.assertEqual(r1["alerts"], 1)
            kinds = [row[0] for row in
                     dbm.query("SELECT kind FROM alerts")]
            self.assertEqual(kinds, ["cve_match"])
            row = dbm.query(
                "SELECT severity, title, detail FROM alerts")[0]
            self.assertEqual(row[0], "Medium")
            self.assertIn("CVE-2021-44228", row[1] + row[2])
            r2 = swam.run_swaudit()
            self.assertTrue(r2["ok"])
            self.assertEqual(r2["new"], 0)
            self.assertEqual(
                dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 1)

    def test_alert_cap_with_summary(self):
        # 15 distinct products on the KEV list, 15 matching packages.
        vulns = []
        inv = []
        for i in range(15):
            vulns.append({
                "cveID": f"CVE-2024-{10000 + i}",
                "vendorProject": "Vendor",
                "product": f"Product{i}",
                "vulnerabilityName": f"Flaw {i}",
                "dateAdded": "2024-01-01",
                "shortDescription": f"Flaw in Product{i}.",
                "requiredAction": "Update.",
                "dueDate": "2024-02-01",
                "knownRansomwareCampaignUse": "Unknown",
                "notes": "",
            })
            inv.append((f"Product{i}", "1.0", "os"))
        dbm.ti_replace_feed("kev-cves", "cve",
                            tim._parse_kev_json(json.dumps(
                                {"vulnerabilities": vulns})))
        with mock.patch.object(swam, "collect_inventory",
                               return_value=inv):
            r = swam.run_swaudit()
            self.assertTrue(r["ok"])
            self.assertEqual(r["new"], 15)
            titles = [row[0] for row in
                      dbm.query("SELECT title FROM alerts")]
            self.assertEqual(len(titles), 11)  # 10 + summary
            self.assertTrue(any("more software matches" in t
                                for t in titles))

    def test_mitre_tag_exists(self):
        tag = mitrem.tag_for("cve_match")
        self.assertIsNotNone(tag)
        self.assertRegex(tag["id"], r"^T\d+")

    def test_status_summary(self):
        st = swam.swaudit_status()
        self.assertIn("matches", st)
        self.assertIn("packages", st)
        self.assertIsNone(st["last_run_ts"])


class InventoryTests(unittest.TestCase):
    def test_python_inventory_mocked(self):
        class FakeDist:
            def __init__(self, name, version):
                self._name = name
                self._version = version

            @property
            def metadata(self):
                return {"Name": self._name}

            @property
            def version(self):
                return self._version

        dists = [FakeDist("Flask", "3.1.0"), FakeDist(None, "1.0")]
        with mock.patch("importlib.metadata.distributions",
                        return_value=dists):
            rows = swam.inventory_python()
        self.assertEqual(rows, [("Flask", "3.1.0")])

    def test_python_inventory_never_raises(self):
        with mock.patch("importlib.metadata.distributions",
                        side_effect=RuntimeError("boom")):
            self.assertEqual(swam.inventory_python(), [])

    def test_os_inventory_never_raises(self):
        with mock.patch.object(swam, "_run_capture",
                               side_effect=RuntimeError("boom")):
            self.assertEqual(swam.inventory_os(), [])

    def test_dpkg_parsing(self):
        out = "flask\t3.1.0\nbadline\nrequests\t2.32.0\n"
        with mock.patch.object(swam, "_run_capture", return_value=out):
            rows = swam._inventory_linux()
        self.assertEqual(rows, [("flask", "3.1.0"),
                                ("requests", "2.32.0")])


if __name__ == "__main__":
    unittest.main()
