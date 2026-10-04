"""Tests for the Phase 3.5 batch 7 (2026-10-03): rap sheets -- threat intel.

- Feed parsing (URLhaus hostfile, Emerging Threats IP list).
- Domain normalization + parent-domain matching.
- Local table: atomic feed replace preserves first_seen; batch lookup.
- Detection: phishing_domain (High, T1566.002) fires for a looked-up
  listed domain, attaches to an incident, respects cooldown + allowlist.
- Detection: malicious_ip (High) fires for traffic to a listed IP.
- AbuseIPDB: no key -> graceful None; keyed path parses + caches; the key
  is never returned, logged, or stored.
- SSRF guard: non-feed hosts refused; oversized feeds refused; failed
  refresh keeps old rows.
- Dashboard endpoints: 200/400 behavior for /api/intel/* and /api/device/*.

Run: python -m unittest discover -s tests -v
"""
import io
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import detect as detm
from netmon import mitre as mitrem
from netmon import threatintel as tim

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


def _restore_db(path, old_path, old_conn):
    try:
        if dbm._conn is not None:
            dbm._conn.close()
    finally:
        dbm.DB_PATH, dbm._conn = old_path, old_conn
    try:
        os.unlink(path)
    except OSError:
        pass


HOSTFILE_SAMPLE = """\
# URLhaus sample
127.0.0.1 evil.example.com
127.0.0.1 Phishy-Sub.Bad-Actor.NET.
127.0.0.1 not_a_domain!!
# comment line
127.0.0.1
"""

IPLIST_SAMPLE = """\
# ET sample
203.0.113.7
198.51.100.23 extra stuff
not.an.ip
# comment
"""


class FeedParsingTests(unittest.TestCase):
    def test_hostfile_parsing(self):
        got = tim._parse_hostfile(HOSTFILE_SAMPLE)
        self.assertIn("evil.example.com", got)
        self.assertIn("phishy-sub.bad-actor.net", got)  # lowercased, dot gone
        self.assertNotIn("not_a_domain!!", got)
        self.assertEqual(len(got), 2)

    def test_ip_list_parsing(self):
        got = tim._parse_ip_list(IPLIST_SAMPLE)
        self.assertEqual(got, ["203.0.113.7", "198.51.100.23"])

    def test_normalize_domain(self):
        self.assertEqual(tim.normalize_domain("  Evil.EXAMPLE.com. "), "evil.example.com")
        self.assertEqual(tim.normalize_domain("*.example.com"), "example.com")
        self.assertEqual(tim.normalize_domain(""), "")

    def test_parent_domains(self):
        self.assertEqual(tim.parent_domains("a.b.example.com"),
                         ["a.b.example.com", "b.example.com", "example.com"])
        self.assertEqual(tim.parent_domains("example.com"), ["example.com"])
        self.assertEqual(tim.parent_domains("single"), [])

    def test_is_plausible_domain(self):
        self.assertTrue(tim.is_plausible_domain("evil.example.com"))
        self.assertFalse(tim.is_plausible_domain("not a domain!!"))
        self.assertFalse(tim.is_plausible_domain("single"))


class LocalTableTests(unittest.TestCase):
    def test_replace_feed_preserves_first_seen(self):
        path, old_path, old_conn = _fresh_db()
        try:
            n1 = dbm.ti_replace_feed("f1", "domain",
                                     [("evil.example.com", "d1")])
            self.assertEqual(n1, 1)
            first = dbm.ti_lookup("domain", ["evil.example.com"])
            fs1 = first["evil.example.com"][0]["first_seen"]
            time.sleep(0.02)
            dbm.ti_replace_feed("f1", "domain",
                                [("evil.example.com", "d1"),
                                 ("bad.example.org", "d1")])
            hits = dbm.ti_lookup("domain",
                                 ["evil.example.com", "bad.example.org"])
            self.assertEqual(hits["evil.example.com"][0]["first_seen"], fs1)
            self.assertGreater(
                hits["bad.example.org"][0]["first_seen"], 0)
            # dropped keys are gone
            self.assertEqual(dbm.ti_lookup("domain", ["gone.example"]), {"gone.example": []})
        finally:
            _restore_db(path, old_path, old_conn)

    def test_lookup_batch_and_missing(self):
        path, old_path, old_conn = _fresh_db()
        try:
            dbm.ti_replace_feed("f1", "ip", [("203.0.113.7", "bad ip")])
            hits = dbm.ti_lookup("ip", ["203.0.113.7", "192.0.2.1"])
            self.assertEqual(len(hits["203.0.113.7"]), 1)
            self.assertEqual(hits["203.0.113.7"][0]["feed"], "f1")
            self.assertEqual(hits["192.0.2.1"], [])
            self.assertEqual(dbm.ti_lookup("ip", []), {})
        finally:
            _restore_db(path, old_path, old_conn)

    def test_feed_status(self):
        path, old_path, old_conn = _fresh_db()
        try:
            dbm.ti_replace_feed("urlhaus-domains", "domain",
                                [("a.example", "d"), ("b.example", "d")])
            st = dbm.ti_feed_status()
            self.assertEqual(len(st), 1)
            self.assertEqual(st[0]["feed"], "urlhaus-domains")
            self.assertEqual(st[0]["entries"], 2)
            self.assertTrue(st[0]["last_updated"])
            self.assertIn("URLhaus", st[0]["label"])
        finally:
            _restore_db(path, old_path, old_conn)

    def test_domain_parent_match(self):
        path, old_path, old_conn = _fresh_db()
        try:
            dbm.ti_replace_feed("urlhaus-domains", "domain",
                                [("example.com", "base listed")])
            hits = tim.lookup_domain("deep.sub.example.com")
            self.assertEqual(len(hits), 1)
            self.assertEqual(hits[0]["matched"], "example.com")
            self.assertFalse(tim.lookup_domain("other.org"))
        finally:
            _restore_db(path, old_path, old_conn)


class MitreTests(unittest.TestCase):
    def test_phishing_domain_tag(self):
        tag = mitrem.tag_for("phishing_domain")
        self.assertEqual(tag["id"], "T1566.002")
        self.assertEqual(tag["tactic"], "Initial Access")

    def test_malicious_ip_tag(self):
        tag = mitrem.tag_for("malicious_ip")
        self.assertEqual(tag["id"], "T1071.001")


class PhishingDetectionTests(unittest.TestCase):
    def _seed(self, now):
        dbm.ti_replace_feed("urlhaus-domains", "domain",
                            [("evil.example.com", "phishing feed")])
        dbm.insert_dns_queries(
            [(now - 60, "192.168.1.5", "evil.example.com", 1),
             (now - 60, "192.168.1.5", "ok.example.org", 1)])

    def test_phishing_alert_fires(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                self._seed(now)
                fired = detm.check_threat_intel(now=now)
            self.assertEqual(fired, [("phishing_domain", "evil.example.com")])
            rows = dbm.query(
                "SELECT kind, severity, mitre_id FROM alerts")
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0][0], "phishing_domain")
            self.assertEqual(rows[0][1], "High")
            self.assertEqual(rows[0][2], "T1566.002")
            # auto-attached to an incident: no external IP named, so the
            # case keys on the LAN device (batch-5 fallback behavior)
            cases = dbm.list_incidents()
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["device_key"], "192.168.1.5")
            self.assertIn("evil.example.com", cases[0]["summary"])
        finally:
            _restore_db(path, old_path, old_conn)

    def test_phishing_cooldown(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                self._seed(now)
                detm.check_threat_intel(now=now)
                fired = detm.check_threat_intel(now=now + 60)
            self.assertEqual(fired, [])
            self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 1)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_phishing_allowlist_suppresses(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                self._seed(now)
                dbm.add_allowlist("phishing_domain", "evil.example.com")
                fired = detm.check_threat_intel(now=now)
            self.assertEqual(fired, [])
            self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_phishing_subdomain_parent_match(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.ti_replace_feed("urlhaus-domains", "domain",
                                    [("example.com", "base listed")])
                dbm.insert_dns_queries(
                    [(now - 60, "192.168.1.5", "deep.sub.example.com", 1)])
                fired = detm.check_threat_intel(now=now)
            self.assertEqual(fired, [("phishing_domain", "deep.sub.example.com")])
        finally:
            _restore_db(path, old_path, old_conn)

    def test_local_suffixes_skipped(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.ti_replace_feed("urlhaus-domains", "domain",
                                    [("printer.local", "x")])
                dbm.insert_dns_queries(
                    [(now - 60, "192.168.1.5", "printer.local", 1)])
                fired = detm.check_threat_intel(now=now)
            self.assertEqual(fired, [])
        finally:
            _restore_db(path, old_path, old_conn)


class MaliciousIpDetectionTests(unittest.TestCase):
    def test_malicious_ip_alert_fires(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            # NOTE: 203.0.113.x is TEST-NET documentation space, which
            # ipaddress correctly reports as non-global (non-external).
            # A real public IP is needed for the external-IP path.
            with dbm.notifications_paused():
                dbm.ti_replace_feed("et-compromised-ips", "ip",
                                    [("93.184.216.34", "bad ip")])
                dbm.insert_flows(
                    [(now - 60, "192.168.1.5", "93.184.216.34", 50000, 443,
                      "TCP", 10, 5000, "outbound"),
                     (now - 60, "192.168.1.5", "192.0.2.9", 50001, 443,
                      "TCP", 10, 5000, "outbound")])
                fired = detm.check_threat_intel(now=now)
            self.assertEqual(fired, [("malicious_ip", "93.184.216.34")])
            rows = dbm.query(
                "SELECT kind, severity, mitre_id FROM alerts")
            self.assertEqual(rows[0], ("malicious_ip", "High", "T1071.001"))
            # the case keys on the malicious IP
            cases = dbm.list_incidents()
            self.assertEqual(cases[0]["device_key"], "93.184.216.34")
        finally:
            _restore_db(path, old_path, old_conn)

    def test_run_all_includes_threat_intel(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.ti_replace_feed("urlhaus-domains", "domain",
                                    [("evil.example.com", "phishing feed")])
                dbm.insert_dns_queries(
                    [(now - 60, "192.168.1.5", "evil.example.com", 1)])
                detm.run_all(now=now)
            kinds = {r[0] for r in dbm.query("SELECT kind FROM alerts")}
            self.assertIn("phishing_domain", kinds)
        finally:
            _restore_db(path, old_path, old_conn)


class AbuseIPDBTests(unittest.TestCase):
    def test_no_key_graceful(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ABUSEIPDB_API_KEY", None)
            self.assertIsNone(tim._abuseipdb_check("203.0.113.7"))
            self.assertFalse(tim.abuseipdb_configured())
            self.assertEqual(
                tim.lookup_ip("203.0.113.7"),
                {"listed": [], "abuseipdb": None})

    def test_keyed_check_parses_and_caches(self):
        path, old_path, old_conn = _fresh_db()
        try:
            payload = {"data": {
                "abuseConfidenceScore": 95, "countryName": "Nowhere",
                "countryCode": "NW", "isp": "Evil ISP",
                "usageType": "Data Center", "asn": 999,
                "domain": "evil.example", "totalReports": 12,
                "lastReportedAt": "2026-10-01T00:00:00+00:00"}}
            body = json.dumps(payload).encode()

            class FakeResp:
                def __init__(self, data):
                    self._data = data
                    self._url = tim._ABUSEIPDB_CHECK_URL
                def geturl(self):
                    return self._url
                def read(self, n=-1):
                    return self._data
                def __enter__(self):
                    return self
                def __exit__(self, *a):
                    return False

            with mock.patch.dict(os.environ,
                                 {"ABUSEIPDB_API_KEY": "s3cr3t-key"}):
                with mock.patch.object(tim, "urlopen",
                                       return_value=FakeResp(body)) as m:
                    got = tim._abuseipdb_check("203.0.113.7")
                    self.assertEqual(got["score"], 95)
                    self.assertEqual(got["country"], "Nowhere")
                    self.assertEqual(got["isp"], "Evil ISP")
                    self.assertEqual(got["asn"], 999)
                    # the key is never in the returned data
                    self.assertNotIn("s3cr3t-key", json.dumps(got))
                    # second call hits the cache: no new HTTP
                    got2 = tim._abuseipdb_check("203.0.113.7")
                    self.assertEqual(got2, got)
                    self.assertEqual(m.call_count, 1)
                    # daily budget was recorded exactly once
                    day = time.strftime("%Y-%m-%d", time.gmtime())
                    self.assertEqual(
                        dbm.get_meta(f"ti_abuseipdb_used_{day}"), "1")
        finally:
            _restore_db(path, old_path, old_conn)

    def test_failure_returns_none(self):
        with mock.patch.dict(os.environ, {"ABUSEIPDB_API_KEY": "k"}):
            with mock.patch.object(tim, "urlopen",
                                   side_effect=OSError("net down")):
                path, old_path, old_conn = _fresh_db()
                try:
                    self.assertIsNone(tim._abuseipdb_check("203.0.113.7"))
                finally:
                    _restore_db(path, old_path, old_conn)


class FetchGuardTests(unittest.TestCase):
    def test_non_feed_host_refused(self):
        with self.assertRaises(ValueError):
            tim._fetch_url("https://evil.example/feed.txt")

    def test_redirect_to_non_feed_host_refused(self):
        class FakeResp:
            def __init__(self):
                self._url = "https://evil.example/real"
            def geturl(self):
                return self._url
            def read(self, n=-1):
                return b""
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        with mock.patch.object(tim, "urlopen",
                               return_value=FakeResp()):
            with self.assertRaises(ValueError):
                tim._fetch_url("https://urlhaus.abuse.ch/downloads/hostfile/")

    def test_size_cap(self):
        class BigResp:
            def __init__(self):
                self._url = "https://urlhaus.abuse.ch/downloads/hostfile/"
            def geturl(self):
                return self._url
            def read(self, n=-1):
                return b"x" * 70000
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
        with mock.patch.object(tim, "urlopen", return_value=BigResp()):
            with mock.patch.object(tim, "MAX_FEED_BYTES", 1000):
                with self.assertRaises(ValueError):
                    tim._fetch_url("https://urlhaus.abuse.ch/downloads/hostfile/")

    def test_failed_refresh_keeps_old_rows(self):
        path, old_path, old_conn = _fresh_db()
        try:
            dbm.ti_replace_feed("urlhaus-domains", "domain",
                                [("old.example.com", "old")])
            with mock.patch.object(tim, "_fetch_url",
                                   side_effect=OSError("net down")):
                results = tim.refresh_feeds()
            self.assertFalse(results["urlhaus-domains"]["ok"])
            hits = dbm.ti_lookup("domain", ["old.example.com"])
            self.assertEqual(len(hits["old.example.com"]), 1)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_maybe_refresh_cadence(self):
        path, old_path, old_conn = _fresh_db()
        try:
            base = time.time()
            with mock.patch.object(tim, "_fetch_url",
                                    return_value="127.0.0.1 x.example.com\n"):
                r1 = tim.maybe_refresh_feeds(now=base)
                self.assertIsNotNone(r1)
                self.assertTrue(r1["urlhaus-domains"]["ok"])
                r2 = tim.maybe_refresh_feeds(now=base + 100)
                self.assertIsNone(r2)  # within the 12h cadence
                r3 = tim.maybe_refresh_feeds(now=base + 13 * 3600)
                self.assertIsNotNone(r3)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_reverse_dns_invalid_ip(self):
        self.assertEqual(tim.reverse_dns("not-an-ip"), "")

    def test_failed_refresh_backs_off(self):
        path, old_path, old_conn = _fresh_db()
        try:
            base = time.time()
            with mock.patch.object(tim, "_fetch_url",
                                   side_effect=OSError("net down")):
                r1 = tim.maybe_refresh_feeds(now=base)
                self.assertIsNotNone(r1)  # attempted...
                self.assertFalse(r1["urlhaus-domains"]["ok"])
                r2 = tim.maybe_refresh_feeds(now=base + 120)
                self.assertIsNone(r2)  # ...then backs off for an hour
                r3 = tim.maybe_refresh_feeds(now=base + 3700)
                self.assertIsNotNone(r3)  # retry window passed
        finally:
            _restore_db(path, old_path, old_conn)


class DashboardIntelTests(unittest.TestCase):
    def setUp(self):
        if dashm is None:
            self.skipTest("Flask not installed")
        self.path, self.old_path, self.old_conn = _fresh_db()
        self.client = dashm.app.test_client()

    def tearDown(self):
        _restore_db(self.path, self.old_path, self.old_conn)

    def test_intel_status_empty(self):
        r = self.client.get("/api/intel/status")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["feeds"], [])
        self.assertIn("abuseipdb", d)

    def test_intel_ip_lookup(self):
        now = time.time()
        dbm.ti_replace_feed("et-compromised-ips", "ip",
                            [("203.0.113.7", "bad ip")])
        dbm.insert_flows(
            [(now - 60, "192.168.1.5", "203.0.113.7", 50000, 443,
              "TCP", 10, 50000, "outbound")])
        with dbm.notifications_paused():
            dbm.add_alert("port_scan", "Medium",
                          "Port scan from 203.0.113.7",
                          "203.0.113.7 knocked on 50 ports.")
        r = self.client.get("/api/intel/ip/203.0.113.7")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertEqual(len(d["listed"]), 1)
        self.assertIn("scanning", d["tags"])
        self.assertEqual(d["up_mb_24h"], 0.0)
        self.assertEqual(d["down_mb_24h"], 0.05)
        self.assertEqual(len(d["alerts"]), 1)
        # only real fields appear: no abuse keys without a configured key
        self.assertNotIn("abuse_score", d)
        r = self.client.get("/api/intel/ip/not-an-ip")
        self.assertEqual(r.status_code, 400)

    def test_intel_ip_word_boundary(self):
        # 192.168.1.10 must not tag along on a 192.168.1.1 lookup
        with dbm.notifications_paused():
            dbm.add_alert("port_scan", "Medium", "t",
                          "192.168.1.10 knocked on ports.")
        r = self.client.get("/api/intel/ip/192.168.1.1")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["tags"], [])
        self.assertEqual(d["alerts"], [])

    def test_intel_domain_lookup(self):
        now = time.time()
        dbm.ti_replace_feed("urlhaus-domains", "domain",
                            [("evil.example.com", "phishing feed")])
        dbm.insert_dns_queries(
            [(now - 60, "192.168.1.5", "evil.example.com", 1)])
        r = self.client.get("/api/intel/domain/evil.example.com")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertEqual(len(d["listed"]), 1)
        self.assertEqual(d["lookups_total"], 1)
        r = self.client.get("/api/intel/domain/not_a_domain!!")
        self.assertEqual(r.status_code, 400)

    def test_intel_refresh_mocked(self):
        with mock.patch.object(
                tim, "_fetch_url",
                return_value="127.0.0.1 evil.example.com\n"):
            r = self.client.post("/api/intel/refresh")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertTrue(d["results"]["urlhaus-domains"]["ok"])
        r = self.client.get("/api/intel/status")
        feeds = {f["feed"]: f for f in r.get_json()["feeds"]}
        self.assertEqual(feeds["urlhaus-domains"]["entries"], 1)

    def test_device_page(self):
        now = time.time()
        dbm.insert_arp_observations(
            [(now - 7200, "192.168.1.5", "aa:bb:cc:dd:ee:ff"),
             (now - 60, "192.168.1.5", "aa:bb:cc:dd:ee:ff")])
        dbm.insert_flows(
            [(now - 60, "192.168.1.5", "93.184.216.34", 50000, 443,
              "TCP", 10, 2_000_000, "outbound")])
        with dbm.notifications_paused():
            dbm.add_alert("unusual_port", "Medium", "t",
                          "device 192.168.1.5 talked on port 8443.")
        r = self.client.get("/api/device/aa:bb:cc:dd:ee:ff")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        self.assertEqual(d["ips"], ["192.168.1.5"])
        self.assertEqual(d["up_mb_24h"], 2.0)
        self.assertEqual(len(d["ports"]), 1)
        self.assertEqual(d["ports"][0]["port"], 443)
        self.assertEqual(len(d["alerts"]), 1)
        r = self.client.get("/api/device/zzz")
        self.assertEqual(r.status_code, 400)
        r = self.client.get("/api/device/AA:BB:CC:DD:EE:FF")
        self.assertEqual(r.status_code, 200)  # case-insensitive MAC

    def test_host_event_4625_tag(self):
        with dbm.notifications_paused():
            dbm.add_alert("host_event", "Medium", "t",
                          "5 failed logons from 203.0.113.9 (event 4625).")
        r = self.client.get("/api/intel/ip/203.0.113.9")
        d = r.get_json()
        self.assertIn("brute-force", d["tags"])


if __name__ == "__main__":
    unittest.main()
