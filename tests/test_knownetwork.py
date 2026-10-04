"""Tests for the Phase 3.5 batch 6 (2026-10-03): "know the network".

- Asset inventory: OUI vendor lookup, TTL OS guess, hostname/TTL
  observation storage, asset refresh combining all sources.
- Self vulnerability scan: LAN-only safety, local risk knowledge base,
  finding storage (new/changed/resolved), quiet re-scans.
- Top talkers: per-device up/down attribution over the last hour.
- Internet uptime log: weekly stats math.
- Windows log ingestion: pfirewall.log parsing, Security XML parsing,
  safe file enumeration, USB / 4625 / Defender detection rules.
- Sensor self-health: baseline learn, drift detection, scheduling.

Run: python -m unittest discover -s tests
"""
import json
import os
import socket
import sys
import tempfile
import threading
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import assets as assetsm
from netmon import scan as scanm
from netmon import ingest as ingm
from netmon import selfcheck as selfm
from netmon import mitre as mitrem
from netmon import config as cfgm
from netmon import topology as topom

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


class _DbTest(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)


# --- asset enrichment --------------------------------------------------------

class OuiVendorTests(unittest.TestCase):
    def test_known_vendors(self):
        self.assertEqual(assetsm.vendor_for_mac("00:1b:63:aa:bb:cc"),
                         "Apple")
        self.assertEqual(assetsm.vendor_for_mac("00:23:04:11:22:33"),
                         "Cisco")
        self.assertEqual(assetsm.vendor_for_mac("b8:27:eb:00:11:22"),
                         "Raspberry Pi")
        self.assertEqual(assetsm.vendor_for_mac("B8:27:EB:00:11:22"),
                         "Raspberry Pi")  # case-insensitive

    def test_unknown_and_randomized(self):
        self.assertEqual(assetsm.vendor_for_mac("00:00:00:00:00:00"), "")
        # Locally-administered (randomized) MACs have no real OUI.
        self.assertEqual(assetsm.vendor_for_mac("02:1b:63:aa:bb:cc"), "")
        self.assertEqual(assetsm.vendor_for_mac("1a:2b:3c:4d:5e:6f"), "")

    def test_malformed(self):
        self.assertEqual(assetsm.vendor_for_mac(""), "")
        self.assertEqual(assetsm.vendor_for_mac("not-a-mac"), "")
        self.assertEqual(assetsm.vendor_for_mac(None), "")


class TtlOsTests(unittest.TestCase):
    def test_guesses(self):
        self.assertIn("Linux", assetsm.os_guess_for_ttl(64))
        self.assertIn("Linux", assetsm.os_guess_for_ttl(61))
        self.assertEqual(assetsm.os_guess_for_ttl(128), "Windows")
        self.assertEqual(assetsm.os_guess_for_ttl(127), "Windows")
        self.assertEqual(assetsm.os_guess_for_ttl(255), "Network gear")
        self.assertEqual(assetsm.os_guess_for_ttl(250), "Network gear")

    def test_unknown(self):
        self.assertEqual(assetsm.os_guess_for_ttl(100), "")
        self.assertEqual(assetsm.os_guess_for_ttl(30), "")
        self.assertEqual(assetsm.os_guess_for_ttl(0), "")
        self.assertEqual(assetsm.os_guess_for_ttl("abc"), "")
        self.assertEqual(assetsm.os_guess_for_ttl(None), "")


class HostnameTests(_DbTest):
    def test_insert_and_latest_wins(self):
        now = time.time()
        dbm.insert_hostname_observations([
            (now - 100, "aa:bb:cc:dd:ee:ff", "192.168.1.10",
             "Living-Room-TV", "dhcp"),
            (now, "aa:bb:cc:dd:ee:ff", "192.168.1.10",
             "Living-Room-TV-2", "mdns"),
        ])
        m = dbm.device_hostname_map()
        self.assertEqual(m["aa:bb:cc:dd:ee:ff"],
                         ("Living-Room-TV-2", "mdns"))

    def test_sanitizes_lan_strings(self):
        now = time.time()
        dbm.insert_hostname_observations([
            (now, "aa:bb:cc:dd:ee:ff", "192.168.1.10",
             "<script>alert(1)</script>", "dhcp"),
            (now, "aa:bb:cc:dd:ee:01", "192.168.1.11", "   ", "dhcp"),
        ])
        m = dbm.device_hostname_map()
        self.assertNotIn("<", m["aa:bb:cc:dd:ee:ff"][0])
        self.assertNotIn("aa:bb:cc:dd:ee:01", m)

    def test_empty_is_noop(self):
        dbm.insert_hostname_observations([])
        self.assertEqual(dbm.device_hostname_map(), {})


class TtlRecordTests(_DbTest):
    def test_record_and_map(self):
        now = time.time()
        dbm.record_ttls([("192.168.1.10", 64, now),
                         ("192.168.1.11", 128, now)])
        m = dbm.device_ttl_map()
        self.assertEqual(m["192.168.1.10"], 64)
        self.assertEqual(m["192.168.1.11"], 128)
        # latest write wins
        dbm.record_ttls([("192.168.1.10", 63, now + 1)])
        self.assertEqual(dbm.device_ttl_map()["192.168.1.10"], 63)


class AssetsSyncTests(_DbTest):
    def test_refresh_combines_sources(self):
        now = time.time()
        dbm.insert_arp_observations([
            (now - 3600, "192.168.1.10", "b8:27:eb:00:11:22"),
            (now, "192.168.1.10", "b8:27:eb:00:11:22"),
        ])
        dbm.insert_hostname_observations([
            (now, "b8:27:eb:00:11:22", "192.168.1.10", "pihole", "dhcp"),
        ])
        dbm.record_ttls([("192.168.1.10", 64, now)])
        dbm.record_scan_findings(now, [
            ("192.168.1.10", "b8:27:eb:00:11:22", 80, "HTTP", "Low",
             "A web page is served here."),
        ])
        n = assetsm.refresh_assets()
        self.assertEqual(n, 1)
        assets = dbm.get_assets()
        self.assertEqual(len(assets), 1)
        a = assets[0]
        self.assertEqual(a["mac"], "b8:27:eb:00:11:22")
        self.assertEqual(a["ip"], "192.168.1.10")
        self.assertEqual(a["hostname"], "pihole")
        self.assertEqual(a["hostname_source"], "dhcp")
        self.assertEqual(a["vendor"], "Raspberry Pi")
        self.assertIn("Linux", a["os_guess"])
        self.assertEqual(len(a["open_ports"]), 1)
        self.assertEqual(a["open_ports"][0]["port"], 80)
        self.assertAlmostEqual(a["first_seen"], now - 3600, delta=1)
        self.assertAlmostEqual(a["last_seen"], now, delta=1)

    def test_device_without_enrichment(self):
        now = time.time()
        dbm.insert_arp_observations([(now, "192.168.1.99",
                                      "02:11:22:33:44:55")])
        assetsm.refresh_assets()
        a = dbm.get_assets()[0]
        self.assertEqual(a["vendor"], "")      # randomized MAC
        self.assertEqual(a["os_guess"], "")    # no TTL seen
        self.assertEqual(a["hostname"], "")
        self.assertEqual(a["open_ports"], [])

    def test_assets_stale(self):
        self.assertTrue(dbm.assets_stale())
        assetsm.refresh_assets()
        self.assertFalse(dbm.assets_stale())
        self.assertTrue(dbm.assets_stale(max_age_s=-1))


# --- self vulnerability scan -------------------------------------------------

class ScanKbTests(unittest.TestCase):
    def test_every_scanned_port_has_kb_entry(self):
        for port, _service in scanm.SCAN_PORTS:
            self.assertIn(port, scanm.RISK_KB,
                          f"port {port} has no risk knowledge-base entry")
            risk, what = scanm.RISK_KB[port]
            self.assertIn(risk, ("Low", "Medium"),
                          f"port {port}: findings are Low/Medium only")
            self.assertTrue(what and len(what) > 20)

    def test_risky_ports_covered(self):
        for port in (23, 445, 3389, 5900, 6379, 3306):
            self.assertIn(port, scanm.RISK_KB)


class ScanSafetyTests(unittest.TestCase):
    def test_lan_targets_only(self):
        self.assertTrue(scanm._ok_target("192.168.1.5"))
        self.assertTrue(scanm._ok_target("10.0.0.1"))
        self.assertTrue(scanm._ok_target("172.16.5.4"))
        self.assertTrue(scanm._ok_target("127.0.0.1"))
        self.assertFalse(scanm._ok_target("8.8.8.8"))
        self.assertFalse(scanm._ok_target("203.0.113.7"))
        self.assertFalse(scanm._ok_target("999.1.1.1"))
        self.assertFalse(scanm._ok_target(""))
        self.assertFalse(scanm._ok_target(None))

    def test_public_ip_never_scanned(self):
        # Would raise/attempt network if it tried; must return empty fast.
        self.assertEqual(scanm.scan_device("8.8.8.8", ports=[80]), set())

    def test_scan_targets_are_lan_only(self):
        for ip in scanm.scan_targets():
            self.assertTrue(scanm._ok_target(ip), ip)


class ScanLocalhostTests(_DbTest):
    def test_open_and_closed_ports(self):
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", 0))
        srv.listen(1)
        open_port = srv.getsockname()[1]
        closed_port = open_port + 1  # almost certainly closed
        try:
            found = scanm.scan_device("127.0.0.1",
                                      ports=[open_port, closed_port],
                                      timeout=0.5)
            self.assertIn(open_port, found)
            self.assertNotIn(closed_port, found)
        finally:
            srv.close()

    def test_bad_ports_ignored(self):
        self.assertEqual(scanm.scan_device("127.0.0.1", ports=[0, 99999,
                                                               "nope"],
                                          timeout=0.2), set())


class ScanFindingsTests(_DbTest):
    def test_new_changed_resolved(self):
        now = time.time()
        f1 = [("192.168.1.10", "aa:bb:cc:dd:ee:ff", 80, "HTTP", "Low",
               "web page here."),
              ("192.168.1.10", "aa:bb:cc:dd:ee:ff", 23, "Telnet", "Medium",
               "plain-text logins.")]
        new, resolved, changed = dbm.record_scan_findings(now, f1)
        self.assertEqual(len(new), 2)
        self.assertEqual(resolved, [])
        self.assertEqual(changed, [])
        # identical re-scan: nothing new, nothing resolved
        new2, resolved2, changed2 = dbm.record_scan_findings(now + 1, f1)
        self.assertEqual(new2, [])
        self.assertEqual(resolved2, [])
        self.assertEqual(changed2, [])
        # port 23 closed now: resolved
        f2 = [f1[0]]
        new3, resolved3, changed3 = dbm.record_scan_findings(now + 2, f2)
        self.assertEqual(new3, [])
        self.assertEqual(resolved3, [("192.168.1.10", 23)])
        self.assertEqual(
            [f["status"] for f in dbm.list_scan_findings(status="open")],
            ["open"])
        self.assertEqual(len(dbm.list_scan_findings(status="resolved")), 1)

    def test_risk_change_flagged(self):
        now = time.time()
        f = [("192.168.1.10", "", 80, "HTTP", "Low", "web.")]
        dbm.record_scan_findings(now, f)
        f2 = [("192.168.1.10", "", 80, "HTTP", "Medium", "web, riskier.")]
        new, resolved, changed = dbm.record_scan_findings(now + 1, f2)
        self.assertEqual(changed, [("192.168.1.10", 80)])

    def test_latest_scan_run(self):
        self.assertIsNone(dbm.latest_scan_run())
        dbm.record_scan_run(time.time(), 12.5, 8, 3, note="manual")
        lr = dbm.latest_scan_run()
        self.assertEqual(lr["devices_scanned"], 8)
        self.assertEqual(lr["findings"], 3)
        self.assertEqual(lr["note"], "manual")


class ScanAlertTests(_DbTest):
    def test_alerts_only_for_new_doors(self):
        now = time.time()
        scanm.alert_new_findings(
            [("192.168.1.10", 23)], [], {"192.168.1.10": "aa:bb:cc:dd:ee:ff"},
            {}, ts=now)
        rows = dbm.query("SELECT kind, severity, title FROM alerts")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][0], "vuln_finding")
        self.assertEqual(rows[0][1], "Medium")  # telnet is Medium
        self.assertIn("23", rows[0][2] + dbm.query(
            "SELECT detail FROM alerts")[0][0])

    def test_low_severity_for_benign_ports(self):
        scanm.alert_new_findings(
            [("192.168.1.10", 80)], [], {"192.168.1.10": ""}, {},
            ts=time.time())
        rows = dbm.query("SELECT severity FROM alerts")
        self.assertEqual(rows[0][0], "Low")

    def test_run_full_scan_quiet_rescan(self):
        # run_full_scan against localhost only: patch scan_targets.
        orig = scanm.scan_targets
        scanm.scan_targets = lambda: ["127.0.0.1"]
        try:
            s1 = scanm.run_full_scan(note="test")
            self.assertTrue(s1["ok"])
            n1 = dbm.query("SELECT COUNT(*) FROM alerts")[0][0]
            s2 = scanm.run_full_scan(note="test")
            self.assertTrue(s2["ok"])
            n2 = dbm.query("SELECT COUNT(*) FROM alerts")[0][0]
            # second identical scan fires no new alerts (quiet is a feature)
            self.assertEqual(n1, n2)
            self.assertEqual(s2["new"], 0)
        finally:
            scanm.scan_targets = orig


# --- top talkers ---------------------------------------------------------------

@unittest.skipIf(dashm is None, "Flask not installed")
class TopTalkersTests(_DbTest):
    def test_per_device_attribution(self):
        now = time.time()
        dbm.insert_arp_observations([
            (now, "192.168.1.10", "aa:bb:cc:dd:ee:ff"),
            (now, "192.168.1.11", "11:22:33:44:55:66"),
        ])
        dbm.insert_flows([
            (now, "192.168.1.10", "93.184.216.34", 5000, 443, "TCP",
             10, 10_000_000, "outbound"),
            (now, "93.184.216.34", "192.168.1.10", 443, 5000, "TCP",
             10, 40_000_000, "inbound"),
            (now, "192.168.1.11", "93.184.216.34", 5001, 443, "TCP",
             10, 5_000_000, "outbound"),
        ])
        client = dashm.app.test_client()
        r = client.get("/api/top_talkers")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertEqual(d["window_min"], 60)
        by_mac = {t["mac"]: t for t in d["talkers"]}
        tv = by_mac["aa:bb:cc:dd:ee:ff"]
        self.assertAlmostEqual(tv["up_mb"], 10.0, delta=0.01)
        self.assertAlmostEqual(tv["down_mb"], 40.0, delta=0.01)
        self.assertAlmostEqual(tv["total_mb"], 50.0, delta=0.01)
        # sorted by total desc
        totals = [t["total_mb"] for t in d["talkers"]]
        self.assertEqual(totals, sorted(totals, reverse=True))


# --- internet uptime log ---------------------------------------------------------

class OutageStatsTests(_DbTest):
    def test_weekly_stats(self):
        now = time.time()
        # two outages inside the week, one outside
        o1 = dbm.start_outage("gateway", now - 3 * 86400)
        dbm.end_outage(o1, now - 3 * 86400 + 600)     # 10 min
        o2 = dbm.start_outage("internet", now - 86400)
        dbm.end_outage(o2, now - 86400 + 1800)        # 30 min
        o3 = dbm.start_outage("gateway", now - 10 * 86400)
        dbm.end_outage(o3, now - 10 * 86400 + 3600)   # outside window
        stats = dbm.outage_stats(7)
        self.assertEqual(stats["count"], 2)
        self.assertAlmostEqual(stats["total_s"], 2400, delta=1)
        self.assertAlmostEqual(stats["longest_s"], 1800, delta=1)
        self.assertGreater(stats["uptime_pct"], 99.0)
        self.assertLess(stats["uptime_pct"], 100.0)
        self.assertEqual(stats["ongoing_s"], 0.0)

    def test_ongoing_outage(self):
        now = time.time()
        dbm.start_outage("internet", now - 120)
        stats = dbm.outage_stats(7)
        self.assertEqual(stats["count"], 0)  # only completed count
        self.assertGreater(stats["ongoing_s"], 100)

    def test_quiet_week(self):
        stats = dbm.outage_stats(7)
        self.assertEqual(stats["count"], 0)
        self.assertEqual(stats["total_s"], 0.0)
        self.assertEqual(stats["uptime_pct"], 100.0)

    def test_log_lists_recent(self):
        now = time.time()
        o1 = dbm.start_outage("gateway", now - 100)
        dbm.end_outage(o1, now - 40)
        log = dbm.list_outages(30)
        self.assertEqual(len(log), 1)
        self.assertEqual(log[0]["target"], "gateway")
        self.assertAlmostEqual(log[0]["gap_seconds"], 60, delta=1)


# --- Windows log ingestion -------------------------------------------------------

_PF_SAMPLE = """\
#Version: 1.5
#Software: Microsoft Windows Firewall
#Time Format: Local
#Fields: date time action protocol src-ip dst-ip src-port dst-port size tcpflags tcpsyn tcpack tcpwin icmptype icmpcode info path
2026-10-03 14:22:01 DROP TCP 203.0.113.9 192.168.1.50 41234 445 60 S 1 0 8192 - - - RECEIVE
2026-10-03 14:22:02 ALLOW TCP 192.168.1.50 93.184.216.34 51234 443 60 - - - - - - - SEND
2026-10-03 14:22:03 DROP UDP 203.0.113.9 192.168.1.50 53 53 60 - - - - - - - RECEIVE
"""

_XML_SAMPLE = """\
<Events>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Microsoft-Windows-Security-Auditing"/><EventID>4625</EventID><TimeCreated SystemTime="2026-10-03T14:22:01.1234567Z"/><Computer>PC-01</Computer><Channel>Security</Channel></System>
<EventData><Data Name="TargetUserName">admin</Data><Data Name="IpAddress">203.0.113.9</Data><Data Name="LogonType">3</Data></EventData>
</Event>
<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
<System><Provider Name="Service Control Manager"/><EventID>7045</EventID><TimeCreated SystemTime="2026-10-03T14:23:01Z"/><Computer>PC-01</Computer><Channel>System</Channel></System>
<EventData><Data Name="ServiceName">EvilSvc</Data><Data Name="ImagePath">C:\\evil\\evil.exe</Data></EventData>
</Event>
</Events>
"""


class PfirewallParseTests(unittest.TestCase):
    def test_drops_stored_allows_skipped(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as fh:
            fh.write(_PF_SAMPLE)
            path = fh.name
        try:
            events, offset, skipped = ingm.parse_pfirewall(path, 0)
            self.assertEqual(len(events), 2)  # DROP rows only
            self.assertEqual(skipped, 0)
            self.assertGreater(offset, 0)
            self.assertEqual(events[0][2], "DROP")
            detail = json.loads(events[0][5])
            self.assertEqual(detail["src_ip"], "203.0.113.9")
            self.assertEqual(detail["dst_port"], "445")
            # incremental: second read from the offset finds nothing new
            events2, _o2, _s2 = ingm.parse_pfirewall(path, offset)
            self.assertEqual(events2, [])
        finally:
            os.unlink(path)

    def test_missing_fields_header_skips(self):
        with tempfile.NamedTemporaryFile("w", suffix=".log",
                                         delete=False) as fh:
            fh.write("2026-10-03 14:22:01 DROP TCP 1.2.3.4 5.6.7.8 1 2 3\n")
            path = fh.name
        try:
            events, _o, skipped = ingm.parse_pfirewall(path, 0)
            self.assertEqual(events, [])
            self.assertEqual(skipped, 1)
        finally:
            os.unlink(path)


class SecurityXmlParseTests(unittest.TestCase):
    def test_events_parsed(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml",
                                         delete=False) as fh:
            fh.write(_XML_SAMPLE)
            path = fh.name
        try:
            events, skipped = ingm.parse_security_xml(path, since_ts=0)
            self.assertEqual(len(events), 2)
            self.assertEqual(skipped, 0)
            by_id = {e[2]: e for e in events}
            self.assertEqual(by_id["4625"][3], "PC-01")
            detail = json.loads(by_id["4625"][5])
            self.assertEqual(detail["fields"]["IpAddress"], "203.0.113.9")
            self.assertIn("Failed logon", detail["summary"])
            self.assertIn("EvilSvc", json.loads(by_id["7045"][5])["summary"])
            # incremental: nothing newer than the max ts
            max_ts = max(e[0] for e in events)
            events2, _s2 = ingm.parse_security_xml(path,
                                                   since_ts=max_ts)
            self.assertEqual(events2, [])
        finally:
            os.unlink(path)

    def test_bad_xml_degrades(self):
        with tempfile.NamedTemporaryFile("w", suffix=".xml",
                                         delete=False) as fh:
            fh.write("<Events><broken")
            path = fh.name
        try:
            events, skipped = ingm.parse_security_xml(path)
            self.assertEqual(events, [])
            self.assertEqual(skipped, 1)
        finally:
            os.unlink(path)


class SafeFilesTests(unittest.TestCase):
    def test_enumeration_rules(self):
        with tempfile.TemporaryDirectory() as d:
            open(os.path.join(d, "a.log"), "w").write("x")
            open(os.path.join(d, "b.xml"), "w").write("x")
            open(os.path.join(d, ".hidden.log"), "w").write("x")
            open(os.path.join(d, "c.evtx"), "w").write("x")
            os.mkdir(os.path.join(d, "subdir"))
            open(os.path.join(d, "subdir", "d.log"), "w").write("x")
            # symlink escaping the dir must be skipped
            os.symlink("/etc/hosts", os.path.join(d, "escape.log"))
            names = sorted(os.path.basename(p)
                           for p in ingm._safe_files(d))
            self.assertEqual(names, ["a.log", "b.xml"])

    def test_missing_dir_is_empty(self):
        self.assertEqual(list(ingm._safe_files("/no/such/dir")), [])


class FailedLogonRuleTests(_DbTest):
    def _logon_events(self, ip, count, base_ts):
        rows = []
        for i in range(count):
            detail = json.dumps({
                "summary": "x",
                "fields": {"TargetUserName": "admin", "IpAddress": ip,
                           "LogonType": "3"}})
            rows.append((base_ts + i * 60, "eventlog", "4625", "PC-01",
                         "admin", detail))
        dbm.insert_host_events(rows)

    def test_burst_fires_medium(self):
        now = time.time()
        self._logon_events("203.0.113.9", 5, now - 300)
        fired = ingm.check_failed_logons()
        self.assertEqual(fired, 1)
        rows = dbm.query("SELECT kind, severity FROM alerts")
        self.assertEqual(rows[0], ("host_event", "Medium"))

    def test_below_threshold_stays_quiet(self):
        now = time.time()
        self._logon_events("203.0.113.9", 4, now - 300)
        self.assertEqual(ingm.check_failed_logons(), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)

    def test_loopback_ignored(self):
        now = time.time()
        self._logon_events("127.0.0.1", 8, now - 300)
        self.assertEqual(ingm.check_failed_logons(), 0)

    def test_correlates_with_network_alert(self):
        now = time.time()
        self._logon_events("203.0.113.9", 2, now - 300)
        aid = dbm.add_alert(
            "port_scan", "High", "Possible port scan from 203.0.113.9",
            "203.0.113.9 tried 25 different ports within 120 seconds.",
            ts=now)
        ingm.check_failed_logons()
        matched = dbm.query(
            "SELECT matched_alert FROM host_events WHERE event_id='4625'")
        self.assertTrue(all(m[0] == aid for m in matched))


class NewServiceRuleTests(_DbTest):
    def test_new_service_alerts_once(self):
        now = time.time()
        detail = json.dumps({"summary": "x", "fields": {
            "ServiceName": "EvilSvc", "ImagePath": "C:\\evil\\evil.exe"}})
        dbm.insert_host_events([(now, "eventlog", "7045", "PC-01", "",
                                 detail)])
        self.assertEqual(ingm.check_new_services(), 1)
        rows = dbm.query("SELECT kind, severity FROM alerts")
        self.assertEqual(rows[0], ("host_event", "Low"))
        # same service again: known now, stays quiet
        dbm.insert_host_events([(now + 10, "eventlog", "7045", "PC-01", "",
                                 detail)])
        dbm.set_meta("ingest_correlate_7045_ts", "0")  # re-run the rule
        self.assertEqual(ingm.check_new_services(), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 1)


class UsbRuleTests(_DbTest):
    def _usb_event(self, device_id, ts, eid="6416"):
        detail = json.dumps({"summary": "x", "fields": {
            "DeviceId": device_id,
            "DeviceDescription": "SanDisk Ultra USB Device",
            "ClassId": "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"}})
        dbm.insert_host_events([(ts, "eventlog", eid, "PC-01", "", detail)])

    def test_unknown_usb_storage_alerts(self):
        now = time.time()
        self._usb_event(
            "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\ABC123&0", now)
        self.assertEqual(ingm.check_usb_devices(), 1)
        rows = dbm.query("SELECT kind, severity, title FROM alerts")
        self.assertEqual(rows[0][0], "usb_insert")
        self.assertEqual(rows[0][1], "Medium")
        self.assertIn("PC-01", rows[0][2])

    def test_known_device_stays_quiet(self):
        now = time.time()
        dev = "USBSTOR\\DISK&VEN_SANDISK&PROD_ULTRA&REV_1.00\\ABC123&0"
        self._usb_event(dev, now)
        self.assertEqual(ingm.check_usb_devices(), 1)
        self._usb_event(dev, now + 3600)  # unplug/replug tomorrow
        dbm.set_meta("ingest_correlate_usb_ts", "0")
        self.assertEqual(ingm.check_usb_devices(), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 1)

    def test_non_storage_usb_stored_not_alerted(self):
        now = time.time()
        detail = json.dumps({"summary": "x", "fields": {
            "DeviceId": "USB\\VID_046D&PID_C52B\\1234",
            "DeviceDescription": "USB Keyboard",
            "ClassId": "{4d36e96b-e325-11ce-bfc1-08002be10318}"}})
        dbm.insert_host_events([(now, "eventlog", "6416", "PC-01", "",
                                 detail)])
        self.assertEqual(ingm.check_usb_devices(), 0)
        self.assertEqual(dbm.query("SELECT COUNT(*) FROM alerts")[0][0], 0)


class DefenderRuleTests(_DbTest):
    def _defender_event(self, eid, fields, ts):
        detail = json.dumps({"summary": "x", "fields": fields})
        dbm.insert_host_events([(ts, "eventlog", eid, "PC-01", "", detail)])

    def test_detection_alerts(self):
        now = time.time()
        self._defender_event("1117", {
            "Threat Name": "Trojan:Win32/Wacatac", "Severity Name": "Severe",
            "Action Name": "Quarantine", "Path": "file:C:\\dl\\x.exe"}, now)
        self.assertEqual(ingm.check_defender(), 1)
        rows = dbm.query("SELECT kind, severity FROM alerts")
        self.assertEqual(rows[0], ("defender_detection", "High"))

    def test_detection_plus_c2_is_critical(self):
        now = time.time()
        host = socket.gethostname()
        # network saw this host beaconing to an external IP
        local_ip = "127.0.0.1"  # always a local IP
        dbm.add_alert(
            "beaconing", "Medium",
            f"Repeated check-ins: device {local_ip} with 203.0.113.77",
            f"device {local_ip} contacted 203.0.113.77 in 10 of the last"
            " 60 minutes -- roughly every 6 minutes (0.50 MB total).",
            ts=now - 3600)
        self._defender_event("1116", {
            "Threat Name": "Trojan:Win32/Emotet", "Severity Name": "Severe",
            "Path": "file:C:\\dl\\y.exe"}, now)
        # event must come from this box for host->IP resolution
        dbm.query("UPDATE host_events SET computer=?", (host,))
        dbm.set_meta("ingest_correlate_defender_ts", "0")
        self.assertEqual(ingm.check_defender(), 1)
        rows = dbm.query(
            "SELECT kind, severity, detail FROM alerts"
            " WHERE kind='host_compromise'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0][1], "Critical")
        self.assertIn("203.0.113.77", rows[0][2])

    def test_rtp_disabled_is_high(self):
        now = time.time()
        self._defender_event("5007", {
            "New Value": "Real-Time Protection disabled = false"}, now)
        self.assertEqual(ingm.check_defender(), 1)
        rows = dbm.query(
            "SELECT kind, severity FROM alerts WHERE kind='host_event'")
        self.assertEqual(rows[0][1], "High")


class IngestRunTests(_DbTest):
    def setUp(self):
        super().setUp()
        cfgm._CACHE.clear()  # env changes must not hit a stale config cache
        self._old_env = os.environ.get("BRUTEDASH_INGEST_WATCH_DIR")

    def tearDown(self):
        cfgm._CACHE.clear()
        if self._old_env is None:
            os.environ.pop("BRUTEDASH_INGEST_WATCH_DIR", None)
        else:
            os.environ["BRUTEDASH_INGEST_WATCH_DIR"] = self._old_env
        super().tearDown()

    def test_disabled_without_watch_dir(self):
        os.environ["BRUTEDASH_INGEST_WATCH_DIR"] = ""
        self.assertEqual(ingm.run_ingest()["enabled"], False)

    def test_full_pass(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "pfirewall.log"), "w") as fh:
                fh.write(_PF_SAMPLE)
            with open(os.path.join(d, "security.xml"), "w") as fh:
                fh.write(_XML_SAMPLE)
            os.environ["BRUTEDASH_INGEST_WATCH_DIR"] = d
            summary = ingm.run_ingest()
            self.assertTrue(summary["enabled"])
            self.assertEqual(summary["files"], 2)
            self.assertEqual(summary["events"], 4)  # 2 DROP + 2 XML
            # second pass: nothing new
            summary2 = ingm.run_ingest()
            self.assertEqual(summary2["events"], 0)


# --- sensor self-health ----------------------------------------------------------

class SelfcheckTests(_DbTest):
    def test_listening_ports_readable(self):
        status, detail, current = selfm.check_listening_ports()
        self.assertIn(status, ("ok", "drift", "unavailable", "error"))
        self.assertIsInstance(current, set)

    def test_baseline_learn_then_ok(self):
        r1 = selfm.run_selfcheck()
        self.assertEqual(r1["alerts"], 0)  # first run learns silently
        r2 = selfm.run_selfcheck()
        self.assertEqual(r2["alerts"], 0)
        self.assertIn(selfm.status_summary()["status"], ("ok", "drift"))

    def test_drift_alerts(self):
        selfm.run_selfcheck()  # learn baseline
        # pretend the baseline had no ports: everything now is drift
        dbm.selfcheck_baseline_set("listening_ports", [])
        # but only if there IS something listening; force determinism:
        base = dbm.selfcheck_baseline_get("listening_ports")
        self.assertEqual(base, [])
        r = selfm.run_selfcheck()
        status = r["checks"]["listening_ports"]["status"]
        if status == "drift":
            self.assertEqual(r["alerts"], 1)
            rows = dbm.query(
                "SELECT kind, severity FROM alerts WHERE kind='self_drift'")
            self.assertEqual(rows[0][1], "Medium")
        else:
            # nothing listening on this box: no drift possible, no alert
            self.assertEqual(r["alerts"], 0)

    def test_scheduling(self):
        self.assertIsNotNone(selfm.maybe_scheduled_selfcheck())  # first: due
        self.assertIsNone(selfm.maybe_scheduled_selfcheck())     # now: waiting

    def test_non_windows_checks_unavailable(self):
        if not selfm._is_windows():
            for fn in (selfm.check_services, selfm.check_autorun,
                       selfm.check_defender_rtp):
                status, _d, _c = fn()
                self.assertEqual(status, "unavailable")


# --- network topology map ----------------------------------------------------

class OuiFileTests(unittest.TestCase):
    def test_oui_file_is_the_source(self):
        import os as _os
        path = _os.path.join(_os.path.dirname(assetsm.__file__), "oui.txt")
        self.assertTrue(_os.path.isfile(path))
        self.assertGreater(len(assetsm.OUI_VENDORS), 100)
        # spot checks still resolve through the file
        self.assertEqual(assetsm.vendor_for_mac("00:1b:63:aa:bb:cc"), "Apple")
        self.assertEqual(assetsm.vendor_for_mac("b8:27:eb:00:11:22"),
                         "Raspberry Pi")
        self.assertEqual(assetsm.vendor_for_mac("00:00:00:00:00:00"), "")


class ClassifyTests(_DbTest):
    def test_user_pin_wins(self):
        dbm.set_device_type("aa:bb:cc:dd:ee:ff", "tv")
        dtype, src = topom.classify_device(
            "aa:bb:cc:dd:ee:ff", vendor="Apple", hostname="MacBook-Pro")
        self.assertEqual((dtype, src), ("tv", "manual"))
        # clearing the pin falls back to auto
        dbm.set_device_type("aa:bb:cc:dd:ee:ff", "")
        dtype, src = topom.classify_device(
            "aa:bb:cc:dd:ee:ff", hostname="Roku-TV")
        self.assertEqual((dtype, src), ("tv", "auto"))

    def test_gateway_is_router(self):
        dtype, src = topom.classify_device(
            "aa:bb:cc:dd:ee:01", vendor="Netgear", is_gateway=True)
        self.assertEqual(dtype, "router")

    def test_hostname_keywords(self):
        cases = [("Roku-Streaming-Stick", "tv"),
                 ("HP-LaserJet-Pro", "printer"),
                 ("Living-Room-Echo", "iot"),
                 ("synology-nas", "server"),
                 ("iPhone-von-Demetrius", "phone"),
                 ("DESKTOP-9X2K1", "desktop"),
                 ("ThinkPad-T14", "laptop")]
        for hn, want in cases:
            dtype, src = topom.classify_device(
                "aa:bb:cc:dd:ee:ff", hostname=hn)
            self.assertEqual(dtype, want, hn)
            self.assertEqual(src, "auto")

    def test_printer_port_and_vendor(self):
        dtype, _ = topom.classify_device(
            "aa:bb:cc:dd:ee:ff", vendor="Brother",
            open_ports=[{"port": 9100, "service": "jetdirect"}])
        self.assertEqual(dtype, "printer")

    def test_streaming_dns_hint(self):
        dtype, _ = topom.classify_device(
            "aa:bb:cc:dd:ee:ff", vendor="Amazon",
            dns_hints=("streaming",))
        self.assertEqual(dtype, "tv")

    def test_unknown_when_ambiguous(self):
        dtype, src = topom.classify_device("aa:bb:cc:dd:ee:ff")
        self.assertEqual((dtype, src), ("unknown", "auto"))

    def test_valid_dtype_allowlist(self):
        for t in topom.DEVICE_TYPES:
            self.assertTrue(topom.valid_dtype(t))
        self.assertFalse(topom.valid_dtype("toaster"))
        self.assertFalse(topom.valid_dtype(""))


class DeviceTypeStoreTests(_DbTest):
    def test_roundtrip_and_clear(self):
        dbm.set_device_type("AA:BB:CC:DD:EE:FF", "printer")
        self.assertEqual(dbm.device_type_map(),
                         {"aa:bb:cc:dd:ee:ff": "printer"})
        dbm.set_device_type("aa:bb:cc:dd:ee:ff", "")
        self.assertEqual(dbm.device_type_map(), {})

    def test_mac_required(self):
        with self.assertRaises(ValueError):
            dbm.set_device_type("", "tv")


class GatewayTests(_DbTest):
    def _seed_flows(self, now):
        # phone talks to laptop a lot; laptop is the most-connected node
        rows = []
        for i in range(5):
            rows.append((now - i * 60, "192.168.1.20", "192.168.1.10",
                         50000 + i, 443, "TCP", 10, 1000, "local"))
            rows.append((now - i * 60, "192.168.1.10", "192.168.1.30",
                         50001 + i, 443, "TCP", 10, 1000, "local"))
        dbm.insert_flows(rows)
        dbm.insert_arp_observations([
            (now, "192.168.1.1", "aa:bb:cc:dd:ee:01"),
            (now, "192.168.1.10", "aa:bb:cc:dd:ee:02"),
            (now, "192.168.1.20", "aa:bb:cc:dd:ee:03"),
            (now, "192.168.1.30", "aa:bb:cc:dd:ee:04"),
        ])

    def test_dhcp_gateway_preferred(self):
        now = time.time()
        self._seed_flows(now)
        dbm.set_meta("dhcp_gateway_ip", "192.168.1.1")
        ip, mac = topom.gateway_info()
        self.assertEqual((ip, mac),
                         ("192.168.1.1", "aa:bb:cc:dd:ee:01"))

    def test_fallback_most_connected(self):
        now = time.time()
        self._seed_flows(now)
        ip, mac = topom.gateway_info()
        # 192.168.1.10 talks to both .20 and .30
        self.assertEqual(ip, "192.168.1.10")
        self.assertEqual(mac, "aa:bb:cc:dd:ee:02")

    def test_no_data_no_gateway(self):
        self.assertEqual(topom.gateway_info(), (None, None))


class TopologyBuildTests(_DbTest):
    def _seed(self, now):
        dbm.insert_arp_observations([
            (now - 7200, "192.168.1.1", "aa:bb:cc:dd:ee:01"),
            (now - 7000, "192.168.1.10", "aa:bb:cc:dd:ee:02"),
            (now - 6900, "192.168.1.20", "aa:bb:cc:dd:ee:03"),
        ])
        dbm.insert_hostname_observations([
            (now - 7000, "aa:bb:cc:dd:ee:02", "192.168.1.10",
             "Roku-TV", "dhcp"),
        ])
        dbm.insert_flows([
            (now - 60, "192.168.1.10", "192.168.1.1", 5000, 443,
             "TCP", 50, 5_000_000, "local"),
            (now - 300, "192.168.1.20", "192.168.1.10", 5001, 8080,
             "TCP", 20, 500_000, "local"),
            (now - 10000, "192.168.1.20", "192.168.1.1", 5002, 443,
             "TCP", 5, 100_000, "local"),
        ])
        assetsm.refresh_assets()

    def test_nodes_edges_gateway(self):
        now = time.time()
        self._seed(now)
        dbm.set_meta("dhcp_gateway_ip", "192.168.1.1")
        topo = topom.build_topology(window_min=60)
        self.assertEqual(topo["gateway"]["ip"], "192.168.1.1")
        by_ip = {n["ip"]: n for n in topo["nodes"]}
        self.assertEqual(by_ip["192.168.1.10"]["dtype"], "tv")
        self.assertEqual(by_ip["192.168.1.1"]["dtype"], "router")
        self.assertTrue(by_ip["192.168.1.1"]["is_gateway"])
        # every non-gateway node has a gateway spoke
        gw_key = topo["gateway"]["key"]
        spokes = [e for e in topo["edges"] if e["kind"] == "gateway"]
        spoke_nodes = {e["a"] for e in spokes} | {e["b"] for e in spokes}
        for n in topo["nodes"]:
            if not n["is_gateway"]:
                self.assertIn(n["key"], spoke_nodes)
        # LAN-local device pair edge exists (.20 <-> .10)
        lan = [e for e in topo["edges"] if e["kind"] == "lan"]
        self.assertTrue(lan)
        # active flag: .10<->gw flow is 5 min old -> active
        gw_edge = [e for e in spokes
                   if by_ip["192.168.1.10"]["key"] in (e["a"], e["b"])]
        self.assertTrue(gw_edge[0]["active"])
        # types list shipped for the re-label dropdown
        self.assertEqual(len(topo["types"]), len(topom.DEVICE_TYPES))

    def test_empty_network_renders(self):
        topo = topom.build_topology(window_min=60)
        self.assertEqual(topo["nodes"], [])
        self.assertEqual(topo["edges"], [])
        self.assertIsNone(topo["gateway"])

    def test_manual_pin_shows_in_topology(self):
        now = time.time()
        self._seed(now)
        dbm.set_device_type("aa:bb:cc:dd:ee:02", "laptop")
        topo = topom.build_topology(window_min=60)
        by_ip = {n["ip"]: n for n in topo["nodes"]}
        self.assertEqual(by_ip["192.168.1.10"]["dtype"], "laptop")
        self.assertEqual(by_ip["192.168.1.10"]["dtype_source"], "manual")

    def test_alert_counts_word_boundary(self):
        now = time.time()
        self._seed(now)
        # alert naming .10 must not count toward .1
        dbm.add_alert("port_scan", "High", "Port scan",
                      "192.168.1.10 touched 25 ports", ts=now - 100)
        counts = topom._alert_counts_24h(
            ["192.168.1.1", "192.168.1.10"])
        self.assertEqual(counts.get("192.168.1.10"), 1)
        self.assertIsNone(counts.get("192.168.1.1"))


class ScanSingleFlightTests(_DbTest):
    def test_second_scan_declines_while_running(self):
        self.assertTrue(scanm._claim_scan())
        try:
            res = scanm.run_full_scan(note="test")
            self.assertFalse(res["ok"])
            self.assertIn("already running", res["error"])
        finally:
            scanm._release_scan()
        self.assertFalse(scanm.scan_already_running())


@unittest.skipIf(dashm is None, "Flask not installed")
class TopologyRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_topology_route(self):
        now = time.time()
        dbm.insert_arp_observations([
            (now - 100, "192.168.1.10", "aa:bb:cc:dd:ee:02")])
        assetsm.refresh_assets()
        c = self._client()
        r = c.get("/api/topology")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertIn("nodes", d)
        self.assertIn("edges", d)
        self.assertIn("types", d)
        self.assertEqual(len(d["nodes"]), 1)
        self.assertEqual(d["nodes"][0]["ip"], "192.168.1.10")

    def test_device_type_route(self):
        c = self._client()
        r = c.post("/api/device_type",
                   json={"mac": "aa:bb:cc:dd:ee:ff", "dtype": "tv"})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(dbm.device_type_map(),
                         {"aa:bb:cc:dd:ee:ff": "tv"})
        # clear back to auto
        r = c.post("/api/device_type",
                   json={"mac": "aa:bb:cc:dd:ee:ff", "dtype": ""})
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(dbm.device_type_map(), {})

    def test_device_type_rejects_bad_input(self):
        c = self._client()
        r = c.post("/api/device_type",
                   json={"mac": "aa:bb:cc:dd:ee:ff", "dtype": "toaster"})
        self.assertEqual(r.status_code, 400)
        r = c.post("/api/device_type",
                   json={"mac": "not-a-mac", "dtype": "tv"})
        self.assertEqual(r.status_code, 400)
        r = c.post("/api/device_type", json={"dtype": "tv"})
        self.assertEqual(r.status_code, 400)


# --- new kinds are MITRE-tagged (mirrors test_phase35's enforcement) ----------

class NewKindsMitreTests(unittest.TestCase):
    def test_new_kinds_tagged(self):
        for kind in ("vuln_finding", "host_event", "usb_insert",
                     "defender_detection", "host_compromise", "self_drift"):
            tag = mitrem.tag_for(kind)
            self.assertIsNotNone(tag, kind)
            self.assertTrue(tag["id"] and tag["name"] and tag["tactic"])


if __name__ == "__main__":
    unittest.main()
