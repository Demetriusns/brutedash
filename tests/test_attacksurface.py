"""Tests for the Phase 3.5 batch 8 (2026-10-03): attack surface view.

- Internet reachability: inbound evidence from external IPs to service
  ports = reachable; return traffic to ephemeral ports = not reachable;
  no flows = not reachable with an honest "no sign" label.
- Severity ranking: reachable+risky=High, TI hit=High, reachable+plain=
  Medium, LAN-only+risky=Medium, LAN-only+plain=Low (rules documented in
  netmon/attacksurface.py).
- Lateral paths: low-trust -> high-value observed flows flagged, one
  hop only; gateway pairs excluded; reverse direction not flagged.
- The review never fires alerts (informational only).
- Playbook slugs: grammar validation; placeholder route 200s on
  well-formed slugs (known and unknown), 404s on malformed ones.
- Dashboard: /api/attack_surface 200 + shape.

Run: python -m unittest discover -s tests
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import attacksurface as asm

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

    def _seed_device(self, mac, ip, hostname="", vendor="",
                     os_guess="", ports=()):
        """One asset row with open ports (ports: [(port, service, risk)])."""
        dbm.refresh_assets([{
            "mac": mac, "ip": ip, "first_seen": time.time() - 1000,
            "last_seen": time.time(), "hostname": hostname,
            "hostname_source": "dhcp" if hostname else "",
            "os_guess": os_guess, "vendor": vendor,
            "open_ports": [{"port": p, "service": s, "risk": r}
                           for p, s, r in ports],
            "updated_ts": time.time(),
        }])


NOW = 1700000000.0
PUB = "93.184.216.34"  # example.com: is_global, safe in tests


class ReachabilityTests(_DbTest):
    def test_inbound_to_service_port_is_evidence(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20",
                          ports=[(3389, "Remote Desktop", "Medium")])
        dbm.insert_flows([
            (NOW, PUB, "192.168.1.20", 41234, 3389, "TCP", 10, 5000,
             "inbound"),
        ])
        reachable, evidence = asm.inbound_evidence(
            "192.168.1.20", {3389}, now=NOW + 10)
        self.assertTrue(reachable)
        self.assertEqual(len(evidence), 1)
        self.assertEqual(evidence[0]["ext_ip"], PUB)
        self.assertEqual(evidence[0]["port"], 3389)

    def test_return_traffic_to_ephemeral_port_is_not_evidence(self):
        # Replies to outbound browsing come back to ephemeral ports --
        # they must not count as "the internet reaching in".
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        dbm.insert_flows([
            (NOW, "192.168.1.20", PUB, 51234, 443, "TCP", 10, 5000,
             "outbound"),
            (NOW, PUB, "192.168.1.20", 443, 51234, "TCP", 10, 5000,
             "inbound"),
        ])
        reachable, evidence = asm.inbound_evidence(
            "192.168.1.20", set(), now=NOW + 10)
        self.assertFalse(reachable)
        self.assertEqual(evidence, [])

    def test_no_flows_not_reachable(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        reachable, evidence = asm.inbound_evidence(
            "192.168.1.20", {80}, now=NOW + 10)
        self.assertFalse(reachable)
        self.assertEqual(evidence, [])

    def test_evidence_bounded(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        rows = [(NOW, f"93.184.216.{i}", "192.168.1.20", 40000 + i, 80,
                 "TCP", 1, 100, "inbound") for i in range(1, 60)]
        dbm.insert_flows(rows)
        reachable, evidence = asm.inbound_evidence(
            "192.168.1.20", {80}, now=NOW + 10)
        self.assertTrue(reachable)
        self.assertLessEqual(len(evidence), asm.EVIDENCE_CAP)


class SeverityRankingTests(_DbTest):
    def _dev(self, dtype="desktop", ports=()):
        return {"name": "TestPC", "hostname": "", "ip": "192.168.1.20",
                "mac": "aa:bb:cc:dd:ee:01", "dtype": dtype,
                "type_label": dtype,
                "open_ports": [{"port": p, "service": s, "risk": r}
                               for p, s, r in ports]}

    def test_reachable_risky_is_high(self):
        exps = asm.device_exposures(
            self._dev(ports=[(3389, "Remote Desktop", "Medium")]),
            True, [])
        self.assertEqual(exps[0]["severity"], "High")
        self.assertEqual(exps[0]["playbook"], "internet-exposed-door")

    def test_reachable_printer_gets_printer_playbook(self):
        exps = asm.device_exposures(
            self._dev(dtype="printer",
                      ports=[(80, "HTTP", "Low"), (9100, "Printer", "Low")]),
            True, [])
        self.assertEqual(len(exps), 1)
        self.assertEqual(exps[0]["severity"], "Medium")
        self.assertEqual(exps[0]["playbook"], "internet-exposed-printer")
        self.assertIn("printer is visible", exps[0]["title"])

    def test_reachable_printer_risky_is_high_printer_playbook(self):
        exps = asm.device_exposures(
            self._dev(dtype="printer",
                      ports=[(23, "Telnet", "Medium")]),
            True, [])
        self.assertEqual(exps[0]["severity"], "High")
        self.assertEqual(exps[0]["playbook"], "internet-exposed-printer")

    def test_reachable_plain_is_medium(self):
        exps = asm.device_exposures(
            self._dev(ports=[(80, "HTTP", "Low")]), True, [])
        self.assertEqual(len(exps), 1)
        self.assertEqual(exps[0]["severity"], "Medium")

    def test_lan_only_risky_is_medium(self):
        exps = asm.device_exposures(
            self._dev(ports=[(445, "SMB file sharing", "Medium")]),
            False, [])
        self.assertEqual(exps[0]["severity"], "Medium")
        self.assertEqual(exps[0]["playbook"], "risky-service")

    def test_lan_only_plain_is_low(self):
        exps = asm.device_exposures(
            self._dev(ports=[(80, "HTTP", "Low")]), False, [])
        self.assertEqual(exps[0]["severity"], "Low")

    def test_ti_hit_is_high(self):
        hits = [{"value": " evil.example.com".strip(), "kind": "domain",
                 "feeds": ["urlhaus-domains"], "detail": "phishing"}]
        exps = asm.device_exposures(self._dev(), False, hits)
        self.assertEqual(exps[0]["severity"], "High")
        self.assertEqual(exps[0]["playbook"], "malicious-contact")

    def test_no_ports_no_exposures(self):
        self.assertEqual(asm.device_exposures(self._dev(), False, []), [])

    def test_ranking_order(self):
        # High sorts before Medium before Low.
        dev = self._dev(ports=[(80, "HTTP", "Low"),
                               (445, "SMB file sharing", "Medium")])
        hits = [{"value": PUB, "kind": "ip", "feeds": ["et-compromised-ips"],
                 "detail": "malicious"}]
        exps = asm.device_exposures(dev, True, hits)
        sevs = [e["severity"] for e in exps]
        self.assertEqual(sevs, sorted(
            sevs, key=lambda s: {"High": 0, "Medium": 1, "Low": 2}[s]))


class TiContextTests(_DbTest):
    def test_listed_ip_hit_surfaced(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        dbm.ti_replace_feed("et-compromised-ips", "ip",
                            [(PUB, "compromised host")])
        dbm.insert_flows([
            (NOW, "192.168.1.20", PUB, 5000, 443, "TCP", 5, 1000,
             "outbound"),
        ])
        hits = asm.ti_hits_for_device("192.168.1.20", now=NOW + 10)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["value"], PUB)
        self.assertEqual(hits[0]["kind"], "ip")

    def test_listed_domain_hit_surfaced(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        dbm.ti_replace_feed("urlhaus-domains", "domain",
                            [("evil.example.com", "malware")])
        dbm.insert_dns_queries([
            (NOW, "192.168.1.20", "evil.example.com", 1),
        ])
        hits = asm.ti_hits_for_device("192.168.1.20", now=NOW + 10)
        self.assertEqual(len(hits), 1)
        self.assertEqual(hits[0]["value"], "evil.example.com")
        self.assertEqual(hits[0]["kind"], "domain")

    def test_clean_device_no_hits(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        dbm.insert_flows([
            (NOW, "192.168.1.20", PUB, 5000, 443, "TCP", 5, 1000,
             "outbound"),
        ])
        self.assertEqual(asm.ti_hits_for_device("192.168.1.20",
                                                now=NOW + 10), [])


class LateralPathTests(_DbTest):
    def _seed_lan(self):
        now = time.time()
        rows = []
        for mac, ip, hostname, ports in [
                ("aa:bb:cc:dd:ee:01", "192.168.1.1", "router", []),
                ("aa:bb:cc:dd:ee:30", "192.168.1.30", "smartplug", []),
                ("aa:bb:cc:dd:ee:40", "192.168.1.40", "mynas",
                 [(445, "SMB file sharing", "Medium")])]:
            rows.append({
                "mac": mac, "ip": ip, "first_seen": now - 1000,
                "last_seen": now, "hostname": hostname,
                "hostname_source": "dhcp" if hostname else "",
                "os_guess": "", "vendor": "",
                "open_ports": [{"port": p, "service": s, "risk": r}
                               for p, s, r in ports],
                "updated_ts": now,
            })
        dbm.refresh_assets(rows)
        dbm.set_meta("dhcp_gateway_ip", "192.168.1.1")

    def _by_ip(self):
        devices, gw = asm._load_devices(NOW)
        return {d["ip"]: d for d in devices if d.get("ip")}, gw

    def test_iot_to_server_path_flagged(self):
        self._seed_lan()
        dbm.insert_flows([
            (NOW, "192.168.1.30", "192.168.1.40", 5000, 445, "TCP",
             20, 2000, "local"),
        ])
        by_ip, gw = self._by_ip()
        paths = asm.lateral_paths(by_ip, gw, now=NOW + 10)
        self.assertEqual(len(paths), 1)
        p = paths[0]
        self.assertEqual(p["from_ip"], "192.168.1.30")
        self.assertEqual(p["to_ip"], "192.168.1.40")
        self.assertEqual(p["playbook"], "iot-lateral-path")
        self.assertIn("smartplug", p["title"])

    def test_gateway_pairs_excluded(self):
        self._seed_lan()
        # Everyone talks to the router -- that is plumbing, not a path.
        dbm.insert_flows([
            (NOW, "192.168.1.30", "192.168.1.1", 5000, 53, "UDP",
             20, 2000, "local"),
        ])
        by_ip, gw = self._by_ip()
        self.assertEqual(asm.lateral_paths(by_ip, gw, now=NOW + 10), [])

    def test_reverse_direction_not_flagged(self):
        self._seed_lan()
        dbm.insert_flows([
            (NOW, "192.168.1.40", "192.168.1.30", 445, 5000, "TCP",
             20, 2000, "local"),
        ])
        by_ip, gw = self._by_ip()
        self.assertEqual(asm.lateral_paths(by_ip, gw, now=NOW + 10), [])

    def test_paths_bounded(self):
        self.assertLessEqual(asm.LATERAL_CAP, 100)


class ReportTests(_DbTest):
    def test_report_shape_and_quiet(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20",
                          hostname="mypc",
                          ports=[(3389, "Remote Desktop", "Medium")])
        dbm.insert_flows([
            (NOW, PUB, "192.168.1.20", 41234, 3389, "TCP", 10, 5000,
             "inbound"),
        ])
        rep = asm.build_report(now=NOW + 10)
        self.assertTrue(rep["ok"])
        self.assertIn("summary_line", rep)
        self.assertIn("worth a look", rep["summary_line"])
        self.assertEqual(rep["counts"]["High"], 1)
        self.assertEqual(len(rep["devices"]), 1)
        dev = rep["devices"][0]
        self.assertTrue(dev["reachable"])
        self.assertEqual(dev["reachability_label"], "Seen from outside")
        self.assertEqual(len(dev["exposures"]), 1)
        # The review fires no alerts -- informational only.
        n_alerts = dbm.query("SELECT COUNT(*) FROM alerts")[0][0]
        self.assertEqual(n_alerts, 0)

    def test_quiet_network_summary(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20")
        rep = asm.build_report(now=NOW + 10)
        self.assertTrue(rep["ok"])
        self.assertIn("All quiet", rep["summary_line"])
        self.assertEqual(rep["exposures"], [])

    def test_no_sign_label_when_unseen(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20",
                          ports=[(80, "HTTP", "Low")])
        rep = asm.build_report(now=NOW + 10)
        dev = rep["devices"][0]
        self.assertFalse(dev["reachable"])
        self.assertEqual(dev["reachability_label"],
                         "No sign of outside access")
        self.assertIn("does not prove", dev["reachability_note"])


class PlaybookSlugTests(unittest.TestCase):
    def test_valid_slugs(self):
        for slug in asm.PLAYBOOK_SLUGS:
            self.assertTrue(asm.valid_playbook_slug(slug), slug)

    def test_invalid_slugs(self):
        for bad in ("", "../etc", "A B", "x" * 65, "a/b", "x;y",
                    "UPPER", "with space", None):
            self.assertFalse(asm.valid_playbook_slug(bad), repr(bad))


@unittest.skipIf(dashm is None, "Flask not installed")
class AttackSurfaceRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_api_attack_surface(self):
        self._seed_device("aa:bb:cc:dd:ee:01", "192.168.1.20",
                          ports=[(80, "HTTP", "Low")])
        r = self._client().get("/api/attack_surface")
        self.assertEqual(r.status_code, 200)
        d = r.get_json()
        self.assertTrue(d["ok"])
        for key in ("summary_line", "counts", "devices", "exposures",
                    "lateral_paths"):
            self.assertIn(key, d)

    def test_playbook_placeholder(self):
        c = self._client()
        # open-admin-interface now has a full guide (batch 9).
        r = c.get("/playbook/open-admin-interface")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"what we found", r.data)
        self.assertNotIn(b"still being written", r.data)
        # Unknown-but-well-formed slug: still graceful, never 404.
        r = c.get("/playbook/some-future-guide")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"still being written", r.data)

    def test_playbook_malformed_404(self):
        c = self._client()
        r = c.get("/playbook/%2e%2e%2fetc")
        self.assertEqual(r.status_code, 404)


if __name__ == "__main__":
    unittest.main()
