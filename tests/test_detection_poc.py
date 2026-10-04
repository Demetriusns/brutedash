"""PoC firing tests for every brutedash detection rule (repo-learning item 11,
the Strix "validate with PoC" pattern -- his eval discipline).

Every rule gets a test that PROVES it fires: synthetic fixtures
(packets/flows/events) are fed through the real rule on a scratch DB and
the alert is asserted with the right kind and severity -- plus a negative
case where the rule must NOT fire. All synthetic, all scratch; nothing
here can create noise in a real database (notifications_paused).

Rules already proven elsewhere keep their existing homes:
  host_event / usb_insert / defender_detection / host_compromise /
  self_drift / vuln_finding  -> tests/test_knownetwork.py
  phishing_domain / malicious_ip -> tests/test_threatintel.py
  amass_new_asset -> tests/test_amass.py
  nuclei_finding  -> tests/test_nuclei.py
  cve_match       -> tests/test_swaudit.py
This file fills the gaps: every check_* in netmon/detect.py plus the live
port-scan tracker in netmon/capture.py.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import detect as detm


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


class _ScratchDb(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)

    def _alerts(self):
        return dbm.query("SELECT kind, severity FROM alerts ORDER BY id")

    def _kinds(self):
        return [k for k, _ in self._alerts()]


# --- live port scan (netmon/capture.py ScanTracker) --------------------------


class PortScanPocTests(_ScratchDb):
    def test_scan_fires_high(self):
        from netmon import capture as capm
        now = time.time()
        tracker = capm.ScanTracker()
        with dbm.notifications_paused():
            for i in range(20):  # 20 distinct ports, SYN, inside 120s
                tracker.observe("203.0.113.9", 1000 + i, now - 60 + i,
                                is_syn=True)
        self.assertIn(("port_scan", "High"), self._alerts())

    def test_below_threshold_stays_quiet(self):
        from netmon import capture as capm
        now = time.time()
        tracker = capm.ScanTracker()
        with dbm.notifications_paused():
            for i in range(10):  # 10 ports < 20 threshold
                tracker.observe("203.0.113.9", 1000 + i, now - 60 + i,
                                is_syn=True)
        self.assertEqual(self._alerts(), [])

    def test_non_syn_ignored(self):
        from netmon import capture as capm
        now = time.time()
        tracker = capm.ScanTracker()
        with dbm.notifications_paused():
            for i in range(30):  # plenty of ports, but no SYNs
                tracker.observe("203.0.113.9", 1000 + i, now - 60 + i,
                                is_syn=False)
        self.assertEqual(self._alerts(), [])

    def test_cooldown_suppresses_immediate_refire(self):
        from netmon import capture as capm
        now = time.time()
        tracker = capm.ScanTracker()
        with dbm.notifications_paused():
            for i in range(20):
                tracker.observe("203.0.113.9", 1000 + i, now - 60 + i,
                                is_syn=True)
            # a second burst right away must NOT re-alert (1h cooldown)
            for i in range(20):
                tracker.observe("203.0.113.9", 2000 + i, now + i,
                                is_syn=True)
        rows = self._alerts()
        self.assertEqual(rows, [("port_scan", "High")])


# --- traffic spike -----------------------------------------------------------


class TrafficSpikePocTests(_ScratchDb):
    def _flow(self, ts, nbytes):
        return (ts, "192.168.1.5", "203.0.113.9", 51234, 443, "TCP",
                100, nbytes, "outbound")

    def test_spike_fires_medium(self):
        now = time.time()
        # baseline: 120 MB spread over the previous hour
        dbm.insert_flows(
            [self._flow(now - 300 - k * 300, 10_000_000) for k in range(1, 13)])
        # recent: 700 MB in the last 5 minutes (>= 5x the baseline)
        dbm.insert_flows(
            [self._flow(now - 40 - j * 30, 100_000_000) for j in range(7)])
        with dbm.notifications_paused():
            detail = detm.check_traffic_spike(now=now)
        self.assertIsNotNone(detail)
        self.assertIn(("traffic_spike", "Medium"), self._alerts())

    def test_small_surge_stays_quiet(self):
        now = time.time()
        dbm.insert_flows(
            [self._flow(now - 300 - k * 300, 10_000_000) for k in range(1, 13)])
        # 300 MB recent vs 600 MB needed (5x of 120 MB) -> no alert
        dbm.insert_flows(
            [self._flow(now - 40 - j * 60, 60_000_000) for j in range(5)])
        with dbm.notifications_paused():
            self.assertIsNone(detm.check_traffic_spike(now=now))
        self.assertEqual(self._alerts(), [])


# --- unusual port ------------------------------------------------------------


class UnusualPortPocTests(_ScratchDb):
    def _flow(self, now, port, dst="203.0.113.9"):
        return (now - 300, "192.168.1.5", dst, 51234, port, "TCP",
                10, 5_000_000, "outbound")

    def test_odd_port_fires(self):
        now = time.time()
        dbm.insert_flows([self._flow(now, 4444)])
        with dbm.notifications_paused():
            fired = detm.check_unusual_ports(now=now)
        self.assertEqual(fired, ["192.168.1.5:203.0.113.9:4444"])
        self.assertIn(("unusual_port", "Medium"), self._alerts())

    def test_common_port_stays_quiet(self):
        now = time.time()
        dbm.insert_flows([self._flow(now, 443), self._flow(now, 53)])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_unusual_ports(now=now), [])
        self.assertEqual(self._alerts(), [])

    def test_lan_netbios_chatter_stays_quiet(self):
        now = time.time()
        dbm.insert_flows([self._flow(now, 139, dst="192.168.1.10")])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_unusual_ports(now=now), [])
        self.assertEqual(self._alerts(), [])


# --- beaconing ---------------------------------------------------------------


class BeaconingPocTests(_ScratchDb):
    def _flow(self, ts):
        return (ts, "192.168.1.5", "203.0.113.9", 51234, 443, "TCP",
                5, 100_000, "outbound")

    def test_clockwork_fires(self):
        now = time.time()
        # 10 distinct 5-minute buckets in the last hour (>= 8 needed)
        dbm.insert_flows([self._flow(now - 150 - i * 300) for i in range(10)])
        with dbm.notifications_paused():
            fired = detm.check_beaconing(now=now)
        self.assertEqual(fired, ["192.168.1.5:203.0.113.9"])
        self.assertIn(("beaconing", "Medium"), self._alerts())

    def test_sporadic_contact_stays_quiet(self):
        now = time.time()
        dbm.insert_flows([self._flow(now - 150 - i * 300) for i in range(5)])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_beaconing(now=now), [])
        self.assertEqual(self._alerts(), [])


# --- first contact + volume anomaly ------------------------------------------


class NewExternalIpPocTests(_ScratchDb):
    def test_first_contact_fires(self):
        now = time.time()
        dbm.insert_flows(
            [(now - 600, "192.168.1.5", "93.184.216.34", 51234, 443,
              "TCP", 100, 2_000_000, "outbound")])  # 2 MB > 1 MB floor
        with dbm.notifications_paused():
            fired = detm.check_baseline_anomalies(now=now)
        self.assertEqual(fired, [("new_external_ip",
                                  "192.168.1.5|93.184.216.34")])
        self.assertIn(("new_external_ip", "Low"), self._alerts())

    def test_small_first_contact_stays_quiet(self):
        now = time.time()
        dbm.insert_flows(
            [(now - 600, "192.168.1.5", "93.184.216.34", 51234, 443,
              "TCP", 10, 500_000, "outbound")])  # 0.5 MB < 1 MB floor
        with dbm.notifications_paused():
            self.assertEqual(detm.check_baseline_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])

    def test_known_address_stays_quiet(self):
        now = time.time()
        dbm.note_first_seen("ext_ip", "192.168.1.5|93.184.216.34",
                            now - 30 * 86400)
        dbm.insert_flows(
            [(now - 600, "192.168.1.5", "93.184.216.34", 51234, 443,
              "TCP", 100, 2_000_000, "outbound")])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_baseline_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])


class VolumeAnomalyPocTests(_ScratchDb):
    SRC, DST = "192.168.1.5", "93.184.216.35"

    def _seed_known(self, now):
        dbm.note_first_seen("ext_ip", f"{self.SRC}|{self.DST}",
                            now - 30 * 86400)

    def _baseline(self, now):
        # 5 MB/day for 7 days -> ~0.2 MB/hour average
        dbm.insert_flows(
            [(now - d * 86400 - 3600, self.SRC, self.DST, 51234, 443,
              "TCP", 500, 5_000_000, "outbound") for d in range(1, 8)])

    def test_surge_fires(self):
        now = time.time()
        self._seed_known(now)
        self._baseline(now)
        dbm.insert_flows(
            [(now - 1800, self.SRC, self.DST, 51234, 443,
              "TCP", 6000, 60_000_000, "outbound")])  # 60 MB > 50 MB floor
        with dbm.notifications_paused():
            fired = detm.check_baseline_anomalies(now=now)
        self.assertEqual(fired, [("volume_anomaly",
                                  f"{self.SRC}|{self.DST}")])
        self.assertIn(("volume_anomaly", "Medium"), self._alerts())

    def test_below_absolute_floor_stays_quiet(self):
        now = time.time()
        self._seed_known(now)
        self._baseline(now)
        dbm.insert_flows(
            [(now - 1800, self.SRC, self.DST, 51234, 443,
              "TCP", 3000, 30_000_000, "outbound")])  # 30 MB < 50 MB floor
        with dbm.notifications_paused():
            self.assertEqual(detm.check_baseline_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])


# --- DNS anomalies -----------------------------------------------------------


class DnsLookupBurstPocTests(_ScratchDb):
    SRC, NAME = "192.168.1.5", "hammer.example.com"

    def _lookups(self, now, n):
        return [(now - 60 - i, self.SRC, self.NAME, 1) for i in range(n)]

    def test_burst_fires(self):
        now = time.time()
        # silence the new_busy_domain sibling so this test proves the
        # burst rule and only the burst rule
        dbm.note_first_seen("domain", f"{self.SRC}|{self.NAME}",
                            now - 86400)
        dbm.insert_dns_queries(self._lookups(now, 201))  # > 200
        with dbm.notifications_paused():
            fired = detm.check_dns_anomalies(now=now)
        self.assertEqual(fired, [("dns_lookup_burst",
                                  f"{self.SRC}|{self.NAME}")])
        self.assertIn(("dns_lookup_burst", "Medium"), self._alerts())

    def test_normal_lookup_rate_stays_quiet(self):
        now = time.time()
        dbm.note_first_seen("domain", f"{self.SRC}|{self.NAME}",
                            now - 86400)
        dbm.insert_dns_queries(self._lookups(now, 100))
        with dbm.notifications_paused():
            self.assertEqual(detm.check_dns_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])


class DnsTunnelingPocTests(_ScratchDb):
    def _lookups(self, now, n):
        return [(now - 60 - i, "192.168.1.5",
                 f"zz{i}.tunnel.example.com", 1) for i in range(n)]

    def test_tunnel_shape_fires(self):
        now = time.time()
        dbm.insert_dns_queries(self._lookups(now, 26))  # > 25 subdomains
        with dbm.notifications_paused():
            fired = detm.check_dns_anomalies(now=now)
        # parent domain = last two labels per _parent_domain
        self.assertEqual(fired, [("dns_tunneling",
                                  "192.168.1.5|example.com")])
        self.assertIn(("dns_tunneling", "High"), self._alerts())

    def test_few_subdomains_stay_quiet(self):
        now = time.time()
        dbm.insert_dns_queries(self._lookups(now, 10))
        with dbm.notifications_paused():
            self.assertEqual(detm.check_dns_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])


class NewBusyDomainPocTests(_ScratchDb):
    SRC, NAME = "192.168.1.5", "newapp.example.com"

    def _lookups(self, now, n):
        return [(now - 60 - i, self.SRC, self.NAME, 1) for i in range(n)]

    def test_new_busy_domain_fires(self):
        now = time.time()
        dbm.insert_dns_queries(self._lookups(now, 51))  # > 50, never seen
        with dbm.notifications_paused():
            fired = detm.check_dns_anomalies(now=now)
        self.assertEqual(fired, [("new_busy_domain",
                                  f"{self.SRC}|{self.NAME}")])
        self.assertIn(("new_busy_domain", "Low"), self._alerts())

    def test_known_domain_stays_quiet(self):
        now = time.time()
        dbm.note_first_seen("domain", f"{self.SRC}|{self.NAME}",
                            now - 86400)
        dbm.insert_dns_queries(self._lookups(now, 51))
        with dbm.notifications_paused():
            self.assertEqual(detm.check_dns_anomalies(now=now), [])
        self.assertEqual(self._alerts(), [])


# --- new device + ARP spoof --------------------------------------------------


class NewDevicePocTests(_ScratchDb):
    MAC = "aa:bb:cc:dd:ee:ff"

    def test_unknown_mac_fires(self):
        now = time.time()
        dbm.insert_arp_observations([(now - 300, "192.168.1.50", self.MAC)])
        with dbm.notifications_paused():
            fired = detm.check_new_devices(now=now)
        self.assertEqual(fired, [self.MAC])
        self.assertIn(("new_device", "Low"), self._alerts())

    def test_known_mac_stays_quiet(self):
        now = time.time()
        dbm.note_first_seen("mac", self.MAC, now - 30 * 86400)
        dbm.insert_arp_observations([(now - 300, "192.168.1.50", self.MAC)])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_new_devices(now=now), [])
        self.assertEqual(self._alerts(), [])


class ArpSpoofPocTests(_ScratchDb):
    def test_one_mac_many_ips_fires(self):
        now = time.time()
        mac = "de:ad:be:ef:00:01"
        dbm.insert_arp_observations([
            (now - 300, "192.168.1.10", mac),
            (now - 240, "192.168.1.11", mac),
            (now - 180, "192.168.1.12", mac),  # 3 IPs from one MAC
        ])
        with dbm.notifications_paused():
            fired = detm.check_arp_spoof(now=now)
        self.assertEqual(fired, [("mac", mac)])
        self.assertIn(("arp_spoof", "High"), self._alerts())

    def test_mac_two_ips_stays_quiet(self):
        now = time.time()
        mac = "de:ad:be:ef:00:02"
        dbm.insert_arp_observations([
            (now - 300, "192.168.1.10", mac),
            (now - 240, "192.168.1.11", mac),  # 2 IPs < 3 threshold
        ])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_arp_spoof(now=now), [])
        self.assertEqual(self._alerts(), [])

    def test_ip_changing_mac_fires(self):
        now = time.time()
        ip = "192.168.1.20"
        dbm.note_first_seen("ip_mac", ip, "aa:bb:cc:00:00:01")
        dbm.insert_arp_observations(
            [(now - 300, ip, "aa:bb:cc:00:00:02")])  # different MAC now
        with dbm.notifications_paused():
            fired = detm.check_arp_spoof(now=now)
        self.assertEqual(fired, [("ip", ip)])
        self.assertIn(("arp_spoof", "High"), self._alerts())

    def test_stable_ip_mac_stays_quiet(self):
        now = time.time()
        ip = "192.168.1.20"
        dbm.note_first_seen("ip_mac", ip, "aa:bb:cc:00:00:01")
        dbm.insert_arp_observations(
            [(now - 300, ip, "aa:bb:cc:00:00:01")])  # same MAC as recorded
        with dbm.notifications_paused():
            self.assertEqual(detm.check_arp_spoof(now=now), [])
        self.assertEqual(self._alerts(), [])


# --- behavior deviation ------------------------------------------------------


class BehaviorDeviationPocTests(_ScratchDb):
    MAC, IP = "aa:bb:cc:dd:ee:02", "192.168.1.60"

    def _hour_ts(self, now, days_ago, minute=30):
        """Timestamp at `minute` past the current local hour, days_ago back.

        DST-safe: the wall-clock hour is resolved per target day (mktime
        with isdst=-1), so a DST transition inside the window cannot push
        the fixture into the wrong profile cell."""
        lt = time.localtime(now - days_ago * 86400)
        return time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, lt.tm_hour,
                            minute, 0, -1, -1, -1))

    def _seed_device(self, now):
        # seen 30 days ago (well past the 24h probation), active now
        dbm.insert_arp_observations([(now - 30 * 86400, self.IP, self.MAC),
                                     (now - 3600, self.IP, self.MAC)])
        # baseline: ~100 MB at this hour, 5 days of history
        dbm.insert_flows(
            [(self._hour_ts(now, d), self.IP, "203.0.113.40", 51234, 443,
              "TCP", 1000, 100_000_000, "outbound") for d in range(1, 6)])
        dbm.build_device_profiles(now)

    def test_deviation_fires(self):
        now = time.time()
        self._seed_device(now)
        # 450 MB last hour: >= 4x the 100 MB baseline AND >= 250 MB floor
        dbm.insert_flows(
            [(now - 1800, self.IP, "203.0.113.40", 51234, 443,
              "TCP", 4000, 450_000_000, "outbound")])
        with dbm.notifications_paused():
            fired = detm.check_behavior_deviation(now=now)
        self.assertEqual(fired, [("behavior_deviation", self.MAC)])
        self.assertIn(("behavior_deviation", "Medium"), self._alerts())

    def test_below_floor_stays_quiet(self):
        now = time.time()
        self._seed_device(now)
        # 200 MB last hour: below the 250 MB absolute floor
        dbm.insert_flows(
            [(now - 1800, self.IP, "203.0.113.40", 51234, 443,
              "TCP", 2000, 200_000_000, "outbound")])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_behavior_deviation(now=now), [])
        self.assertEqual(self._alerts(), [])

    def test_new_device_on_probation_stays_quiet(self):
        now = time.time()
        # same spike, but the device first appeared an hour ago
        dbm.insert_arp_observations([(now - 3600, self.IP, self.MAC)])
        dbm.insert_flows(
            [(self._hour_ts(now, d), self.IP, "203.0.113.40", 51234, 443,
              "TCP", 1000, 100_000_000, "outbound") for d in range(1, 6)])
        dbm.build_device_profiles(now)
        dbm.insert_flows(
            [(now - 1800, self.IP, "203.0.113.40", 51234, 443,
              "TCP", 4000, 450_000_000, "outbound")])
        with dbm.notifications_paused():
            self.assertEqual(detm.check_behavior_deviation(now=now), [])
        self.assertEqual(self._alerts(), [])


if __name__ == "__main__":
    unittest.main()
