"""Retention for host_events + device_hostnames — council review
2026-11-08, robustness R7. Shipped 2026-11-14 (daily build).

Pre-fix retention._TABLES covered only flows, dns_queries,
arp_observations, summaries, outages, score_snapshots and alerts: no
DELETE anywhere targeted host_events or device_hostnames, so both
tables grew without bound for the life of the install — and
db.device_hostname_map() full-scans device_hostnames on every asset
refresh, so the dashboard's asset path got steadily slower on exactly
the long-lived small boxes this targets.

Post-fix the two tables prune under DISTINCT windows with distinct
rationales (council innovation ADAPT, adopted in full):
  * device_hostnames — raw DHCP/mDNS observations, an asset-fold
    cache — shares the 30d observations_days window with the fold's
    other inputs (dns_queries, arp_observations). The curated
    device_names table is not pruned and is untouched.
  * host_events — ingested Windows/firewall security history — gets
    its own key, host_events_days, default 90d.

Run: python -m unittest discover -s tests -v
"""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

from netmon import config as cfgm
from netmon import db as dbm
from netmon import retention as retm


class RetentionR7Tests(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()

    def tearDown(self):
        _restore_db(*self._db)

    def _old_ts(self, days):
        return time.time() - days * 86400

    def _host_event(self, ts):
        return (ts, "eventlog", "4625", "PC1", "bob", "failed logon")

    def _hostname(self, ts, mac="aa:bb:cc:dd:ee:01", name="oldpc"):
        return (ts, mac, "192.168.1.5", name, "dhcp")

    def test_expired_host_events_pruned_recent_kept(self):
        dbm.insert_host_events([self._host_event(self._old_ts(100)),
                                self._host_event(self._old_ts(10))])
        counts = retm.prune_once()
        self.assertEqual(counts.get("host_events"), 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM host_events")[0][0], 1)

    def test_expired_device_hostnames_pruned_recent_kept(self):
        dbm.insert_hostname_observations(
            [self._hostname(self._old_ts(40)),
             self._hostname(self._old_ts(10), name="newpc")])
        counts = retm.prune_once()
        self.assertEqual(counts.get("device_hostnames"), 1)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM device_hostnames")[0][0], 1)

    def test_hostname_fold_survives_prune_with_recent_name(self):
        # The asset fold's latest-per-MAC answer must come from the
        # surviving recent observation once the stale one is pruned.
        mac = "aa:bb:cc:dd:ee:02"
        dbm.insert_hostname_observations(
            [self._hostname(self._old_ts(40), mac=mac, name="stalepc"),
             self._hostname(self._old_ts(5), mac=mac, name="freshpc")])
        retm.prune_once()
        self.assertEqual(dbm.device_hostname_map().get(mac),
                         ("freshpc", "dhcp"))

    def test_host_events_window_is_its_own_key(self):
        # 40d is outside the 30d observations window but inside the
        # 90d host_events window: the row must survive, proving
        # host_events is NOT tied to observations_days.
        dbm.insert_host_events([self._host_event(self._old_ts(40))])
        counts = retm.prune_once()
        self.assertEqual(counts.get("host_events"), 0)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM host_events")[0][0], 1)

    def test_zero_host_events_days_disables_only_host_events(self):
        cfg = {s: dict(keys) for s, keys in cfgm.DEFAULTS.items()}
        cfg["retention"]["host_events_days"] = 0
        dbm.insert_host_events([self._host_event(self._old_ts(100))])
        dbm.insert_flows([(self._old_ts(40), "192.168.1.10",
                           "93.184.216.34", 12345, 443, "tcp", 10, 5000,
                           "outbound")])
        counts = retm.prune_once(cfg=cfg)
        self.assertNotIn("host_events", counts)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM host_events")[0][0], 1)
        self.assertEqual(counts.get("flows"), 1)

    def test_policy_exposes_host_events_default(self):
        pol = retm.policy()
        self.assertEqual(pol.get("host_events_days"), 90)
        self.assertEqual(pol.get("observations_days"), 30)

    def test_host_events_prune_runs_in_bounded_batches(self):
        rows = [self._host_event(self._old_ts(100)) for _ in range(2500)]
        dbm.insert_host_events(rows)
        counts = retm.prune_once(batch=1000)
        self.assertEqual(counts.get("host_events"), 2500)
        self.assertEqual(
            dbm.query("SELECT COUNT(*) FROM host_events")[0][0], 0)


if __name__ == "__main__":
    unittest.main()
