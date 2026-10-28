"""Robustness H2+M1 (2026-10-28): detect.py query amplification + TTL.

- H2a: _device_label re-ran two full DB scans per call, and every
  alert candidate paid for 4 (label + sentence, which re-labels).
  run_all() now shares one lazy device-maps load across the pass;
  outside a pass, labels still load fresh per call.
- H2b: check_arp_spoof shape 1 + shape 2 were N+1 over
  arp_observations. Both shapes now group ONE DISTINCT ip/mac query
  in Python; firing behaviour is unchanged.
- M1: _LOCAL_IPS_CACHE never expired -- a transient load failure
  cached an empty set for the process lifetime. The cache now has a
  300s TTL; failures keep the previous value (or the loopback floor)
  and are retried after the TTL.

Run: python -m unittest discover -s tests
"""
import os
import sys
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from helpers import fresh_db as _fresh_db, restore_db as _restore_db

from netmon import db as dbm
from netmon import detect as detm


class _ScratchDb(unittest.TestCase):
    def setUp(self):
        self._db = _fresh_db()
        # detect.py holds module-level caches; never leak them across
        # tests (the local-IP cache would otherwise name this box).
        self._saved_local = (detm._LOCAL_IPS_CACHE, detm._LOCAL_IPS_CACHE_TS)
        detm._LOCAL_IPS_CACHE = {"127.0.0.1", "::1", "10.9.9.9"}
        detm._LOCAL_IPS_CACHE_TS = time.time()
        self._saved_maps = detm._PASS_MAPS
        detm._PASS_MAPS = None

    def tearDown(self):
        detm._LOCAL_IPS_CACHE, detm._LOCAL_IPS_CACHE_TS = self._saved_local
        detm._PASS_MAPS = self._saved_maps
        _restore_db(*self._db)

    def _alerts(self):
        return dbm.query("SELECT kind, severity FROM alerts ORDER BY id")


# --- H2a: pass-scoped device maps -------------------------------------------


class DeviceMapsScopeTests(_ScratchDb):
    def _named_device(self):
        now = time.time()
        dbm.insert_arp_observations([(now, "192.168.1.50",
                                      "aa:bb:cc:dd:ee:50")])
        dbm.set_device_name("aa:bb:cc:dd:ee:50", "PS5")

    def test_many_labels_in_scope_load_maps_once(self):
        self._named_device()
        with mock.patch.object(dbm, "ip_to_mac_map",
                               wraps=dbm.ip_to_mac_map) as ip2mac, \
             mock.patch.object(dbm, "device_name_map",
                               wraps=dbm.device_name_map) as names:
            with detm._device_maps_scope():
                for _ in range(5):
                    self.assertEqual(detm._device_label("192.168.1.50"),
                                     "PS5 (192.168.1.50)")
                    self.assertEqual(detm._device_sentence("192.168.1.50"),
                                     "PS5 (192.168.1.50)")
                self.assertEqual(detm._device_label("192.168.1.99"),
                                 "device 192.168.1.99")
        self.assertEqual(ip2mac.call_count, 1)
        self.assertEqual(names.call_count, 1)

    def test_labels_outside_scope_load_fresh(self):
        # A rename is visible on the very next label call when no pass
        # scope is active (the pre-fix behaviour direct callers keep).
        self._named_device()
        self.assertEqual(detm._device_label("192.168.1.50"),
                         "PS5 (192.168.1.50)")
        dbm.set_device_name("aa:bb:cc:dd:ee:50", "Xbox")
        self.assertEqual(detm._device_label("192.168.1.50"),
                         "Xbox (192.168.1.50)")

    def test_scope_restores_previous_state_on_error(self):
        with self.assertRaises(RuntimeError):
            with detm._device_maps_scope():
                raise RuntimeError("boom")
        self.assertIsNone(detm._PASS_MAPS)


# --- M1: local-IP cache TTL ---------------------------------------------------


class LocalIpsCacheTests(_ScratchDb):
    def setUp(self):
        super().setUp()
        detm._LOCAL_IPS_CACHE = None
        detm._LOCAL_IPS_CACHE_TS = 0.0

    def test_loads_once_within_ttl_then_reloads(self):
        from netmon import capture as capm
        now = 1_000_000.0
        with mock.patch.object(capm, "get_local_ips",
                               return_value={"127.0.0.1", "10.0.0.5"}) as gl:
            self.assertIn("10.0.0.5", detm._local_ips(now=now))
            self.assertIn("10.0.0.5", detm._local_ips(now=now + 299))
            self.assertEqual(gl.call_count, 1)
            detm._local_ips(now=now + detm._LOCAL_IPS_TTL + 1)
            self.assertEqual(gl.call_count, 2)

    def test_failure_without_prior_value_floors_and_recovers(self):
        from netmon import capture as capm
        now = 2_000_000.0
        with mock.patch.object(capm, "get_local_ips",
                               side_effect=OSError("route down")):
            got = detm._local_ips(now=now)
        # Loopback floor, not an empty set -- and not permanent: after
        # the TTL a working lookup replaces it (the M1 bug cached the
        # failure for the process lifetime).
        self.assertEqual(got, {"127.0.0.1", "::1"})
        with mock.patch.object(capm, "get_local_ips",
                               return_value={"127.0.0.1", "10.0.0.7"}) as gl:
            got = detm._local_ips(now=now + detm._LOCAL_IPS_TTL + 1)
            self.assertEqual(gl.call_count, 1)
        self.assertIn("10.0.0.7", got)

    def test_failure_with_prior_value_keeps_it(self):
        from netmon import capture as capm
        now = 3_000_000.0
        detm._LOCAL_IPS_CACHE = {"127.0.0.1", "10.0.0.9"}
        detm._LOCAL_IPS_CACHE_TS = now - detm._LOCAL_IPS_TTL - 1
        with mock.patch.object(capm, "get_local_ips",
                               side_effect=OSError("route down")):
            self.assertEqual(detm._local_ips(now=now), {"127.0.0.1", "10.0.0.9"})

    def test_label_recognises_sensor_box_ip(self):
        detm._LOCAL_IPS_CACHE = {"127.0.0.1", "::1", "10.9.9.9"}
        detm._LOCAL_IPS_CACHE_TS = time.time()
        self.assertEqual(detm._device_label("10.9.9.9"),
                         "this computer (10.9.9.9)")


# --- H2b: arp_spoof single query ----------------------------------------------


class ArpSpoofSingleQueryTests(_ScratchDb):
    def _arp_query_count(self, fn):
        real_query = dbm.query
        hits = []

        def counting(sql, params=()):
            if "arp_observations" in sql:
                hits.append(sql)
            return real_query(sql, params)

        with mock.patch.object(dbm, "query", side_effect=counting):
            result = fn()
        return result, hits

    def test_both_shapes_one_arp_query(self):
        now = time.time()
        mac = "de:ad:be:ef:00:01"
        dbm.insert_arp_observations([
            (now - 300, "192.168.1.10", mac),
            (now - 240, "192.168.1.11", mac),
            (now - 180, "192.168.1.12", mac),  # shape 1: 3 IPs, one MAC
        ])
        dbm.note_first_seen("ip_mac", "192.168.1.20", "aa:bb:cc:00:00:01")
        dbm.insert_arp_observations(
            [(now - 300, "192.168.1.20", "aa:bb:cc:00:00:02")])  # shape 2
        with dbm.notifications_paused():
            fired, hits = self._arp_query_count(
                lambda: detm.check_arp_spoof(now=now))
        self.assertEqual(len(hits), 1)
        self.assertEqual(sorted(fired),
                         [("ip", "192.168.1.20"), ("mac", mac)])
        self.assertEqual(self._alerts().count(("arp_spoof", "High")), 2)

    def test_quiet_cases_stay_quiet(self):
        now = time.time()
        mac = "de:ad:be:ef:00:02"
        dbm.insert_arp_observations([
            (now - 300, "192.168.1.10", mac),
            (now - 240, "192.168.1.11", mac),  # 2 IPs < threshold
        ])
        dbm.note_first_seen("ip_mac", "192.168.1.20", "aa:bb:cc:00:00:01")
        dbm.insert_arp_observations(
            [(now - 300, "192.168.1.20", "aa:bb:cc:00:00:01")])  # stable
        with dbm.notifications_paused():
            fired, hits = self._arp_query_count(
                lambda: detm.check_arp_spoof(now=now))
        self.assertEqual(fired, [])
        self.assertEqual(self._alerts(), [])
        self.assertEqual(len(hits), 1)


if __name__ == "__main__":
    unittest.main()
