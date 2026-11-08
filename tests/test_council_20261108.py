"""Council review 2026-11-08 -- shipped batch regression tests.

Batch theme: a transient failure must not become a permanent outage.
Each finding was reproduced by the robustness seat at HEAD 75ffce6
(council-reviews/repro-2026-11-08-robust.py) and verified in source
by the head before fixing:

  R1 (robustness, High) capture.run_live's finally set the CALLER's
     shared stop_event when sniff() raised -- one Npcap/driver hiccup
     killed the monitor loop too and made the capture watchdog's
     restart a no-op. The flusher now has its own private stop event;
     the shared event is never set by run_live.
  R4 (robustness, Medium) canary.start() trusted the running flag: a
     dead listener thread was never restarted. start() now rebinds
     when the recorded thread is dead, and _serve clears the flag on
     exit when it is still the recorded listener.
  R5 (robustness, Medium) selfcheck.check_listening_ports learned an
     EMPTY baseline on Windows when netstat failed (empty set = the
     _run failure shape), so the next good run flagged every real
     port as drift. An empty Windows enumeration is now an error,
     like check_services.
  R3 (robustness, Medium) nuclei/amass maybe_weekly_* stamped the
     last-run meta at LAUNCH, so one failed scan ate the weekly slot.
     The stamp now happens on success only (nuclei already stamped in
     run_full_nuclei_scan; amass stamps in run_domain_scan), matching
     the built-in scan.
  R8 (robustness, Low) threatintel.reverse_dns cached a failed or
     timed-out lookup as a definitive empty answer for 7 days. Failed
     lookups now carry a "neg" marker with a 10-minute TTL; only a
     completed lookup gets the 7-day cache.

Run: python -m unittest discover -s tests -v
"""
import json
import os
import sys
import threading
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import amass as amassm
from netmon import canary as canarym
from netmon import capture as capm
from netmon import db as dbm
from netmon import nuclei as nucleim
from netmon import selfcheck as selfm
from netmon import threatintel as tim

from helpers import ScratchDbTestCase


# --- R1: run_live must never set the caller's shared stop event ---------


@unittest.skipUnless(capm.HAVE_SCAPY, "run_live needs scapy")
class RunLiveSharedEventTests(ScratchDbTestCase):
    def test_sniff_failure_leaves_shared_event_clear(self):
        stop = threading.Event()
        with mock.patch.object(
                capm, "sniff",
                side_effect=RuntimeError("Npcap hiccup")):
            with self.assertRaises(RuntimeError):
                capm.run_live(interface="fake0", stop_event=stop)
        self.assertFalse(stop.is_set())

    def test_restart_after_failure_actually_sniffs_again(self):
        stop = threading.Event()
        calls = []

        def _flaky(**kwargs):
            calls.append(kwargs)
            if len(calls) == 1:
                raise RuntimeError("Npcap hiccup")
            stop.set()

        with mock.patch.object(capm, "sniff", side_effect=_flaky):
            with self.assertRaises(RuntimeError):
                capm.run_live(interface="fake0", stop_event=stop)
            stop.clear()
            agg = capm.run_live(interface="fake0", stop_event=stop)
        self.assertIsNotNone(agg)
        self.assertEqual(len(calls), 2)  # the restart really captured

    def test_clean_shutdown_still_returns_aggregator(self):
        stop = threading.Event()

        def _once(**kwargs):
            stop.set()

        with mock.patch.object(capm, "sniff", side_effect=_once):
            agg = capm.run_live(interface="fake0", stop_event=stop)
        self.assertIsNotNone(agg)
        self.assertTrue(stop.is_set())  # set by the caller, not by us


# --- R4: canary restarts a dead listener ---------------------------------


class CanaryRestartTests(unittest.TestCase):
    def tearDown(self):
        with canarym._lock:
            thread = canarym._state["thread"]
        canarym.stop()
        if thread is not None:
            # A listener blocked in accept() holds its port until the
            # syscall returns (<=1s timeout); join so the next test's
            # bind doesn't race the release.
            thread.join(timeout=2)
        with canarym._lock:
            canarym._state.update(thread=None, stop=None, sock=None,
                                  running=False)

    def _seed_dead_listener(self):
        dead = threading.Thread(target=lambda: None)
        dead.start()
        dead.join()
        with canarym._lock:
            canarym._state.update(thread=dead, stop=threading.Event(),
                                  sock=None, port=canarym.DEFAULT_PORT,
                                  bind="127.0.0.1", running=True)

    def test_start_rebinds_when_thread_dead(self):
        self._seed_dead_listener()
        self.assertFalse(canarym.is_running())
        self.assertTrue(canarym.start(bind_ip="127.0.0.1"))
        self.assertTrue(canarym.is_running())

    def test_start_is_idempotent_when_alive(self):
        self.assertTrue(canarym.start(bind_ip="127.0.0.1"))
        with canarym._lock:
            thread = canarym._state["thread"]
        self.assertTrue(canarym.start(bind_ip="127.0.0.1"))
        with canarym._lock:
            self.assertIs(canarym._state["thread"], thread)

    def test_serve_exit_clears_running_flag(self):
        class _DeadSock:
            """A listener whose socket died underneath it (the
            sleep/resume / driver-reset shape): accept() raises."""

            def settimeout(self, _t):
                pass

            def accept(self):
                raise OSError("socket closed")

        stop = threading.Event()
        with canarym._lock:
            canarym._state.update(thread=None, stop=stop, sock=None,
                                  running=True)
        canarym._serve(_DeadSock(), stop)  # must not raise
        with canarym._lock:
            self.assertFalse(canarym._state["running"])


# --- R5: empty Windows port enumeration is an error, not a baseline -----


class SelfcheckEmptyBaselineTests(ScratchDbTestCase):
    def test_failed_netstat_learns_no_baseline(self):
        with mock.patch.object(selfm, "_is_windows", return_value=True), \
                mock.patch.object(selfm, "_run", return_value=""):
            status, detail, current = selfm.check_listening_ports()
        self.assertEqual(status, "error")
        self.assertEqual(current, set())
        self.assertIsNone(dbm.selfcheck_baseline_get("listening_ports"))

    def test_recovery_after_failed_netstat_learns_real_baseline(self):
        with mock.patch.object(selfm, "_is_windows", return_value=True), \
                mock.patch.object(selfm, "_run", return_value=""):
            selfm.check_listening_ports()
        ports = {("TCP", 445), ("TCP", 5001)}
        with mock.patch.object(selfm, "_is_windows", return_value=True), \
                mock.patch.object(selfm, "_windows_listening_ports",
                                  return_value=set(ports)):
            status, detail, _ = selfm.check_listening_ports()
        self.assertEqual(status, "ok")
        self.assertIn("baseline learned: 2", detail)


# --- R3: weekly stamps on success only ------------------------------------


class WeeklyStampTests(ScratchDbTestCase):
    def _prime_nuclei(self):
        return mock.patch.multiple(
            nucleim, find_binary=lambda: "/bin/true",
            nuclei_enabled=lambda: True,
            nuclei_targets=lambda: ["192.168.1.50"],
            _nuclei_cfg=lambda k, d: True,
            start_nuclei_async=lambda: None)

    def _prime_amass(self):
        return mock.patch.multiple(
            amassm, find_binary=lambda: "/bin/true",
            amass_enabled=lambda: True,
            configured_domains=lambda: ["example.com"],
            _amass_cfg=lambda k, d: True,
            start_amass_async=lambda: [])

    def test_nuclei_launch_does_not_stamp_and_retries(self):
        with self._prime_nuclei():
            self.assertTrue(nucleim.maybe_weekly_nuclei())
            self.assertIsNone(dbm.get_meta("nuclei_scan_last_ts"))
            # A failed attempt must not eat the week: due again.
            self.assertTrue(nucleim.maybe_weekly_nuclei())

    def test_amass_launch_does_not_stamp_and_retries(self):
        with self._prime_amass():
            self.assertTrue(amassm.maybe_weekly_amass())
            self.assertIsNone(dbm.get_meta("amass_last_ts"))
            self.assertTrue(amassm.maybe_weekly_amass())

    def test_nuclei_recent_success_still_skips(self):
        dbm.set_meta("nuclei_scan_last_ts", str(time.time()))
        with self._prime_nuclei():
            self.assertIsNone(nucleim.maybe_weekly_nuclei())

    def test_amass_recent_success_still_skips(self):
        dbm.set_meta("amass_last_ts", str(time.time()))
        with self._prime_amass():
            self.assertIsNone(amassm.maybe_weekly_amass())


# --- R8: failed reverse-DNS lookups get the short negative TTL -----------


class ReverseDnsNegativeCacheTests(ScratchDbTestCase):
    IP = "203.0.113.7"

    def _cached(self):
        raw = dbm.get_meta(f"ti_rdns_{self.IP}")
        return json.loads(raw) if raw else None

    def test_failed_lookup_is_marked_negative(self):
        import socket as _socket
        with mock.patch.object(_socket, "gethostbyaddr",
                               side_effect=OSError("resolver down")):
            self.assertEqual(tim.reverse_dns(self.IP), "")
        cached = self._cached()
        self.assertIsNotNone(cached)
        self.assertTrue(cached.get("neg"))

    def test_negative_entry_expires_after_short_ttl(self):
        import socket as _socket
        with mock.patch.object(_socket, "gethostbyaddr",
                               side_effect=OSError("resolver down")):
            tim.reverse_dns(self.IP)
        cached = self._cached()
        cached["ts"] = time.time() - tim._RDNS_NEG_CACHE_S - 1
        dbm.set_meta(f"ti_rdns_{self.IP}", json.dumps(cached))
        with mock.patch.object(
                _socket, "gethostbyaddr",
                return_value=("recovered.example.com", [], [self.IP])):
            self.assertEqual(tim.reverse_dns(self.IP),
                             "recovered.example.com")
        # The recovered answer is a definitive cache entry now.
        cached = self._cached()
        self.assertFalse(cached.get("neg"))
        self.assertEqual(cached.get("name"), "recovered.example.com")

    def test_successful_lookup_uses_long_cache(self):
        import socket as _socket
        with mock.patch.object(
                _socket, "gethostbyaddr",
                return_value=("host.example.com", [], [self.IP])) as gh:
            self.assertEqual(tim.reverse_dns(self.IP),
                             "host.example.com")
            self.assertEqual(tim.reverse_dns(self.IP),
                             "host.example.com")
        self.assertEqual(gh.call_count, 1)  # second call was cached
        self.assertFalse(self._cached().get("neg"))


if __name__ == "__main__":
    unittest.main()
