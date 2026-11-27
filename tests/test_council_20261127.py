"""Council review 2026-11-27 -- robustness L1-L5 (the five lows from the
2026-11-22 weekly review).

L1: syslog timestamps range-validated (isolated forward spike nulled,
years re-placed over survivors).
L2: same-ts ceiling escape bounded (truncate to a group boundary;
single giant group processed in hard-cap chunks, never wedged).
L3: scanner JSONL readers no longer materialise one whole line
(chunked readline under the total-byte cap).
L4: llm_egress correlation requires temporal overlap (6h), not just a
shared 24h window.
L5: the demo scan's three passes share one _collect_events read.

Run: python -m unittest discover -s tests -v
"""
import gzip
import json
import os
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import detector
from detector import (_collect_events, detect_brute_force,
                      detect_cadence, detect_key_events)
from netmon import db as dbm
from netmon import detect as detm
from netmon import ingest as ingm

from helpers import ScratchDbTestCase

try:
    import app as appm
except ImportError:  # Flask not installed: skip app-only tests
    appm = None


def _fail_line(ip, dt_str, user="root"):
    return (f"{dt_str} host sshd[1]: Failed password for {user} from {ip}"
            f" port 22 ssh2")


def _syslog_year(ts):
    return time.gmtime(ts).tm_year if ts is not None else None


# --- L1: syslog timestamp range validation -----------------------------------

class L1SyslogSpikeTests(unittest.TestCase):
    def _events(self, lines):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "auth.log")
            with open(path, "w") as f:
                f.write("\n".join(lines) + "\n")
            return _collect_events(path)

    def test_stray_dec_line_gets_no_ts_and_does_not_shift_primary(self):
        # A "Dec 31" line in the middle of a January stream: the spike
        # is nulled AND the January lines after it keep year 2000
        # (the reader's streaming wrap used to shift them to 2001 on
        # the stray line alone).
        lines = [
            _fail_line("203.0.113.1", "Jan  5 10:00:01"),
            _fail_line("203.0.113.1", "Jan  6 10:00:01"),
            _fail_line("203.0.113.2", "Dec 31 10:00:01"),
            _fail_line("203.0.113.1", "Jan  7 10:00:01"),
            _fail_line("203.0.113.1", "Jan  8 10:00:01"),
        ]
        events = self._events(lines)
        by_ip = {e["ip"]: e for e in events}
        self.assertIsNone(by_ip["203.0.113.2"]["ts"])
        for e in events:
            if e["ip"] == "203.0.113.1":
                self.assertEqual(_syslog_year(e["ts"]), 2000)

    def test_sparse_log_months_apart_is_kept(self):
        # A legitimate months-long gap is monotonic, not a spike: the
        # later event is ahead of its predecessor but behind its
        # successor, so nothing is dropped.
        lines = [
            _fail_line("203.0.113.1", "Feb  1 10:00:01"),
            _fail_line("203.0.113.1", "Sep 15 10:00:01"),
            _fail_line("203.0.113.1", "Sep 16 10:00:01"),
        ]
        events = self._events(lines)
        self.assertEqual(len(events), 3)
        self.assertTrue(all(e["ts"] is not None for e in events))
        self.assertEqual([_syslog_year(e["ts"]) for e in events],
                         [2000, 2000, 2000])

    def test_legit_dec_to_jan_crossing_kept(self):
        lines = [
            _fail_line("203.0.113.1", "Dec 30 10:00:01"),
            _fail_line("203.0.113.1", "Dec 31 10:00:01"),
            _fail_line("203.0.113.1", "Jan  5 10:00:01"),
            _fail_line("203.0.113.1", "Jan  6 10:00:01"),
        ]
        events = self._events(lines)
        self.assertEqual([_syslog_year(e["ts"]) for e in events],
                         [2000, 2000, 2001, 2001])

    def test_sparse_year_crossing_not_mistaken_for_spike(self):
        # Jun -> Dec -> Jan is a real year crossing over a sparse log:
        # the Dec line is followed by a January line ~7 months after
        # June, not days after it, so the neighbour clause saves it.
        lines = [
            _fail_line("203.0.113.1", "Jun  1 10:00:01"),
            _fail_line("203.0.113.1", "Dec 31 10:00:01"),
            _fail_line("203.0.113.1", "Jan  5 10:00:01"),
        ]
        events = self._events(lines)
        self.assertTrue(all(e["ts"] is not None for e in events))
        self.assertEqual([_syslog_year(e["ts"]) for e in events],
                         [2000, 2000, 2001])


# --- L2: same-ts ceiling escape ----------------------------------------------

def _host_row(ts):
    detail = json.dumps({"summary": "x",
                         "fields": {"IpAddress": "-"}})
    return (ts, "eventlog", "4625", "HOST1", "u", detail)


class L2CeilingEscapeTests(ScratchDbTestCase):
    def test_truncates_to_group_boundary_and_resumes(self):
        # 22,000 rows at T1 straddle the 20k ceiling; 10,000 at T2 and
        # 5 at T3 follow. The pass completes one extra page (25k) and
        # truncates back to the T1 boundary -- the T2 group is picked
        # up on the next pass because the watermark only advanced to T1.
        base = 1_700_000_000.0
        rows = ([_host_row(base)] * 22000 + [_host_row(base + 10)] * 10000
                + [_host_row(base + 20)] * 5)
        dbm.insert_host_events(rows)
        first = ingm._new_events(0)
        self.assertEqual(len(first), 22000)
        self.assertTrue(all(r["ts"] == base for r in first))
        rest = ingm._new_events(base)
        self.assertEqual(len(rest), 10005)
        self.assertEqual([r["ts"] for r in rest[-5:]], [base + 20] * 5)

    def test_single_giant_group_does_not_wedge(self):
        # One same-ts group larger than the hard cap: the pass
        # processes the hard-cap chunk and the watermark advances past
        # the group (its tail is skipped, documented) instead of
        # returning nothing forever.
        base = 1_700_000_000.0
        rows = [_host_row(base)] * 30000 + [_host_row(base + 10)] * 5
        dbm.insert_host_events(rows)
        first = ingm._new_events(0)
        self.assertEqual(len(first), ingm._MAX_EVENTS_HARD)
        self.assertTrue(all(r["ts"] == base for r in first))
        # The rule would stamp the watermark to max(ts) = base; the
        # newer rows must still be reachable after that.
        rest = ingm._new_events(base)
        self.assertEqual([r["ts"] for r in rest], [base + 10] * 5)


# --- L3: scanner single-line materialisation ---------------------------------

_NUCLEI_VALID = json.dumps({
    "template-id": "http-missing-security-headers",
    "info": {"name": "HTTP Missing Security Headers",
             "severity": "medium",
             "description": "The server is missing security headers."},
    "host": "http://192.168.1.10/",
})
_AMASS_VALID = json.dumps({
    "name": "www.example.com", "domain": "example.com",
    "addresses": [{"ip": "93.184.216.34"}],
})


class L3ScannerLineCapTests(unittest.TestCase):
    def test_nuclei_huge_line_dropped_valid_lines_kept(self):
        from netmon import nuclei as nucleim
        huge = "{" + "x" * 5_000_000 + "}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                        delete=False) as f:
            f.write(_NUCLEI_VALID + "\n" + huge + _NUCLEI_VALID + "\n")
            path = f.name
        try:
            findings = nucleim.parse_jsonl_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(findings), 2)
        self.assertTrue(all(f["ip"] == "192.168.1.10" for f in findings))

    def test_nuclei_huge_line_at_eof_keeps_prior_findings(self):
        from netmon import nuclei as nucleim
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                        delete=False) as f:
            f.write(_NUCLEI_VALID + "\n" + "y" * 5_000_000)
            path = f.name
        try:
            findings = nucleim.parse_jsonl_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(findings), 1)

    def test_amass_huge_line_dropped_valid_lines_kept(self):
        from netmon import amass as amassm
        huge = "{" + "x" * 5_000_000 + "}\n"
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl",
                                        delete=False) as f:
            f.write(_AMASS_VALID + "\n" + huge + _AMASS_VALID + "\n")
            path = f.name
        try:
            assets = amassm.parse_jsonl_file(path)
        finally:
            os.unlink(path)
        self.assertEqual(len(assets), 2)
        self.assertTrue(all(a["name"] == "www.example.com"
                            for a in assets))


# --- L4: llm_egress correlation needs temporal overlap ------------------------

class L4CorrelationOverlapTests(ScratchDbTestCase):
    SRC = "192.168.1.5"
    ATTACKER = "203.0.113.9"

    def _dns(self, ts, name="api.deepseek.com"):
        return [(ts, self.SRC, name, 1)]

    def _auth_flows(self, ts, n=12):
        return [(ts - i * 30, self.ATTACKER, self.SRC,
                 40000 + i, 22, "TCP", 1, 200, "inbound")
                for i in range(n)]

    def test_ai_lookup_23h_before_attack_stays_quiet(self):
        # The old code correlated any two halves sharing a 24h window;
        # a lookup at 00:05 and an attack at 23:55 must not fire.
        now = time.time()
        dbm.insert_dns_queries(self._dns(now - 23 * 3600))
        dbm.insert_flows(self._auth_flows(now - 600))
        with dbm.notifications_paused():
            self.assertEqual(detm.check_llm_egress(now=now), [])

    def test_ai_lookup_within_6h_of_attack_fires(self):
        now = time.time()
        dbm.insert_dns_queries(self._dns(now - 5 * 3600))
        dbm.insert_flows(self._auth_flows(now - 600))
        with dbm.notifications_paused():
            fired = detm.check_llm_egress(now=now)
        self.assertEqual(fired, [("llm_egress", self.SRC)])
        detail = dbm.query(
            "SELECT detail FROM alerts WHERE kind='llm_egress'")[0][0]
        self.assertIn("within 6 hours", detail)

    def test_attack_within_6h_after_lookup_fires(self):
        # Overlap is symmetric: the attack may also precede the lookup.
        now = time.time()
        dbm.insert_dns_queries(self._dns(now - 600))
        dbm.insert_flows(self._auth_flows(now - 5 * 3600))
        with dbm.notifications_paused():
            fired = detm.check_llm_egress(now=now)
        self.assertEqual(fired, [("llm_egress", self.SRC)])

    def test_host_burst_within_6h_fires_via_correlation_b(self):
        # Correlation (b): the 4625 burst on this box, judged on the
        # burst alert's timestamp instead of the old boolean check.
        now = time.time()
        old_cache, old_ts = detm._LOCAL_IPS_CACHE, detm._LOCAL_IPS_CACHE_TS
        detm._LOCAL_IPS_CACHE = {self.SRC}
        detm._LOCAL_IPS_CACHE_TS = now
        try:
            dbm.insert_dns_queries(self._dns(now - 600))
            dbm.add_alert("host_event", "Medium",
                          "Failed logons", "4625 burst detail 4625",
                          ts=now - 5 * 3600)
            with dbm.notifications_paused():
                fired = detm.check_llm_egress(now=now)
        finally:
            detm._LOCAL_IPS_CACHE = old_cache
            detm._LOCAL_IPS_CACHE_TS = old_ts
        self.assertEqual(fired, [("llm_egress", self.SRC)])

    def test_host_burst_23h_before_lookup_stays_quiet(self):
        now = time.time()
        old_cache, old_ts = detm._LOCAL_IPS_CACHE, detm._LOCAL_IPS_CACHE_TS
        detm._LOCAL_IPS_CACHE = {self.SRC}
        detm._LOCAL_IPS_CACHE_TS = now
        try:
            dbm.insert_dns_queries(self._dns(now - 600))
            dbm.add_alert("host_event", "Medium",
                          "Failed logons", "4625 burst detail 4625",
                          ts=now - 23 * 3600)
            with dbm.notifications_paused():
                self.assertEqual(detm.check_llm_egress(now=now), [])
        finally:
            detm._LOCAL_IPS_CACHE = old_cache
            detm._LOCAL_IPS_CACHE_TS = old_ts


# --- L5: one shared event collection for the three passes ---------------------

_FP_OLD = "AAAAC3NzaC1lZDI1NTE5AAAAIOldKeyFingerprint0001"
_FP_NEW = "AAAAC3NzaC1lZDI1NTE5AAAAINewKeyFingerprint0002"


def _key_line(user, ip, dt, fp, host="host"):
    line = (f"{dt} {host} sshd[100]: Accepted publickey for {user}"
            f" from {ip} port 51234 ssh2")
    if fp:
        line += f": ED25519 SHA256:{fp}"
    return line


class L5SharedEventsTests(unittest.TestCase):
    def _run_dir(self):
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        sibling = [
            _key_line("alice", "10.0.0.1", "Oct  2 18:00:01", _FP_OLD),
            _fail_line("203.0.113.9", "Oct  2 18:05:01"),
            _fail_line("203.0.113.9", "Oct  2 18:05:02"),
        ]
        primary = [
            _fail_line("203.0.113.9", "Oct  2 19:00:01"),
            _fail_line("203.0.113.9", "Oct  2 19:00:02"),
            _fail_line("203.0.113.9", "Oct  2 19:00:03"),
            _fail_line("203.0.113.9", "Oct  2 19:00:04"),
            _key_line("bob", "10.0.0.2", "Oct  2 19:00:05", _FP_NEW),
        ]
        with open(os.path.join(d.name, "auth.log"), "w") as f:
            f.write("\n".join(primary) + "\n")
        with open(os.path.join(d.name, "auth.log.1.gz"), "wb") as f:
            f.write(gzip.compress(("\n".join(sibling) + "\n").encode()))
        return os.path.join(d.name, "auth.log")

    def test_shared_events_match_separate_reads(self):
        path = self._run_dir()
        events = _collect_events(path)
        self.assertEqual(detect_brute_force(path),
                         detect_brute_force(path, events=events))
        self.assertEqual(detect_cadence(path),
                         detect_cadence(path, events=events))
        self.assertEqual(detect_key_events(path),
                         detect_key_events(path, events=events))

    def test_shared_events_never_re_reads_the_log(self):
        path = self._run_dir()
        events = _collect_events(path)
        with mock.patch.object(detector, "_collect_events",
                               side_effect=AssertionError("re-read")):
            detect_brute_force(path, events=events)
            detect_cadence(path, events=events)
            detect_key_events(path, events=events)
        # And with events given, the path itself is never touched:
        self.assertEqual(
            detect_brute_force("/nonexistent/auth.log",
                               events=events),
            detect_brute_force(path))


@unittest.skipIf(appm is None, "Flask not installed")
class L5DemoPostTests(unittest.TestCase):
    def setUp(self):
        fd, self._db_path = tempfile.mkstemp(suffix=".db")
        os.close(fd)
        self._old_db_path = appm.DB_PATH
        appm.DB_PATH = self._db_path
        appm._SCAN_USAGE.clear()
        self.client = appm.app.test_client()

    def tearDown(self):
        appm.DB_PATH = self._old_db_path
        appm._SCAN_USAGE.clear()
        os.unlink(self._db_path)

    def test_post_collects_events_once(self):
        log = "\n".join(
            [_fail_line("203.0.113.9", "Oct  2 19:00:0%d" % i)
             for i in range(1, 6)]) + "\n"
        calls = []

        def _counting(path):
            calls.append(path)
            return detector._collect_events(path)

        with mock.patch.object(appm, "_collect_events",
                               side_effect=_counting):
            resp = self.client.post("/", data={"log": log})
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(calls), 1)
        self.assertIn(b"203.0.113.9", resp.data)


if __name__ == "__main__":
    unittest.main()
