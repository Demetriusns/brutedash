"""Tests for the Phase 3.5 batch (2026-10-03): incidents + MITRE tagging.

- Every alert kind brutedash emits has a MITRE tag.
- add_alert stores the MITRE fields on the row.
- Related alerts (same address, inside the window) join one incident;
  different addresses or an expired window open a new case.
- Incident severity escalates to the highest member severity.
- Old databases get MITRE columns backfilled on connect.

Run: python -m unittest discover -s tests -v
"""
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import mitre as mitrem


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


def _kinds_emitted():
    """Alert kinds emitted anywhere in the codebase (add_alert calls)."""
    root = os.path.join(os.path.dirname(__file__), "..", "netmon")
    kinds = set()
    pat = re.compile(r"add_alert\(\s*\"([a-z_0-9]+)\"")
    for fn in os.listdir(root):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(root, fn)) as fh:
            kinds.update(pat.findall(fh.read()))
    return kinds


class MitreMapTests(unittest.TestCase):
    def test_every_emitted_kind_has_a_tag(self):
        missing = [k for k in _kinds_emitted() if mitrem.tag_for(k) is None]
        self.assertEqual(missing, [],
                         f"kinds without MITRE tags: {missing}")

    def test_tag_shape(self):
        for kind in mitrem.all_kinds():
            tag = mitrem.tag_for(kind)
            self.assertRegex(tag["id"], r"^T\d+(\.\d+)?$",
                             f"bad technique id for {kind}")
            self.assertTrue(tag["name"] and tag["tactic"] and tag["note"])

    def test_unknown_kind_returns_none(self):
        self.assertIsNone(mitrem.tag_for("nope_not_a_kind"))
        self.assertIsNone(mitrem.tag_for(""))


class AlertMitreColumnTests(unittest.TestCase):
    def test_add_alert_stores_mitre_fields(self):
        path, old_path, old_conn = _fresh_db()
        try:
            with dbm.notifications_paused():
                aid = dbm.add_alert(
                    "port_scan", "High", "Possible port scan from 203.0.113.7",
                    "203.0.113.7 tried 20 ports.")
            rows = dbm.query(
                "SELECT mitre_id, mitre_name, mitre_tactic FROM alerts"
                " WHERE id=?", (aid,))
            self.assertEqual(rows[0], ("T1046", "Network Service Discovery",
                                       "Discovery"))
        finally:
            _restore_db(path, old_path, old_conn)

    def test_unmapped_kind_leaves_nulls(self):
        path, old_path, old_conn = _fresh_db()
        try:
            with dbm.notifications_paused():
                aid = dbm.add_alert("mystery_kind", "Low", "t", "d")
            rows = dbm.query(
                "SELECT mitre_id FROM alerts WHERE id=?", (aid,))
            self.assertIsNone(rows[0][0])
        finally:
            _restore_db(path, old_path, old_conn)


class IncidentGroupingTests(unittest.TestCase):
    def test_same_address_groups_into_one_case(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                a1 = dbm.add_alert(
                    "port_scan", "High",
                    "Possible port scan from 203.0.113.7",
                    "203.0.113.7 tried 20 ports.", ts=now)
                a2 = dbm.add_alert(
                    "beaconing", "Medium",
                    "Repeated check-ins: laptop with 203.0.113.7",
                    "laptop contacted 203.0.113.7 repeatedly.", ts=now + 60)
            cases = dbm.list_incidents()
            self.assertEqual(len(cases), 1)
            self.assertEqual(cases[0]["alert_count"], 2)
            self.assertEqual(cases[0]["device_key"], "203.0.113.7")
            self.assertEqual(cases[0]["severity"], "High")  # escalated
            # both alerts point at the same incident
            for aid in (a1, a2):
                rows = dbm.query(
                    "SELECT incident_id FROM incident_alerts WHERE alert_id=?",
                    (aid,))
                self.assertEqual(rows[0][0], cases[0]["id"])
        finally:
            _restore_db(path, old_path, old_conn)

    def test_different_addresses_open_separate_cases(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports.", ts=now)
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 198.51.100.9",
                              "198.51.100.9 tried 20 ports.", ts=now + 60)
            self.assertEqual(len(dbm.list_incidents()), 2)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_expired_window_opens_new_case(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports.", ts=now)
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports again.",
                              ts=now + dbm.INCIDENT_WINDOW_S + 10)
            self.assertEqual(len(dbm.list_incidents()), 2)
        finally:
            _restore_db(path, old_path, old_conn)

    def test_keyless_alerts_get_own_cases(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.add_alert("traffic_spike", "Medium",
                              "Unusual surge in network traffic",
                              "moved a lot of data", ts=now)
                dbm.add_alert("traffic_spike", "Medium",
                              "Unusual surge in network traffic",
                              "moved a lot of data", ts=now + 60)
            cases = dbm.list_incidents()
            self.assertEqual(len(cases), 2)
            self.assertIsNone(cases[0]["device_key"])
        finally:
            _restore_db(path, old_path, old_conn)

    def test_lan_ip_used_when_no_external(self):
        path, old_path, old_conn = _fresh_db()
        try:
            with dbm.notifications_paused():
                dbm.add_alert("new_device", "Low",
                              "New device joined",
                              "192.168.1.42 showed up on the LAN.")
            cases = dbm.list_incidents()
            self.assertEqual(cases[0]["device_key"], "192.168.1.42")
        finally:
            _restore_db(path, old_path, old_conn)

    def test_get_incident_timeline_order(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.add_alert("beaconing", "Medium", "b1",
                              "laptop with 203.0.113.7 (first)", ts=now)
                dbm.add_alert("beaconing", "Medium", "b2",
                              "laptop with 203.0.113.7 (second)", ts=now + 5)
            case = dbm.get_incident(dbm.list_incidents()[0]["id"])
            self.assertEqual([a["title"] for a in case["alerts"]],
                             ["b1", "b2"])
            self.assertEqual(case["alerts"][0]["mitre_id"], "T1071.001")
        finally:
            _restore_db(path, old_path, old_conn)

    def test_close_and_reopen(self):
        path, old_path, old_conn = _fresh_db()
        try:
            with dbm.notifications_paused():
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports.")
            iid = dbm.list_incidents()[0]["id"]
            self.assertTrue(dbm.set_incident_status(iid, "closed"))
            self.assertEqual(dbm.list_incidents(), [])
            self.assertEqual(len(dbm.list_incidents(status="closed")), 1)
            self.assertTrue(dbm.set_incident_status(iid, "open"))
            self.assertEqual(len(dbm.list_incidents()), 1)
            self.assertFalse(dbm.set_incident_status(iid, "bogus"))
            self.assertFalse(dbm.set_incident_status(999999, "closed"))
        finally:
            _restore_db(path, old_path, old_conn)

    def test_closed_case_does_not_reopen_on_new_alert(self):
        path, old_path, old_conn = _fresh_db()
        try:
            now = time.time()
            with dbm.notifications_paused():
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports.", ts=now)
            iid = dbm.list_incidents()[0]["id"]
            dbm.set_incident_status(iid, "closed")
            with dbm.notifications_paused():
                dbm.add_alert("port_scan", "High",
                              "Possible port scan from 203.0.113.7",
                              "203.0.113.7 tried 20 ports.", ts=now + 60)
            open_cases = dbm.list_incidents()
            self.assertEqual(len(open_cases), 1)
            self.assertNotEqual(open_cases[0]["id"], iid)
        finally:
            _restore_db(path, old_path, old_conn)


class MigrationTests(unittest.TestCase):
    def test_old_db_gets_mitre_columns_backfilled(self):
        path, old_path, old_conn = _fresh_db()
        try:
            # Simulate a pre-Phase-3.5 database: alerts table without the
            # MITRE columns, one row already stored.
            conn = sqlite3.connect(path)
            conn.execute("DROP TABLE IF EXISTS alerts")
            conn.execute(
                "CREATE TABLE alerts(id INTEGER PRIMARY KEY, ts REAL,"
                " kind TEXT, severity TEXT, title TEXT, detail TEXT)")
            conn.execute(
                "INSERT INTO alerts (ts, kind, severity, title, detail)"
                " VALUES (?,?,?,?,?)",
                (time.time(), "port_scan", "High", "t", "d"))
            conn.commit()
            conn.close()
            # Reconnect through the real path: schema + migrations run.
            dbm._conn = None
            rows = dbm.query(
                "SELECT mitre_id, mitre_name, mitre_tactic FROM alerts")
            self.assertEqual(rows[0], ("T1046", "Network Service Discovery",
                                       "Discovery"))
            # New alerts on the migrated DB also get tagged.
            with dbm.notifications_paused():
                dbm.add_alert("beaconing", "Medium", "b",
                              "x with 203.0.113.7")
            rows = dbm.query(
                "SELECT mitre_id FROM alerts WHERE kind='beaconing'")
            self.assertEqual(rows[0][0], "T1071.001")
        finally:
            _restore_db(path, old_path, old_conn)


if __name__ == "__main__":
    unittest.main()
