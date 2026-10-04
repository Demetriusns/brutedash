"""Tests for the Phase 3.5 batch 9 (2026-10-03): response.

"Act, not just watch": full playbooks, one-click quarantine
(approval-only), and "Escalate to administrator".

- Playbooks: every registered slug renders its full guide (200) with
  the three sections; unknown-but-well-formed slugs keep the friendly
  placeholder (200); malformed slugs 404. Every alert kind the monitor
  emits maps to a guide.
- Quarantine safety: the gateway, this box, and the viewer's device are
  refused with a plain-English reason; unknown/malformed MACs refused.
- Quarantine flow: isolate -> active row + audit entry + ARP packets;
  release -> row flips + corrective ARP + audit entry.
- Audit log is append-only: no UPDATE/DELETE against audit_log exists
  anywhere in the source tree.
- NO AUTONOMOUS QUARANTINE: no code path outside the dashboard route
  may call request_quarantine/release_quarantine (source inspection).
  No shell/subprocess in the ARP layer (argv-free by construction).
- Escalate: state machine open -> escalated -> closed (closed cases
  can't escalate); unconfigured admin email -> setup hint; bad email
  rejected; email headers can't be injected; a failed send never moves
  the case; the bundle carries timeline, MITRE tags, recommended
  actions, and what the owner already tried.

Run: python -m unittest discover -s tests
"""
import os
import re
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import attacksurface as asm
from netmon import playbooks as pbm
from netmon import quarantine as qm
from netmon import escalate as escm
from netmon import mitre as mitrem

try:
    from netmon import dashboard as dashm
except ImportError:  # Flask not installed: skip dashboard-only tests
    dashm = None

NETMON = os.path.join(os.path.dirname(__file__), "..", "netmon")

FAKE_MAC = "aa:bb:cc:dd:ee:50"
FAKE_IP = "192.168.1.50"
GW_MAC = "aa:bb:cc:dd:ee:01"
GW_IP = "192.168.1.1"


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
        self._old_sendp = qm._SENDP
        self._old_own_mac = qm._own_mac
        self._old_admin_email = escm.admin_email
        self._old_send_email = escm._SEND_EMAIL
        self.sent_packets = []
        qm._SENDP = self.sent_packets.append

    def tearDown(self):
        qm._reset_for_tests()
        qm._SENDP = self._old_sendp
        qm._own_mac = self._old_own_mac
        escm.admin_email = self._old_admin_email
        escm._SEND_EMAIL = self._old_send_email
        _restore_db(*self._db)

    def _seed_device(self, mac=FAKE_MAC, ip=FAKE_IP):
        dbm.insert_arp_observations([(time.time(), ip, mac.lower())])

    def _seed_gateway(self):
        dbm.set_meta("dhcp_gateway_ip", GW_IP)
        dbm.insert_arp_observations([(time.time(), GW_IP, GW_MAC)])


# --- quarantine safety ------------------------------------------------------

class QuarantineSafetyTests(_DbTest):
    def test_malformed_mac_refused(self):
        ok, reason = qm.safety_check("not-a-mac", None)
        self.assertFalse(ok)
        self.assertIn("device address", reason)

    def test_unknown_device_refused(self):
        ok, reason = qm.safety_check(FAKE_MAC, None)
        self.assertFalse(ok)
        self.assertIn("haven't seen", reason)

    def test_gateway_mac_refused(self):
        self._seed_gateway()
        ok, reason = qm.safety_check(GW_MAC, None)
        self.assertFalse(ok)
        self.assertIn("router", reason)

    def test_gateway_ip_device_refused(self):
        # A device currently holding the gateway IP is the router too.
        self._seed_gateway()
        other_mac = "aa:bb:cc:dd:ee:02"
        dbm.insert_arp_observations([(time.time(), GW_IP, other_mac)])
        ok, reason = qm.safety_check(other_mac, None)
        self.assertFalse(ok)
        self.assertIn("router", reason)

    def test_own_mac_refused(self):
        self._seed_device()
        qm._own_mac = lambda: FAKE_MAC
        ok, reason = qm.safety_check(FAKE_MAC, None)
        self.assertFalse(ok)
        self.assertIn("monitor box", reason)

    def test_viewer_device_by_ip_refused(self):
        self._seed_device()
        ok, reason = qm.safety_check(FAKE_MAC, viewer_ip=FAKE_IP)
        self.assertFalse(ok)
        self.assertIn("browsing from", reason)

    def test_different_viewer_ip_allowed(self):
        self._seed_device()
        other_ip = "192.168.1.77"
        ok, reason = qm.safety_check(FAKE_MAC, viewer_ip=other_ip)
        # viewer at a different IP, device not the viewer -> allowed
        self.assertTrue(ok, reason)

    def test_ordinary_device_allowed(self):
        self._seed_device()
        self._seed_gateway()
        ok, reason = qm.safety_check(FAKE_MAC, viewer_ip="192.168.1.99")
        self.assertTrue(ok, reason)


# --- quarantine request/release flow ----------------------------------------

class QuarantineFlowTests(_DbTest):
    def test_request_and_release(self):
        self._seed_device()
        self._seed_gateway()
        poisoned, restored = [], []
        old_poison, old_restore = qm._poison, qm._restore
        qm._poison = lambda mac, ip: poisoned.append((mac, ip))
        qm._restore = lambda mac, ip: restored.append((mac, ip))
        try:
            ok, msg = qm.request_quarantine(FAKE_MAC, actor="test",
                                            viewer_ip="192.168.1.99")
        finally:
            qm._poison, qm._restore = old_poison, old_restore
        self.assertTrue(ok, msg)
        self.assertTrue(dbm.is_quarantined(FAKE_MAC))
        # The isolation attempt went out exactly once for this device.
        self.assertEqual(poisoned, [(FAKE_MAC, FAKE_IP)])
        # Audit trail has the quarantine.
        actions = [e["action"] for e in dbm.list_audit()]
        self.assertIn("quarantine", actions)

        qm._restore = lambda mac, ip: restored.append((mac, ip))
        try:
            ok, msg = qm.release_quarantine(FAKE_MAC, actor="test")
        finally:
            qm._restore = old_restore
        self.assertTrue(ok, msg)
        self.assertFalse(dbm.is_quarantined(FAKE_MAC))
        q = dbm.get_quarantine(FAKE_MAC)
        self.assertEqual(q["state"], "released")
        self.assertEqual(restored, [(FAKE_MAC, FAKE_IP)])
        actions = [e["action"] for e in dbm.list_audit()]
        self.assertIn("release", actions)

    @unittest.skipIf(__import__("importlib").util.find_spec("scapy") is None,
                     "scapy not installed")
    def test_arp_packets_are_forged_replies(self):
        # The real packet builder: op=2 "is-at" replies, target told the
        # router is at our MAC, router told the device is at our MAC.
        pkts = qm._arp_packets("aa:bb:cc:dd:ee:50", "192.168.1.50",
                               "192.168.1.1", "aa:bb:cc:dd:ee:01",
                               "aa:bb:cc:dd:ee:ff", poison=True)
        self.assertEqual(len(pkts), 2)
        for pkt in pkts:
            self.assertTrue(pkt.haslayer("ARP"))
            self.assertEqual(pkt["ARP"].op, 2)
            self.assertEqual(pkt["ARP"].hwsrc, "aa:bb:cc:dd:ee:ff")
        self.assertEqual(pkts[0]["ARP"].psrc, "192.168.1.1")   # to target
        self.assertEqual(pkts[0]["ARP"].pdst, "192.168.1.50")
        self.assertEqual(pkts[1]["ARP"].psrc, "192.168.1.50")   # to router
        self.assertEqual(pkts[1]["ARP"].pdst, "192.168.1.1")
        # Restore tells the truth: real MACs on both sides.
        pkts = qm._arp_packets("aa:bb:cc:dd:ee:50", "192.168.1.50",
                               "192.168.1.1", "aa:bb:cc:dd:ee:01",
                               None, poison=False)
        self.assertEqual(pkts[0]["ARP"].hwsrc, "aa:bb:cc:dd:ee:01")
        self.assertEqual(pkts[1]["ARP"].hwsrc, "aa:bb:cc:dd:ee:50")

    def test_poison_without_gateway_refuses(self):
        # No gateway known -> _poison raises before any packet is built
        # (no scapy needed for this path).
        with self.assertRaises(RuntimeError):
            qm._poison(FAKE_MAC, FAKE_IP)

    def test_refused_request_is_audited(self):
        ok, _ = qm.request_quarantine(FAKE_MAC, actor="test",
                                      viewer_ip=None)
        self.assertFalse(ok)  # unknown device
        actions = [e["action"] for e in dbm.list_audit()]
        self.assertIn("quarantine_refused", actions)

    def test_release_when_not_isolated(self):
        self._seed_device()
        ok, msg = qm.release_quarantine(FAKE_MAC, actor="test")
        self.assertFalse(ok)
        self.assertIn("isn't isolated", msg)

    def test_audit_log_is_append_only_in_source(self):
        pat = re.compile(r"(UPDATE\s+audit_log|DELETE\s+FROM\s+audit_log)",
                         re.IGNORECASE)
        for fn in sorted(os.listdir(NETMON)):
            if not fn.endswith(".py"):
                continue
            with open(os.path.join(NETMON, fn)) as fh:
                src = fh.read()
            self.assertIsNone(
                pat.search(src),
                f"{fn} mutates the audit log -- it must be append-only")


# --- no autonomous quarantine (source inspection) ----------------------------

class NoAutonomyTests(unittest.TestCase):
    def test_only_dashboard_calls_quarantine(self):
        allowed = {"dashboard.py", "quarantine.py"}
        for fn in sorted(os.listdir(NETMON)):
            if not fn.endswith(".py") or fn in allowed:
                continue
            with open(os.path.join(NETMON, fn)) as fh:
                src = fh.read()
            for call in ("request_quarantine(", "release_quarantine("):
                self.assertNotIn(
                    call, src,
                    f"{fn} calls {call} -- quarantine is approval-only;"
                    " only the dashboard route may call it")

    def test_no_shell_in_arp_layer(self):
        with open(os.path.join(NETMON, "quarantine.py")) as fh:
            src = fh.read()
        self.assertNotIn("shell=True", src)
        self.assertNotIn("import subprocess", src)
        self.assertNotIn("os.system", src)


# --- escalate: state machine + email safety ----------------------------------

class EscalateTests(_DbTest):
    def _make_case(self, title="Case: suspicious activity involving 203.0.113.7"):
        aid = dbm.add_alert(
            "beaconing", "High", title, "device 192.168.1.50",
            meaning="A device keeps checking in.",
            what_to_do="Find the program doing it.", ts=time.time())
        cases = dbm.list_incidents(status="open")
        self.assertTrue(cases)
        return cases[0]["id"], aid

    def test_state_machine(self):
        iid, _ = self._make_case()
        # open -> escalated
        self.assertTrue(dbm.set_incident_status(iid, "escalated"))
        self.assertEqual(dbm.get_incident(iid)["status"], "escalated")
        # escalated -> escalated is not a transition; escalated -> closed ok
        self.assertTrue(dbm.set_incident_status(iid, "closed"))
        # closed -> escalated refused
        self.assertFalse(dbm.set_incident_status(iid, "escalated"))
        self.assertEqual(dbm.get_incident(iid)["status"], "closed")
        # bogus status refused
        self.assertFalse(dbm.set_incident_status(iid, "nope"))

    def test_new_alerts_attach_to_escalated_case(self):
        iid, _ = self._make_case()
        dbm.set_incident_status(iid, "escalated")
        dbm.add_alert("beaconing", "Medium", "Case: suspicious activity"
                      " involving 203.0.113.7", "device 192.168.1.50",
                      ts=time.time())
        case = dbm.get_incident(iid)
        self.assertEqual(len(case["alerts"]), 2)

    def test_unconfigured_admin_email_gives_setup_hint(self):
        escm.admin_email = lambda: ""
        iid, _ = self._make_case()
        ok, msg = escm.send_escalation(iid)
        self.assertFalse(ok)
        self.assertIn("config.yaml", msg)
        self.assertIn("admin_email", msg)
        self.assertEqual(dbm.get_incident(iid)["status"], "open")

    def test_invalid_admin_email_rejected(self):
        escm.admin_email = lambda: "not-an-email\r\nBcc: evil@x.com"
        iid, _ = self._make_case()
        ok, msg = escm.send_escalation(iid)
        self.assertFalse(ok)
        self.assertIn("doesn't look like", msg)
        self.assertEqual(dbm.get_incident(iid)["status"], "open")

    def test_successful_escalation(self):
        sent = []
        escm.admin_email = lambda: "admin@example.com"
        escm._SEND_EMAIL = lambda s, b: sent.append((s, b))
        iid, aid = self._make_case()
        dbm.set_alert_status(aid, "acknowledged", "looked, it's the TV")
        ok, msg = escm.send_escalation(iid, actor="test")
        self.assertTrue(ok, msg)
        self.assertEqual(dbm.get_incident(iid)["status"], "escalated")
        self.assertEqual(len(sent), 1)
        subject, body = sent[0]
        self.assertIn("Escalated case", subject)
        self.assertNotIn("\r", subject)
        self.assertNotIn("\n", subject)
        self.assertIn("admin@example.com", msg)
        # Escalation + audit recorded.
        escs = dbm.list_escalations(iid)
        self.assertEqual(len(escs), 1)
        self.assertTrue(escs[0]["sent_ok"])
        self.assertIn("escalate",
                      [e["action"] for e in dbm.list_audit()])
        # Bundle sections present in the email body.
        for needle in ("Timeline", "What the owner already tried",
                       "Recommended next steps", "T1071.001"):
            self.assertIn(needle, body, needle)
        # ...including what was tried (the acknowledgement above).
        self.assertIn("Acknowledged", body)

    def test_failed_send_keeps_case_open(self):
        escm.admin_email = lambda: "admin@example.com"

        def boom(s, b):
            raise RuntimeError("smtp down")
        escm._SEND_EMAIL = boom
        iid, _ = self._make_case()
        ok, msg = escm.send_escalation(iid)
        self.assertFalse(ok)
        self.assertIn("didn't go through", msg)
        self.assertEqual(dbm.get_incident(iid)["status"], "open")
        escs = dbm.list_escalations(iid)
        self.assertEqual(len(escs), 1)
        self.assertFalse(escs[0]["sent_ok"])

    def test_cannot_escalate_closed_case(self):
        escm.admin_email = lambda: "admin@example.com"
        escm._SEND_EMAIL = lambda s, b: None
        iid, _ = self._make_case()
        dbm.set_incident_status(iid, "closed")
        ok, msg = escm.send_escalation(iid)
        self.assertFalse(ok)
        self.assertIn("Only open cases", msg)

    def test_header_injection_scrubbed(self):
        escm.admin_email = lambda: "admin@example.com"
        sent = []
        escm._SEND_EMAIL = lambda s, b: sent.append((s, b))
        iid, _ = self._make_case(
            title="Case: evil\r\nBcc: attacker@x.com")
        ok, _ = escm.send_escalation(iid)
        self.assertTrue(ok)
        subject, body = sent[0]
        self.assertNotIn("\r", subject)
        self.assertNotIn("\n", subject)
        self.assertNotIn("Bcc:", subject)

    def test_email_validation(self):
        self.assertTrue(escm.valid_admin_email("admin@example.com"))
        self.assertTrue(escm.valid_admin_email("a.b+tag@sub.example.co"))
        for bad in ("", "not-an-email", "a@b", "a@b.c",
                    "x@y.com\r\nBcc: z@w.com", "x" * 65 + "@example.com"):
            self.assertFalse(escm.valid_admin_email(bad), bad)

    def test_what_was_tried_includes_quarantine(self):
        escm.admin_email = lambda: "admin@example.com"
        escm._SEND_EMAIL = lambda s, b: None
        self._seed_device()
        iid, _ = self._make_case(
            title="Case: suspicious activity involving 192.168.1.50")
        # The case's device_key is 192.168.1.50; audit mentions its MAC.
        dbm.audit("quarantine", "test", FAKE_MAC, "isolated for a look")
        tried = dbm.incident_what_was_tried(iid)
        self.assertTrue(any("Isolated" in t for t in tried), tried)


# --- dashboard routes ---------------------------------------------------------

@unittest.skipIf(dashm is None, "Flask not installed")
class PlaybookRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_every_registered_slug_renders_full_guide(self):
        c = self._client()
        for slug in sorted(asm.PLAYBOOK_SLUGS):
            r = c.get(f"/playbook/{slug}")
            self.assertEqual(r.status_code, 200, slug)
            # The three guide sections (apostrophes are HTML-escaped).
            for section in (b"what we found", b"what to do",
                            b"When to escalate"):
                self.assertIn(section, r.data, f"{slug}: missing {section!r}")
            # Title + blurb from the registry appear.
            title = asm.PLAYBOOK_SLUGS[slug]["title"]
            self.assertIn(title.encode()[:20], r.data, slug)

    def test_unknown_wellformed_slug_keeps_placeholder(self):
        c = self._client()
        r = c.get("/playbook/some-future-guide")
        self.assertEqual(r.status_code, 200)
        self.assertIn(b"still being written", r.data)

    def test_malformed_slug_404(self):
        c = self._client()
        r = c.get("/playbook/%2e%2e%2fetc")
        self.assertEqual(r.status_code, 404)
        r = c.get("/playbook/BAD_SLUG!")
        self.assertEqual(r.status_code, 404)

    def test_every_alert_kind_has_a_guide(self):
        for kind in mitrem.all_kinds():
            slug = pbm.playbook_slug_for_kind(kind)
            self.assertIsNotNone(slug, kind)
            self.assertIn(slug, asm.PLAYBOOK_SLUGS, kind)
            self.assertIsNotNone(pbm.get_guide(slug), kind)


@unittest.skipIf(dashm is None, "Flask not installed")
class QuarantineRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_quarantine_and_release_roundtrip(self):
        self._seed_device()
        self._seed_gateway()
        c = self._client()
        r = c.post("/api/devices/quarantine", json={"mac": FAKE_MAC},
                   environ_overrides={"REMOTE_ADDR": "192.168.1.99"})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertTrue(r.get_json()["ok"])
        self.assertTrue(dbm.is_quarantined(FAKE_MAC))
        self.assertTrue(self.sent_packets)

        r = c.get("/api/quarantine")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(len(r.get_json()["quarantined"]), 1)

        r = c.get("/api/devices")
        dev = [d for d in r.get_json()["devices"]
               if d["mac"] == FAKE_MAC][0]
        self.assertTrue(dev["quarantined"])

        r = c.post("/api/devices/quarantine/release",
                   json={"mac": FAKE_MAC})
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertFalse(dbm.is_quarantined(FAKE_MAC))

    def test_gateway_refused_over_http(self):
        self._seed_gateway()
        c = self._client()
        r = c.post("/api/devices/quarantine", json={"mac": GW_MAC},
                   environ_overrides={"REMOTE_ADDR": "192.168.1.99"})
        self.assertEqual(r.status_code, 403)
        self.assertIn("router", r.get_json()["error"])
        self.assertFalse(dbm.is_quarantined(GW_MAC))

    def test_viewer_device_refused_over_http(self):
        self._seed_device()
        c = self._client()
        r = c.post("/api/devices/quarantine", json={"mac": FAKE_MAC},
                   environ_overrides={"REMOTE_ADDR": FAKE_IP})
        self.assertEqual(r.status_code, 403)
        self.assertIn("browsing from", r.get_json()["error"])

    def test_unknown_device_refused_over_http(self):
        c = self._client()
        r = c.post("/api/devices/quarantine",
                   json={"mac": "aa:bb:cc:dd:ee:99"})
        self.assertEqual(r.status_code, 403)

    def test_missing_mac_400(self):
        c = self._client()
        r = c.post("/api/devices/quarantine", json={})
        self.assertEqual(r.status_code, 400)


@unittest.skipIf(dashm is None, "Flask not installed")
class EscalateRouteTests(_DbTest):
    def _client(self):
        dashm.app.config["TESTING"] = True
        return dashm.app.test_client()

    def test_escalate_route_end_to_end(self):
        sent = []
        escm.admin_email = lambda: "admin@example.com"
        escm._SEND_EMAIL = lambda s, b: sent.append((s, b))
        dbm.add_alert("beaconing", "High",
                      "Case: suspicious activity involving 203.0.113.7",
                      "device 192.168.1.50", ts=time.time())
        iid = dbm.list_incidents(status="open")[0]["id"]
        c = self._client()
        r = c.post(f"/api/incidents/{iid}/escalate")
        self.assertEqual(r.status_code, 200, r.get_json())
        self.assertTrue(r.get_json()["ok"])
        self.assertEqual(len(sent), 1)
        # Escalated filter shows it with the awaiting-admin state.
        r = c.get("/api/incidents?status=escalated")
        self.assertEqual(r.status_code, 200)
        ids = [x["id"] for x in r.get_json()["incidents"]]
        self.assertIn(iid, ids)
        # Case detail carries the escalation history + playbook slugs.
        r = c.get(f"/api/incidents/{iid}")
        d = r.get_json()["incident"]
        self.assertEqual(d["status"], "escalated")
        self.assertEqual(len(d["escalations"]), 1)
        self.assertTrue(d["escalations"][0]["sent_ok"])
        self.assertEqual(d["alerts"][0]["playbook"], "beaconing")

    def test_escalate_route_without_admin_email(self):
        escm.admin_email = lambda: ""
        dbm.add_alert("beaconing", "High",
                      "Case: suspicious activity involving 203.0.113.7",
                      "device 192.168.1.50", ts=time.time())
        iid = dbm.list_incidents(status="open")[0]["id"]
        c = self._client()
        r = c.post(f"/api/incidents/{iid}/escalate")
        self.assertEqual(r.status_code, 400)
        self.assertIn("config.yaml", r.get_json()["error"])

    def test_escalate_route_second_time_conflicts(self):
        sent = []
        escm.admin_email = lambda: "admin@example.com"
        escm._SEND_EMAIL = lambda s, b: sent.append((s, b))
        dbm.add_alert("beaconing", "High",
                      "Case: suspicious activity involving 203.0.113.7",
                      "device 192.168.1.50", ts=time.time())
        iid = dbm.list_incidents(status="open")[0]["id"]
        c = self._client()
        self.assertEqual(c.post(f"/api/incidents/{iid}/escalate").status_code,
                         200)
        r = c.post(f"/api/incidents/{iid}/escalate")
        self.assertEqual(r.status_code, 409)
        self.assertEqual(len(sent), 1)  # no double-send


if __name__ == "__main__":
    unittest.main()
