"""Tests for the Phase 3.5 batch 15 (2026-10-04): MCP tool server.

netmon/tools.py -- the AI analyst's tool registry (HexStrike AI pattern,
MIT -- pattern only, no offensive tooling): schemas + validation +
bounded execution + error recovery + audit logging.

Covered here:
- Registry: the six built-in tools are registered with schemas; the
  debug CLI lists them.
- Schema validation: good params pass; wrong types, out-of-range ints,
  unknown tools, unknown params, missing required params, non-dict
  params, enum violations, non-LAN targets, non-inventory targets, and
  bad alert-kind/domain/IP values are all LOUD structured rejections.
- Trust boundary: a model proposing {"tool": "scan", "target":
  "external"} is rejected at validation and the scan never executes
  (execution functions are tripwired); {"tool": "quarantine"} is an
  unknown tool; shell metacharacters never reach a shell (source
  inspection: no shell=True / os.system / eval / exec in tools.py).
- Timeout enforcement: a tool that sleeps past its declared timeout
  returns a timeout error promptly.
- Error recovery: structured error shape (ok/tool/error_kind/error/
  retry_hint, no tracebacks); idempotent tools retry once on transient
  failures; non-idempotent tools never auto-retry; permanent failures
  don't retry.
- Audit: every invocation (success, validation rejection, unknown
  tool) appends a tool_call audit row with who/what/outcome; the
  escalation bundle's "what the user already tried" picks them up.
- Quiet: tool invocations never create alerts and never write scan
  runs/findings (tool scans are ephemeral).
- /ask wiring: the model can request tool calls as data, the registry
  validates + executes, results return as data; malicious proposals are
  rejected without executing; the tool budget is bounded.

Run: python -m unittest discover -s tests
"""
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import db as dbm
from netmon import tools as toolsm
from netmon import ai_assist as assistm

NETMON = os.path.join(os.path.dirname(__file__), "..", "netmon")
REPO = os.path.join(os.path.dirname(__file__), "..")

FAKE_IP = "192.168.1.50"
OTHER_IP = "192.168.1.99"


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
        self._old_inventory = toolsm._inventory_ips
        # Controlled inventory: exactly one known device.
        toolsm._inventory_ips = lambda: {FAKE_IP}

    def tearDown(self):
        toolsm._inventory_ips = self._old_inventory
        _restore_db(*self._db)

    def _seed_alert(self, kind="port_scan", severity="High",
                    title="seeded alert", detail="seeded detail"):
        with dbm.notifications_paused():
            return dbm.add_alert(kind, severity, title, detail,
                                 meaning="m", is_normal="n",
                                 what_to_do="w")

    def _alert_count(self):
        return dbm.query("SELECT COUNT(*) FROM alerts")[0][0]


# --- registry ----------------------------------------------------------------

class RegistryTests(unittest.TestCase):
    def test_builtin_tools_registered(self):
        names = {t["name"] for t in toolsm.list_tools()}
        self.assertEqual(
            names,
            {"get_alerts", "get_incidents", "get_devices",
             "get_scan_status", "scan", "lookup_threat_intel",
             "get_pipeline_health"})

    def test_list_tools_shape(self):
        for t in toolsm.list_tools():
            self.assertIn("name", t)
            self.assertIn("description", t)
            self.assertIn("params", t)
            self.assertIn("timeout_s", t)
            self.assertGreater(t["timeout_s"], 0)
            for pname, p in t["params"].items():
                self.assertIn(p["type"], ("int", "str", "bool", "enum"))
                self.assertIn("required", p)

    def test_no_dangerous_tools_registered(self):
        names = {t["name"] for t in toolsm.list_tools()}
        for bad in ("quarantine", "shell", "exec", "block", "dismiss",
                    "escalate", "delete"):
            self.assertNotIn(bad, names)

    def test_register_unregister_roundtrip(self):
        spec = toolsm.ToolSpec(
            name="__tmp_test_tool", description="throwaway",
            handler=lambda p: {"ok": True})
        toolsm.register_tool(spec)
        try:
            self.assertIsNotNone(toolsm.get_tool("__tmp_test_tool"))
        finally:
            toolsm.unregister_tool("__tmp_test_tool")
        self.assertIsNone(toolsm.get_tool("__tmp_test_tool"))

    def test_no_shell_or_eval_in_source(self):
        # The model never gets process access: no shell/exec primitives
        # may appear in CODE (prose in docstrings/comments is masked
        # first, the same way scripts/audit_llm_sinks.py masks).
        with open(os.path.join(NETMON, "tools.py"),
                  encoding="utf-8") as fh:
            src = fh.read()
        masked = re.sub(r'""".*?"""', '""', src, flags=re.S)
        masked = re.sub(r"'''.*?'''", "''", masked, flags=re.S)
        masked = re.sub(r'"(?:[^"\\]|\\.)*"', '""', masked)
        masked = re.sub(r"'(?:[^'\\]|\\.)*'", "''", masked)
        masked = re.sub(r"#[^\n]*", "", masked)
        for banned in ("shell=True", "os.system", "eval(", "exec(",
                       "subprocess.Popen", "subprocess.call",
                       "__import__", "compile("):
            self.assertNotIn(banned, masked,
                             f"tools.py must not contain {banned!r} in"
                             " code: the model never gets process access")


# --- schema validation ---------------------------------------------------------

class ValidationTests(_DbTest):
    def _is_validation(self, res, param=None):
        self.assertFalse(res["ok"], f"expected rejection, got {res}")
        self.assertEqual(res["error_kind"], "validation")
        self.assertIn("error", res)
        self.assertIn("retry_hint", res)
        if param:
            self.assertEqual(res.get("param"), param)

    def test_good_params_pass(self):
        res = toolsm.invoke("get_alerts",
                            {"severity": "High", "limit": 5, "hours": 24},
                            requested_by="test")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["tool"], "get_alerts")
        self.assertIn("result", res)

    def test_defaults_fill_in(self):
        res = toolsm.invoke("get_alerts", {}, requested_by="test")
        self.assertTrue(res["ok"], res)

    def test_wrong_type_rejected(self):
        res = toolsm.invoke("get_alerts", {"limit": "ten"},
                            requested_by="test")
        self._is_validation(res, param="limit")

    def test_bool_is_not_int(self):
        res = toolsm.invoke("get_alerts", {"limit": True},
                            requested_by="test")
        self._is_validation(res, param="limit")

    def test_out_of_range_rejected(self):
        for bad in (0, 101):
            res = toolsm.invoke("get_alerts", {"limit": bad},
                                requested_by="test")
            self._is_validation(res, param="limit")
        res = toolsm.invoke("get_alerts", {"hours": 169},
                            requested_by="test")
        self._is_validation(res, param="hours")

    def test_enum_violation_rejected(self):
        res = toolsm.invoke("get_alerts", {"severity": "extreme"},
                            requested_by="test")
        self._is_validation(res, param="severity")

    def test_unknown_tool_rejected(self):
        res = toolsm.invoke("quarantine", {"mac": "aa:bb:cc:dd:ee:ff"},
                            requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "validation")
        self.assertIsNone(res["tool"])
        self.assertIn("quarantine", res["error"])

    def test_unknown_param_rejected(self):
        # The exact case from the task: the model invents a "target"
        # parameter. Loud rejection, nothing runs.
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target": "external"},
                            requested_by="test")
        self._is_validation(res, param="target")
        self.assertIn("target", res["error"])

    def test_missing_required_rejected(self):
        res = toolsm.invoke("scan", {}, requested_by="test")
        self._is_validation(res, param="scanner")
        res = toolsm.invoke("lookup_threat_intel", {"kind": "ip"},
                            requested_by="test")
        self._is_validation(res, param="value")

    def test_non_dict_params_rejected(self):
        res = toolsm.invoke("get_alerts", ["limit", 5],
                            requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "validation")

    def test_non_lan_target_rejected(self):
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target_ip": "8.8.8.8"},
                            requested_by="test")
        self._is_validation(res, param="target_ip")
        self.assertIn("LAN", res["error"])

    def test_non_inventory_target_rejected(self):
        # 192.168.1.99 is a LAN address but NOT in the (mocked)
        # inventory -- refused.
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target_ip": OTHER_IP},
                            requested_by="test")
        self._is_validation(res, param="target_ip")
        self.assertIn("inventory", res["error"])

    def test_malformed_ip_rejected(self):
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target_ip": "not-an-ip"},
                            requested_by="test")
        self._is_validation(res, param="target_ip")

    def test_shell_metachars_in_target_rejected(self):
        res = toolsm.invoke(
            "scan", {"scanner": "self",
                     "target_ip": "192.168.1.1; rm -rf /"},
            requested_by="test")
        self._is_validation(res, param="target_ip")

    def test_nuclei_rejects_target_ip(self):
        res = toolsm.invoke("scan", {"scanner": "nuclei",
                                     "target_ip": FAKE_IP},
                            requested_by="test")
        self._is_validation(res)

    def test_amass_rejects_target_ip(self):
        res = toolsm.invoke("scan", {"scanner": "amass",
                                     "target_ip": FAKE_IP},
                            requested_by="test")
        self._is_validation(res)

    def test_alert_kind_scope(self):
        res = toolsm.invoke("get_alerts", {"kind": "port_scan"},
                            requested_by="test")
        self.assertTrue(res["ok"], res)
        # SQL-injection-shaped kind is rejected by the scope check.
        res = toolsm.invoke("get_alerts", {"kind": "x' OR '1'='1"},
                            requested_by="test")
        self._is_validation(res, param="kind")

    def test_intel_ip_scope(self):
        res = toolsm.invoke(
            "lookup_threat_intel",
            {"kind": "ip", "value": "999.1.1.1"}, requested_by="test")
        self._is_validation(res)
        res = toolsm.invoke(
            "lookup_threat_intel",
            {"kind": "domain", "value": "evil.com; rm -rf /"},
            requested_by="test")
        self._is_validation(res)

    def test_intel_good_values_pass_shape(self):
        # Shape validation passes for well-formed values (the lookup
        # itself runs against local feeds).
        res = toolsm.invoke(
            "lookup_threat_intel",
            {"kind": "domain", "value": "example.com"},
            requested_by="test")
        self.assertTrue(res["ok"], res)
        self.assertEqual(res["result"]["kind"], "domain")

    def test_overlong_string_rejected(self):
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target_ip": "x" * 300},
                            requested_by="test")
        self._is_validation(res, param="target_ip")


# --- trust boundary: rejected proposals never execute --------------------------

class TrustBoundaryTests(_DbTest):
    def setUp(self):
        super().setUp()
        self.tripwired = []
        import netmon.scan as scanm
        import netmon.nuclei as nucleim
        import netmon.amass as amassm
        self._mods = []
        for mod, names in ((scanm, ["run_scan", "scan_device"]),
                           (nucleim, ["run_scan"]),
                           (amassm, ["run_enum"])):
            for n in names:
                old = getattr(mod, n)
                self._mods.append((mod, n, old))

                def _trip(*a, _n=n, **k):
                    self.tripwired.append(_n)
                    raise AssertionError(
                        f"{_n} must never execute on a rejected call")
                setattr(mod, n, _trip)

    def tearDown(self):
        for mod, n, old in self._mods:
            setattr(mod, n, old)
        super().tearDown()

    def test_malicious_scan_proposal_rejected_not_executed(self):
        # The task's exact case: model tries to point the scanner at
        # "external". Validation rejects; nothing runs.
        res = toolsm.invoke("scan", {"target": "external"},
                            requested_by="ai_analyst")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "validation")
        self.assertEqual(self.tripwired, [])

    def test_external_ip_proposal_rejected_not_executed(self):
        res = toolsm.invoke("scan", {"scanner": "self",
                                     "target_ip": "203.0.113.5"},
                            requested_by="ai_analyst")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "validation")
        self.assertEqual(self.tripwired, [])

    def test_unknown_tool_never_executes(self):
        res = toolsm.invoke("exec", {"cmd": "id"}, requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "validation")
        self.assertEqual(self.tripwired, [])


# --- timeouts ------------------------------------------------------------------

class TimeoutTests(_DbTest):
    def test_sleeping_tool_times_out(self):
        spec = toolsm.ToolSpec(
            name="__test_sleep", description="sleeps",
            timeout_s=1, idempotent=True,
            handler=lambda p: time.sleep(30))
        toolsm.register_tool(spec)
        try:
            started = time.time()
            res = toolsm.invoke("__test_sleep", {}, requested_by="test")
            elapsed = time.time() - started
        finally:
            toolsm.unregister_tool("__test_sleep")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "timeout")
        self.assertIn("timed out", res["error"])
        # The invocation is killed (returns) long before the 30s sleep.
        self.assertLess(elapsed, 10,
                        f"timeout not enforced: took {elapsed:.1f}s")
        self.assertIn("retry_hint", res)

    def test_fast_tool_completes(self):
        res = toolsm.invoke("get_pipeline_health", {},
                            requested_by="test")
        self.assertTrue(res["ok"], res)
        self.assertIn("stages", res["result"])


# --- error recovery --------------------------------------------------------------

class ErrorRecoveryTests(_DbTest):
    def _register(self, name, handler, idempotent=True):
        spec = toolsm.ToolSpec(
            name=name, description="throwaway", timeout_s=10,
            idempotent=idempotent, handler=handler)
        toolsm.register_tool(spec)
        self.addCleanup(toolsm.unregister_tool, name)
        return spec

    def test_structured_error_shape(self):
        def _boom(p):
            raise RuntimeError("boom happened")
        self._register("__test_boom", _boom, idempotent=True)
        res = toolsm.invoke("__test_boom", {}, requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(res["error_kind"], "execution")
        self.assertEqual(res["tool"], "__test_boom")
        self.assertIn("boom happened", res["error"])
        self.assertNotIn("Traceback", res["error"])
        self.assertNotIn("tools.py", res["error"])
        self.assertIn("retry", res["retry_hint"].lower())

    def test_idempotent_retries_once_on_transient(self):
        calls = []

        def _flaky(p):
            calls.append(1)
            if len(calls) == 1:
                raise RuntimeError("database is locked")
            return {"recovered": True}
        self._register("__test_flaky", _flaky, idempotent=True)
        res = toolsm.invoke("__test_flaky", {}, requested_by="test")
        self.assertTrue(res["ok"], res)
        self.assertEqual(len(calls), 2)
        self.assertTrue(res["result"]["recovered"])

    def test_non_idempotent_never_retries(self):
        calls = []

        def _flaky(p):
            calls.append(1)
            raise RuntimeError("database is locked")
        self._register("__test_flaky2", _flaky, idempotent=False)
        res = toolsm.invoke("__test_flaky2", {}, requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(len(calls), 1)
        self.assertIn("do not retry", res["retry_hint"].lower())

    def test_permanent_failure_does_not_retry(self):
        calls = []

        def _perm(p):
            calls.append(1)
            raise RuntimeError("permanent failure: no such table")
        self._register("__test_perm", _perm, idempotent=True)
        res = toolsm.invoke("__test_perm", {}, requested_by="test")
        self.assertFalse(res["ok"])
        self.assertEqual(len(calls), 1)


# --- audit log ---------------------------------------------------------------------

class AuditTests(_DbTest):
    def _tool_calls(self):
        return [e for e in dbm.list_audit(limit=200)
                if e.get("action") == "tool_call"]

    def test_success_is_audited(self):
        before = len(self._tool_calls())
        res = toolsm.invoke("get_alerts", {"limit": 3},
                            requested_by="ai_analyst")
        self.assertTrue(res["ok"])
        rows = self._tool_calls()
        self.assertEqual(len(rows), before + 1)
        row = rows[0]  # newest first
        self.assertEqual(row["actor"], "ai_analyst")
        self.assertEqual(row["target"], "get_alerts")
        self.assertIn("ok", row["detail"])

    def test_validation_rejection_is_audited(self):
        before = len(self._tool_calls())
        res = toolsm.invoke("scan", {"target": "external"},
                            requested_by="ai_analyst")
        self.assertFalse(res["ok"])
        rows = self._tool_calls()
        self.assertEqual(len(rows), before + 1)
        self.assertEqual(rows[0]["target"], "scan")
        self.assertIn("validation", rows[0]["detail"])

    def test_unknown_tool_is_audited(self):
        before = len(self._tool_calls())
        toolsm.invoke("quarantine", {}, requested_by="evil-model")
        rows = self._tool_calls()
        self.assertEqual(len(rows), before + 1)
        self.assertEqual(rows[0]["actor"], "evil-model")

    def test_recent_tool_calls_helper(self):
        toolsm.invoke("get_alerts", {}, requested_by="ai_analyst")
        toolsm.invoke("scan", {"target": "external"},
                      requested_by="ai_analyst")
        recent = dbm.recent_tool_calls(limit=3)
        self.assertEqual(len(recent), 2)
        # Newest first.
        self.assertEqual(recent[0]["tool"], "scan")
        self.assertIn("validation", recent[0]["outcome"])
        self.assertEqual(recent[1]["tool"], "get_alerts")
        self.assertIn("ok", recent[1]["outcome"])

    def test_escalation_bundle_sees_tool_calls(self):
        aid = self._seed_alert(kind="port_scan", severity="High",
                               title="bundle probe",
                               detail="from 192.168.1.50")
        toolsm.invoke("get_alerts", {"limit": 1},
                      requested_by="ai_analyst")
        case = dbm.get_incident(dbm.query(
            "SELECT incident_id FROM incident_alerts WHERE alert_id=?",
            (aid,))[0][0])
        tried = dbm.incident_what_was_tried(case["id"])
        self.assertTrue(
            any("AI analyst ran 'get_alerts'" in t for t in tried),
            f"tool call missing from what_tried: {tried}")


# --- quiet is a feature --------------------------------------------------------------

class QuietTests(_DbTest):
    def test_read_tools_create_no_alerts(self):
        self._seed_alert()
        before = self._alert_count()
        for name, params in (
                ("get_alerts", {"limit": 5}),
                ("get_incidents", {}),
                ("get_devices", {}),
                ("get_scan_status", {}),
                ("get_pipeline_health", {}),
                ("lookup_threat_intel",
                 {"kind": "domain", "value": "example.com"})):
            res = toolsm.invoke(name, params, requested_by="test")
            self.assertTrue(res["ok"], (name, res))
        self.assertEqual(self._alert_count(), before)

    def test_scan_tool_writes_nothing(self):
        import netmon.scan as scanm
        old_run_scan = scanm.run_scan
        old_device = scanm.scan_device
        scanm.run_scan = lambda *a, **k: {FAKE_IP: {23, 80}}
        scanm.scan_device = lambda ip, **k: {80} if ip == FAKE_IP else set()
        try:
            before = self._alert_count()
            res = toolsm.invoke("scan", {"scanner": "self"},
                                requested_by="test")
            self.assertTrue(res["ok"], res)
            self.assertEqual(res["result"]["targets_scanned"], 1)
            res = toolsm.invoke("scan", {"scanner": "self",
                                         "target_ip": FAKE_IP},
                                requested_by="test")
            self.assertTrue(res["ok"], res)
            self.assertEqual(
                res["result"]["results"][FAKE_IP][0]["port"], 80)
            # No alerts, no scan-run rows, no findings stored: the tool
            # scan is ephemeral -- the scheduled pipeline is untouched.
            self.assertEqual(self._alert_count(), before)
            self.assertIsNone(dbm.latest_scan_run())
            self.assertEqual(dbm.list_scan_findings(limit=10), [])
        finally:
            scanm.run_scan = old_run_scan
            scanm.scan_device = old_device


# --- /ask wiring ---------------------------------------------------------------------

class AskWiringTests(_DbTest):
    def setUp(self):
        super().setUp()
        self._old_client = assistm._client
        self._old_json_chat = assistm._json_chat
        assistm._client = lambda: object()  # fake: model "available"
        self.scripts = []
        self.calls = []

        def _fake_chat(client, prompt, max_tokens=400):
            self.calls.append(prompt)
            return self.scripts.pop(0)

        assistm._json_chat = _fake_chat

    def tearDown(self):
        assistm._client = self._old_client
        assistm._json_chat = self._old_json_chat
        super().tearDown()

    def test_tool_round_trip(self):
        self._seed_alert(title="round-trip probe")
        self.scripts = [
            {"tool_calls": [{"tool": "get_alerts",
                             "params": {"limit": 2}}]},
            {"answer": "One high alert, looks routine."},
        ]
        ans = assistm.answer_question("anything happening?")
        self.assertEqual(ans, {"answer": "One high alert, looks routine."})
        # The tool actually ran through the registry...
        rows = [e for e in dbm.list_audit(limit=50)
                if e.get("action") == "tool_call"
                and e.get("target") == "get_alerts"]
        self.assertTrue(rows)
        self.assertEqual(rows[0]["actor"], "ai_analyst")
        # ...and its results reached the second prompt as data.
        self.assertIn("TOOL RESULTS", self.calls[1])
        self.assertIn("round-trip probe", self.calls[1])

    def test_malicious_proposal_rejected_mid_loop(self):
        import netmon.scan as scanm
        old = scanm.run_scan
        scanm.run_scan = lambda *a, **k: (_ for _ in ()).throw(
            AssertionError("must not execute"))
        try:
            self.scripts = [
                {"tool_calls": [{"tool": "scan",
                                 "params": {"target": "external"}}]},
                {"answer": "I could not run that scan."},
            ]
            ans = assistm.answer_question("scan the internet")
            self.assertEqual(ans, {"answer": "I could not run that scan."})
            # The rejection itself is in the tool results, so the model
            # sees the error and can self-correct.
            self.assertIn("unknown parameter", self.calls[1])
        finally:
            scanm.run_scan = old

    def test_tool_budget_is_bounded(self):
        self.scripts = [
            {"tool_calls": [{"tool": "get_alerts",
                             "params": {"limit": 1}}]},
            {"tool_calls": [{"tool": "get_alerts",
                             "params": {"limit": 1}}]},
            {"answer": "final answer after budget spent"},
        ]
        ans = assistm.answer_question("keep digging")
        self.assertEqual(
            ans, {"answer": "final answer after budget spent"})
        # 2 tool rounds + 1 final answer-only round.
        self.assertEqual(len(self.calls), 3)

    def test_malformed_tool_calls_shape_rejected(self):
        self.scripts = [{"tool_calls": "not-a-list"}]
        self.assertIsNone(assistm.answer_question("hi"))

    def test_plain_answer_still_works(self):
        self.scripts = [{"answer": "All quiet tonight."}]
        ans = assistm.answer_question("anything?")
        self.assertEqual(ans, {"answer": "All quiet tonight."})
        self.assertEqual(len(self.calls), 1)


# --- debug CLI -------------------------------------------------------------------------

class CliTests(unittest.TestCase):
    def _run(self, *args):
        return subprocess.run(
            [sys.executable, "-m", "netmon.tools", *args],
            cwd=REPO, capture_output=True, text=True, timeout=60)

    def test_list(self):
        p = self._run("--list")
        self.assertEqual(p.returncode, 0, p.stderr)
        for name in ("get_alerts", "get_incidents", "get_devices",
                     "get_scan_status", "scan", "lookup_threat_intel",
                     "get_pipeline_health"):
            self.assertIn(name, p.stdout)

    def test_describe(self):
        p = self._run("--describe", "scan")
        self.assertEqual(p.returncode, 0, p.stderr)
        data = json.loads(p.stdout)
        self.assertEqual(data["name"], "scan")
        self.assertIn("scanner", data["params"])
        self.assertIn("target_ip", data["params"])

    def test_describe_unknown(self):
        p = self._run("--describe", "quarantine")
        self.assertEqual(p.returncode, 2)


if __name__ == "__main__":
    unittest.main()
