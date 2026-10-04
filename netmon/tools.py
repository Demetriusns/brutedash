"""netmon/tools.py -- MCP-style tool server for the AI analyst.

Repo-learning item 6 (HexStrike AI pattern, MIT -- see attribution below):
a tool registry with schemas + process management + error recovery, so
the AI analyst can invoke tools (scan status, threat-intel lookups,
inventory-scoped scans) safely. We adopt the PATTERN only -- the
registry, the schemas, the bounded execution -- never HexStrike's
offensive tooling. Every tool here is read-only diagnostics, plus
inventory-scoped scan triggers that reuse the monitor's own validated
scan paths. There is deliberately no quarantine, no shell, no
network-exposed action, nothing the approval-only principle reserves
for the human.

Pattern attribution: inspired by 0x4m4/hexstrike-ai (MIT license) --
tool registry with typed schemas, process management, and error
recovery for AI-driven tool use. No HexStrike code is used or copied.

How it works ("AI narrates, code decides", made concrete):
  * The model NEVER gets raw subprocess access. It proposes tool calls
    as DATA -- {"tool": "name", "params": {...}} -- and the registry
    validates the name and every parameter against a declared schema
    BEFORE anything executes.
  * Validation covers types, ranges, enums, and target scoping: scan
    targets must be RFC1918/loopback AND members of the asset
    inventory; Amass never takes a model-supplied domain (its targets
    come only from config.yaml, same as the dashboard button).
  * Execution is bounded: every tool declares a timeout, the call runs
    on a worker thread, and an expired call returns a structured
    timeout error. Retries happen only for idempotent tools on
    transient failures, at most once.
  * Every invocation -- success, validation rejection, timeout, crash
    -- is audit-logged (who asked, what ran, what it returned) so the
    escalation bundle's "what the user already tried" stays honest.

ATTACK-SURFACE MAP (standing council rule -- entry points, trust
boundaries, injection points, attacker gains):

  Entry points:
    1. invoke() -- called with model-proposed data from ai_assist.py's
       /ask loop (requested_by="ai_analyst"), from the debug CLI below,
       and (future) from dashboard routes. The debug CLI is local-only.
    2. register_tool() -- import-time only in production; tests use it
       to register throwaway tools. A test-only tool is never
       registered outside a test process.
    3. The audit log (dbm.audit) -- append-only, read by the escalation
       bundle.

  Trust boundaries (the important one):
    * UNTRUSTED: everything the model proposes -- the tool name, every
      parameter value, the shape of the params object. Model output is
      treated as hostile input to the registry: unknown tools,
      unknown/untyped/out-of-range parameters, and out-of-scope
      targets are rejected with structured errors and NOTHING runs.
    * TRUSTED: the registry schemas, the handler code, and values that
      code derives itself -- scan targets from scan_targets() (the
      asset inventory), Amass domains from config.yaml, SQL built only
      from fixed strings with ? placeholders.
    * The boundary is drawn inside invoke(): validation happens first,
      on the untrusted side; only schema-clean values cross into
      execution. Prompt text from the model is NEVER interpolated into
      SQL (all queries are parameterized), NEVER passed to a shell
      (no shell=True / os.system anywhere in this module -- there is a
      source-inspection test enforcing it), and NEVER used as a file
      path or email address.

  Injection points reviewed:
    * Tool name -> exact dict lookup, no fuzzy matching, no dynamic
      import. {"tool": "quarantine"} is an unknown-tool rejection.
    * Params -> per-parameter type/range/enum/scope checks. Extra keys
      are rejected, not ignored: {"tool": "scan", "target": "external"}
      fails on the unknown parameter "target" before anything runs.
      (There is a test proving exactly this case never executes.)
    * IP-valued params -> must parse as an IP AND pass scan._ok_target
      (explicit RFC1918/loopback ranges) AND be a member of the
      inventory for scan targets.
    * Domain-valued params -> strict hostname shape (amass.valid_domain)
      for threat-intel lookups; Amass scans take no domain parameter
      at all.
    * Error messages back to the model are useful but minimal: which
      parameter, what was expected. No tracebacks, no file paths, no
      SQL, no internals.

  If the model is compromised (prompt-injected via alert text or a
  hostile question), what does the attacker gain?
    * Read access to the monitor's own diagnostics -- alerts, cases,
      device inventory, scan status, local threat-intel hits, pipeline
      health. All of this is already visible on the password-gated
      dashboard; the tool server does not widen the read audience, it
      only lets the model summarize it.
    * The ability to trigger the same inventory-scoped scans the
      dashboard's own buttons trigger (self port scan of LAN devices,
      Nuclei against inventory targets, Amass against configured
      domains). Scans run QUIET: findings are returned as data to the
      model and never written to the monitor's tables, so a
      tool-triggered scan cannot fire alerts or poison the scheduled
      scans' baselines. Scans can never be pointed elsewhere -- the
      target scoping above is enforced in validation AND re-checked
      inside build_argv/scan_device.
    * They do NOT gain: state changes (no quarantine, no dismissals,
      no config writes -- those live behind dashboard routes and the
      human), shell access, network egress beyond what the scans
      already do on schedule, or the ability to reach another network.

  Known limitation (documented, not hidden): CPython cannot kill a
  thread. A timed-out tool call is abandoned as a daemon thread -- the
  CALLER gets its timeout error on time, but the worker finishes on
  its own. Subprocess-backed scans carry their own internal timeouts
  (see nuclei.SUBPROC_TIMEOUT_S / amass.SUBPROC_TIMEOUT_S), so an
  abandoned scan still ends. This is why scan timeouts are generous
  and scan results are capped.

Stdlib only. Nothing here alerts -- quiet is a feature: tool
invocations never call dbm.add_alert.
"""
import argparse
import json
import shutil
import threading
import time
from dataclasses import dataclass, field

from . import db as dbm

# ---------------------------------------------------------------------------
# Schema primitives
# ---------------------------------------------------------------------------

# Parameter types. "enum" needs enum_values; the scope checks below apply
# on top of the type check for "str" params.
PTYPE_INT = "int"
PTYPE_STR = "str"
PTYPE_BOOL = "bool"
PTYPE_ENUM = "enum"

# Scopes: extra validation for string params beyond type/range.
SCOPE_LAN_IP = "lan_ip"            # parses as IP + RFC1918/loopback
SCOPE_INVENTORY_IP = "inventory_ip"  # lan_ip + member of the asset inventory
SCOPE_ALERT_KIND = "alert_kind"    # one of the detection catalog's rule ids
SCOPE_DOMAIN = "domain"            # strict hostname shape
SCOPE_IP = "ip"                    # parses as an IP address (any scope)

_MAX_PARAM_LEN = 256       # hard cap on any string parameter
_MAX_AUDIT_DETAIL = 500    # audit rows stay small
_MAX_RESULT_LIST = 50      # per-list cap in tool results (model payloads)


@dataclass
class ParamSpec:
    """One declared parameter: type, requirement, bounds, scope."""
    ptype: str                       # int | str | bool | enum
    required: bool = False
    default: object = None
    min: object = None               # int params: inclusive lower bound
    max: object = None               # int params: inclusive upper bound
    enum_values: tuple = ()          # enum params: allowed values (exact)
    max_len: int = _MAX_PARAM_LEN    # str params
    scope: str = None                # lan_ip | inventory_ip | alert_kind
                                     # | domain | ip | None
    description: str = ""


@dataclass
class ToolSpec:
    """One registered tool: schema + execution policy + handler."""
    name: str
    description: str
    params: dict = field(default_factory=dict)  # name -> ParamSpec
    timeout_s: float = 30.0
    idempotent: bool = True          # safe to retry on transient failure
    handler: object = None           # fn(clean_params) -> JSON-able result
    extra: object = None             # fn(clean_params) -> error str | None
                                     # cross-parameter validation


_REGISTRY = {}


def register_tool(spec):
    """Register a tool spec. Explicit only -- no auto-discovery.

    Returns the spec (usable as a decorator). Re-registering a name
    replaces it; production tools are registered once at import.
    """
    if not isinstance(spec, ToolSpec) or not spec.name:
        raise ValueError("register_tool needs a ToolSpec with a name")
    if not callable(spec.handler):
        raise ValueError(f"tool {spec.name!r} has no callable handler")
    _REGISTRY[spec.name] = spec
    return spec


def unregister_tool(name):
    """Remove a registration. Used by tests for throwaway tools."""
    _REGISTRY.pop(name, None)


def get_tool(name):
    """The ToolSpec for `name`, or None."""
    return _REGISTRY.get(name)


def list_tools():
    """[{name, description, params, timeout_s, idempotent}] for every
    registered tool. Params render as {name: {type, required, default,
    enum/min/max/scope, description}} -- this is what the model sees."""
    out = []
    for spec in _REGISTRY.values():
        params = {}
        for pname, ps in spec.params.items():
            d = {"type": ps.ptype, "required": ps.required,
                 "description": ps.description}
            if not ps.required:
                d["default"] = ps.default
            if ps.ptype == PTYPE_ENUM:
                d["allowed"] = list(ps.enum_values)
            if ps.ptype == PTYPE_INT:
                if ps.min is not None:
                    d["min"] = ps.min
                if ps.max is not None:
                    d["max"] = ps.max
            if ps.scope:
                d["scope"] = ps.scope
            params[pname] = d
        out.append({"name": spec.name, "description": spec.description,
                    "params": params, "timeout_s": spec.timeout_s,
                    "idempotent": spec.idempotent})
    return out


# ---------------------------------------------------------------------------
# Validation: untrusted model data -> clean params, or a loud error
# ---------------------------------------------------------------------------

class ToolValidationError(Exception):
    """A proposed call failed schema validation. Carries structured
    detail for the model: which parameter, what was expected."""
    def __init__(self, message, param=None, expected=None):
        super().__init__(message)
        self.param = param
        self.expected = expected


def _scope_check(scope, value):
    """Scope validation for string params. Returns an error string or
    None. Never raises."""
    try:
        if scope == SCOPE_IP:
            import ipaddress
            try:
                ipaddress.ip_address(value)
                return None
            except ValueError:
                return f"{value!r} is not a valid IP address"
        if scope == SCOPE_DOMAIN:
            from . import amass as amassm
            if amassm.valid_domain(value):
                return None
            return (f"{value!r} is not a valid domain name")
        if scope in (SCOPE_LAN_IP, SCOPE_INVENTORY_IP):
            from . import scan as scanm
            if not scanm._ok_target(value):
                return (f"{value!r} is not a LAN address -- scans only"
                        f" ever target this network (RFC1918/loopback)")
            if scope == SCOPE_INVENTORY_IP:
                if value not in _inventory_ips():
                    return (f"{value!r} is not a known device on this"
                            f" network -- scans only target the asset"
                            f" inventory")
            return None
        if scope == SCOPE_ALERT_KIND:
            from . import detection_catalog as catm
            ids = {r.get("id") for r in catm.RULES}
            if value in ids:
                return None
            return (f"unknown alert kind {value!r} -- must be one of the"
                    f" monitor's detection rules")
    except ToolValidationError:
        raise
    except Exception as exc:
        return f"could not validate {value!r}: {exc}"
    return f"unknown scope {scope!r}"


def _validate_params(spec, params):
    """Validate a proposed params object against the spec.

    Returns the cleaned params dict. Raises ToolValidationError --
    loud and structured, never silent. `params` must be a dict; unknown
    keys are rejected (a model inventing parameter names is a signal,
    not something to ignore).
    """
    if not isinstance(params, dict):
        raise ToolValidationError(
            f"params for tool {spec.name!r} must be an object, got"
            f" {type(params).__name__}",
            expected="an object like {\"limit\": 20}")
    unknown = [k for k in params if k not in spec.params]
    if unknown:
        raise ToolValidationError(
            f"unknown parameter(s) {unknown} for tool {spec.name!r}."
            f" Known parameters: {sorted(spec.params)}",
            param=unknown[0],
            expected=f"one of {sorted(spec.params)}")
    clean = {}
    for pname, ps in spec.params.items():
        if pname not in params:
            if ps.required:
                raise ToolValidationError(
                    f"missing required parameter {pname!r} for tool"
                    f" {spec.name!r}",
                    param=pname, expected=f"a {ps.ptype}")
            clean[pname] = ps.default
            continue
        value = params[pname]
        if ps.ptype == PTYPE_INT:
            if isinstance(value, bool) or not isinstance(value, int):
                raise ToolValidationError(
                    f"parameter {pname!r} must be an integer, got"
                    f" {value!r}",
                    param=pname, expected="an integer")
            if ps.min is not None and value < ps.min:
                raise ToolValidationError(
                    f"parameter {pname!r} must be >= {ps.min}, got"
                    f" {value}",
                    param=pname, expected=f">= {ps.min}")
            if ps.max is not None and value > ps.max:
                raise ToolValidationError(
                    f"parameter {pname!r} must be <= {ps.max}, got"
                    f" {value}",
                    param=pname, expected=f"<= {ps.max}")
            clean[pname] = value
        elif ps.ptype == PTYPE_BOOL:
            if type(value) is not bool:
                raise ToolValidationError(
                    f"parameter {pname!r} must be true/false, got"
                    f" {value!r}",
                    param=pname, expected="true or false")
            clean[pname] = value
        elif ps.ptype == PTYPE_ENUM:
            if value not in ps.enum_values:
                raise ToolValidationError(
                    f"parameter {pname!r} must be one of"
                    f" {list(ps.enum_values)}, got {value!r}",
                    param=pname,
                    expected=f"one of {list(ps.enum_values)}")
            clean[pname] = value
        else:  # PTYPE_STR
            if not isinstance(value, str):
                raise ToolValidationError(
                    f"parameter {pname!r} must be a string, got"
                    f" {type(value).__name__}",
                    param=pname, expected="a string")
            if len(value) > ps.max_len:
                raise ToolValidationError(
                    f"parameter {pname!r} is too long"
                    f" ({len(value)} > {ps.max_len} chars)",
                    param=pname,
                    expected=f"at most {ps.max_len} characters")
            value = value.strip()
            if ps.scope:
                err = _scope_check(ps.scope, value)
                if err:
                    raise ToolValidationError(
                        f"parameter {pname!r}: {err}",
                        param=pname, expected=f"a valid {ps.scope}")
            clean[pname] = value
    if spec.extra:
        err = spec.extra(clean)
        if err:
            raise ToolValidationError(err, expected="consistent params")
    return clean


def _inventory_ips():
    """Current scan-target inventory: LAN IPs we discovered ourselves.

    Tests monkeypatch this for a controlled inventory; production reads
    the real asset inventory via scan.scan_targets().
    """
    try:
        from . import scan as scanm
        return set(scanm.scan_targets())
    except Exception:
        return set()


# ---------------------------------------------------------------------------
# Execution: bounded, structured errors, audit-logged
# ---------------------------------------------------------------------------

_TRANSIENT_HINTS = ("locked", "timeout", "timed out", "temporary",
                    "try again", "busy")


def _looks_transient(message):
    msg = str(message or "").lower()
    return any(h in msg for h in _TRANSIENT_HINTS)


def _jsonable(value, _depth=0):
    """Coerce a handler result to JSON-safe data. Never raises."""
    if _depth > 12:
        return "[nested too deep]"
    if value is None or isinstance(value, (bool, int, str)):
        return value
    if isinstance(value, float):
        return value if value == value and abs(value) != float("inf") \
            else str(value)
    if isinstance(value, dict):
        return {str(k): _jsonable(v, _depth + 1)
                for k, v in list(value.items())[:500]}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v, _depth + 1) for v in value[:500]]
    return str(value)[:2000]


def _safe_params_summary(params):
    """Short params summary for audit rows. Never raises -- falls back
    to a type name when the value is not JSON-serializable (only
    possible via programmatic misuse; model input is always JSON)."""
    try:
        if isinstance(params, dict):
            return json.dumps(params)[:200]
        return type(params).__name__
    except Exception:
        try:
            return repr(params)[:200]
        except Exception:
            return "?"


def _audit(requested_by, tool_name, detail):
    """Append one audit row for a tool invocation. Never raises -- a
    broken audit trail must not break the tool call it records."""
    try:
        dbm.audit("tool_call", (requested_by or "")[:64],
                  str(tool_name or "")[:64],
                  str(detail or "")[:_MAX_AUDIT_DETAIL])
    except Exception:
        pass


def _invoke_once(spec, clean, timeout_s):
    """Run the handler on a daemon thread, bounded by timeout_s.

    Returns (ok, payload, duration_s) where payload is the result or a
    (kind, message) pair. The timeout abandons the worker thread --
    CPython cannot kill threads (documented limitation); subprocess
    tools carry their own internal timeouts.
    """
    box = {}
    started = time.time()

    def _worker():
        try:
            box["result"] = spec.handler(clean)
        except Exception as exc:  # noqa: BLE001 -- converted below
            box["error"] = exc

    t = threading.Thread(target=_worker, daemon=True,
                         name=f"tool-{spec.name}")
    t.start()
    t.join(timeout_s)
    duration = time.time() - started
    if t.is_alive():
        return False, ("timeout",
                       f"tool {spec.name!r} timed out after"
                       f" {timeout_s:g}s"), duration
    if "error" in box:
        return False, ("execution", box["error"]), duration
    return True, ("ok", _jsonable(box.get("result"))), duration


def _retry_hint(spec, error_kind):
    if error_kind == "validation":
        return ("fix the parameters per the error and retry -- the call"
                " never executed")
    if error_kind == "timeout":
        if spec.idempotent:
            return ("safe to retry once; if it keeps timing out, the"
                    " underlying job may still be running")
        return ("do not retry automatically -- the underlying job may"
                " still be running; check status first")
    # execution
    if spec.idempotent:
        return "safe to retry -- this tool only reads data"
    return ("do not retry automatically -- this tool triggers real"
            " work; check status first")


def invoke(tool_name, params=None, requested_by="dashboard"):
    """Validate and execute one tool call.

    tool_name/params are UNTRUSTED model-proposed data: the name must
    match a registered tool exactly and params must satisfy the schema
    before anything runs. Returns a structured dict, always:

      {"ok": True, "tool": name, "result": {...}, "duration_s": float}
      {"ok": False, "tool": name|None, "error_kind":
       "validation"|"timeout"|"execution", "error": str,
       "retry_hint": str, ["param": ..., "expected": ...]}

    Error messages are useful but minimal -- which parameter and what
    was expected, never tracebacks or internals. Every invocation is
    audit-logged. Never raises.
    """
    req = requested_by or "dashboard"
    name = tool_name if isinstance(tool_name, str) else None
    spec = get_tool(name) if name else None
    if spec is None:
        known = sorted(_REGISTRY)
        err = (f"unknown tool {tool_name!r}."
               f" Known tools: {known}" if known
               else f"unknown tool {tool_name!r} (no tools registered)")
        _audit(req, tool_name,
               f"params={_safe_params_summary(params)}"
               f" -> rejected: {err[:200]}")
        return {"ok": False, "tool": None, "error_kind": "validation",
                "error": err,
                "retry_hint": "use one of the known tools"}
    try:
        clean = _validate_params(spec, params or {})
    except ToolValidationError as exc:
        detail = (f"params={_safe_params_summary(params)}"
                  f" -> validation rejected: {exc}"[:_MAX_AUDIT_DETAIL])
        _audit(req, spec.name, detail)
        out = {"ok": False, "tool": spec.name,
               "error_kind": "validation", "error": str(exc),
               "retry_hint": _retry_hint(spec, "validation")}
        if exc.param:
            out["param"] = exc.param
        if exc.expected:
            out["expected"] = exc.expected
        return out

    # Bounded execution with one retry for idempotent tools on
    # transient failures only. Validation and timeout errors never
    # retry; non-idempotent tools never auto-retry.
    attempts = 2 if spec.idempotent else 1
    last = None
    for attempt in range(attempts):
        ok, (kind, payload), duration = _invoke_once(
            spec, clean, spec.timeout_s)
        if ok:
            _audit(req, spec.name,
                   f"params={_safe_params_summary(clean)}"
                   f" -> ok in {duration:.2f}s")
            return {"ok": True, "tool": spec.name, "result": payload,
                    "duration_s": round(duration, 3)}
        if kind == "timeout":
            _audit(req, spec.name,
                   f"params={_safe_params_summary(clean)}"
                   f" -> timeout after {spec.timeout_s:g}s")
            return {"ok": False, "tool": spec.name,
                    "error_kind": "timeout",
                    "error": payload,
                    "retry_hint": _retry_hint(spec, "timeout")}
        # execution error
        msg = f"{type(payload).__name__}: {payload}"[:300]
        transient = _looks_transient(msg)
        if transient and attempt + 1 < attempts:
            time.sleep(0.2)
            continue
        _audit(req, spec.name,
               f"params={_safe_params_summary(clean)}"
               f" -> execution error: {msg[:200]}")
        last = {"ok": False, "tool": spec.name,
                "error_kind": "execution", "error": msg,
                "retry_hint": _retry_hint(spec, "execution")}
        break
    return last


# ---------------------------------------------------------------------------
# Built-in tools: read-only diagnostics + inventory-scoped scans
# ---------------------------------------------------------------------------

_SEVERITIES = ("Critical", "High", "Medium", "Low")
_INCIDENT_STATUSES = ("open", "closed", "escalated")
_SCANNERS = ("self", "nuclei", "amass")
_INTEL_KINDS = ("ip", "domain")


def _tool_get_alerts(p):
    """Recent alerts, newest first. Read-only."""
    since = time.time() - p["hours"] * 3600
    sql = ("SELECT id, ts, severity, kind, title, detail FROM alerts"
           " WHERE ts > ?")
    args = [since]
    if p["severity"]:
        sql += " AND severity = ?"
        args.append(p["severity"])
    if p["kind"]:
        sql += " AND kind = ?"
        args.append(p["kind"])
    sql += " ORDER BY ts DESC LIMIT ?"
    args.append(p["limit"])
    rows = dbm.query(sql, tuple(args))
    return {"alerts": [
        {"id": r[0], "ts": r[1], "severity": r[2], "kind": r[3],
         "title": r[4], "detail": (r[5] or "")[:500]} for r in rows],
        "count": len(rows)}


register_tool(ToolSpec(
    name="get_alerts",
    description=("Recent monitor alerts, newest first. Use to see what"
                 " the monitor has flagged lately."),
    params={
        "severity": ParamSpec(PTYPE_ENUM, enum_values=_SEVERITIES,
                              description="only this urgency level"),
        "kind": ParamSpec(PTYPE_STR, scope=SCOPE_ALERT_KIND,
                          description="only this detection rule id"),
        "limit": ParamSpec(PTYPE_INT, default=20, min=1, max=100,
                           description="max alerts to return"),
        "hours": ParamSpec(PTYPE_INT, default=24, min=1, max=168,
                           description="look back this many hours"),
    },
    timeout_s=30, idempotent=True, handler=_tool_get_alerts))


def _tool_get_incidents(p):
    """Alert cases (incidents), newest activity first. Read-only."""
    rows = dbm.list_incidents(status=p["status"], limit=p["limit"])
    return {"incidents": [
        {"id": r["id"], "title": r["title"], "severity": r["severity"],
         "status": r["status"], "device": r["device_key"] or "",
         "alert_count": r["alert_count"],
         "updated_ts": r["updated_ts"]} for r in rows],
        "count": len(rows)}


register_tool(ToolSpec(
    name="get_incidents",
    description=("Alert cases (incidents) bundling related alerts, newest"
                 " activity first."),
    params={
        "status": ParamSpec(PTYPE_ENUM, default="open",
                            enum_values=_INCIDENT_STATUSES,
                            description="which cases to list"),
        "limit": ParamSpec(PTYPE_INT, default=10, min=1, max=50,
                           description="max cases to return"),
    },
    timeout_s=30, idempotent=True, handler=_tool_get_incidents))


def _tool_get_devices(p):
    """Device inventory. Read-only."""
    assets = dbm.get_assets()[:p["limit"]]
    return {"devices": [
        {"ip": a["ip"], "mac": a["mac"],
         "hostname": a["hostname"], "vendor": a["vendor"],
         "os_guess": a["os_guess"], "last_seen": a["last_seen"],
         "open_ports": a["open_ports"][:20]} for a in assets],
        "count": len(assets)}


register_tool(ToolSpec(
    name="get_devices",
    description=("Devices on the network from the asset inventory: IP,"
                 " MAC, hostname, vendor, last seen, known open ports."),
    params={
        "limit": ParamSpec(PTYPE_INT, default=50, min=1, max=100,
                           description="max devices to return"),
    },
    timeout_s=30, idempotent=True, handler=_tool_get_devices))


def _slim_run(run, keys):
    if not run:
        return None
    return {k: run.get(k) for k in keys if k in run}


def _tool_get_scan_status(_p):
    """Status of the three scanners. Read-only: binary presence, feature
    switches, last scheduled runs, open finding counts."""
    from . import scan as scanm
    from . import nuclei as nucleim
    from . import amass as amassm
    self_run = dbm.latest_scan_run()
    nuc_run = dbm.latest_nuclei_run()
    try:
        open_self = len(dbm.list_scan_findings(status="open", limit=500))
    except Exception:
        open_self = None
    try:
        open_nuc = len(dbm.list_nuclei_findings(status="open", limit=500))
    except Exception:
        open_nuc = None
    amass_runs = []
    try:
        for d in amassm.configured_domains():
            r = dbm.latest_amass_run(d)
            if r:
                amass_runs.append({"domain": d,
                                   **_slim_run(r, ("ts", "subdomains",
                                                   "ips", "note"))})
    except Exception:
        amass_runs = []
    return {
        "self": {
            "enabled": scanm._scan_enabled(),
            "running": dbm.get_meta("vuln_scan_running") == "1",
            "last_run": _slim_run(self_run, ("ts", "duration_s",
                                             "devices_scanned",
                                             "findings", "note")),
            "open_findings": open_self,
        },
        "nuclei": {
            "installed": bool(nucleim.find_binary()),
            "enabled": nucleim.nuclei_enabled(),
            "running": dbm.get_meta("nuclei_scan_running") == "1",
            "min_severity": nucleim.min_severity(),
            "last_run": _slim_run(nuc_run, ("ts", "duration_s",
                                            "targets", "findings",
                                            "new_findings", "note")),
            "open_findings": open_nuc,
        },
        "amass": {
            "installed": bool(amassm.find_binary()),
            "enabled": amassm.amass_enabled(),
            "domains": amassm.configured_domains(),
            "runs": amass_runs,
        },
    }


register_tool(ToolSpec(
    name="get_scan_status",
    description=("Status of the vulnerability scanners (self port scan,"
                 " Nuclei, Amass): installed/enabled, last scheduled run,"
                 " open finding counts. Read-only."),
    params={},
    timeout_s=60, idempotent=True, handler=_tool_get_scan_status))


def _scan_self(p):
    """Inventory-scoped port scan. Quiet by construction: uses the pure
    scan primitives (no finding storage, no alerts) and returns the
    results as data."""
    from . import scan as scanm
    target = p["target_ip"]
    services = dict(scanm.SCAN_PORTS)
    if target:
        open_ports = sorted(scanm.scan_device(target))
        return {"scanner": "self", "targets": [target],
                "results": {target: [
                    {"port": po, "service": services.get(po, "unknown")}
                    for po in open_ports]},
                "note": ("single-device scan; full-inventory scan when"
                         " target_ip is omitted")}
    results = scanm.run_scan()
    slim = {}
    for ip in sorted(results):
        slim[ip] = [{"port": po, "service": services.get(po, "unknown")}
                    for po in sorted(results[ip])][: _MAX_RESULT_LIST]
    return {"scanner": "self", "targets_scanned": len(slim),
            "results": slim,
            "note": ("inventory-wide scan of devices the monitor"
                     " discovered itself")}


def _scan_nuclei(_p):
    """Nuclei against inventory targets. Quiet: parses the JSONL and
    returns findings as data -- nothing is stored, no alerts fire, the
    scheduled scan's baseline is untouched."""
    from . import nuclei as nucleim
    targets = nucleim.nuclei_targets()
    if not targets:
        return {"scanner": "nuclei", "targets": [],
                "note": "no LAN targets discovered -- nothing scanned"}
    result = nucleim.run_scan(targets)
    work_dir = result.get("work_dir")
    try:
        if not result.get("ok"):
            return {"scanner": "nuclei", "targets": targets,
                    "error": result.get("error", "scan failed")}
        findings = nucleim.parse_jsonl_file(result["jsonl_path"])
        slim = [{"ip": f["ip"], "template_id": f["template_id"],
                 "name": f["name"], "severity": f["severity"],
                 "matched_at": f["matched_at"][:120],
                 "cves": f["cves"],
                 "description": f["description"][:200]}
                for f in findings[:_MAX_RESULT_LIST]]
        return {"scanner": "nuclei", "targets": targets,
                "findings": slim,
                "truncated": len(findings) > _MAX_RESULT_LIST,
                "version": result.get("version", "")}
    finally:
        if work_dir:
            shutil.rmtree(work_dir, ignore_errors=True)


def _scan_amass(_p):
    """Amass enum for configured domains only. Quiet: parses output and
    returns assets as data -- nothing stored, no alerts, no baseline
    changes."""
    from . import amass as amassm
    domains = amassm.configured_domains()
    if not domains:
        return {"scanner": "amass", "domains": [],
                "note": "no domains configured (amass.domains) --"
                        " nothing scanned"}
    out = []
    for domain in domains:
        result = amassm.run_enum(domain)
        work_dir = result.get("work_dir")
        try:
            if not result.get("ok"):
                out.append({"domain": domain,
                            "error": result.get("error", "scan failed")})
                continue
            assets = amassm.parse_jsonl_file(result["jsonl_path"])
            subs = sorted({a["name"] for a in assets})
            ips = sorted({ip for a in assets for ip in a["ips"]})
            out.append({
                "domain": domain,
                "subdomains": subs[:_MAX_RESULT_LIST],
                "subdomains_truncated": len(subs) > _MAX_RESULT_LIST,
                "ips": ips[:_MAX_RESULT_LIST],
                "asns": sorted({a for a in assets for a in a["asns"]}),
                "version": result.get("version", ""),
            })
        finally:
            if work_dir:
                shutil.rmtree(work_dir, ignore_errors=True)
    return {"scanner": "amass", "domains": out}


def _tool_scan(p):
    scanner = p["scanner"]
    if scanner == "self":
        return _scan_self(p)
    if scanner == "nuclei":
        return _scan_nuclei(p)
    return _scan_amass(p)


def _scan_extra(clean):
    """Cross-parameter rules: target_ip only makes sense for the self
    scanner (one device); nuclei runs inventory-wide and Amass scans
    configured domains -- neither takes a model-supplied target."""
    if clean.get("target_ip"):
        if clean.get("scanner") == "nuclei":
            return ("target_ip is only valid with scanner='self' -- the"
                    " nuclei scan always covers the whole inventory")
        if clean.get("scanner") == "amass":
            return ("target_ip is only valid with scanner='self' --"
                    " amass scans your configured domains, not IPs")
    return None


register_tool(ToolSpec(
    name="scan",
    description=("Run a vulnerability scan and return the findings."
                 " scanner='self': TCP port scan of your own LAN devices"
                 " (one device when target_ip is given, else the whole"
                 " inventory). scanner='nuclei': deeper template-based"
                 " scan of inventory devices (needs the nuclei binary)."
                 " scanner='amass': maps what the internet sees of your"
                 " configured domains (needs the amass binary). Scans run"
                 " quiet: findings come back as data, no alerts fire."),
    params={
        "scanner": ParamSpec(PTYPE_ENUM, required=True,
                             enum_values=_SCANNERS,
                             description="which scanner to run"),
        "target_ip": ParamSpec(PTYPE_STR, scope=SCOPE_INVENTORY_IP,
                               max_len=64,
                               description=("optional: one LAN IP from"
                                            " the asset inventory;"
                                            " self scanner only")),
    },
    timeout_s=600, idempotent=False, handler=_tool_scan,
    extra=_scan_extra))


def _tool_lookup_threat_intel(p):
    """Local threat-intel lookup. Read-only, offline: local feeds only,
    never the AbuseIPDB API (no key leaves the box on a model request)."""
    from . import threatintel as tim
    if p["kind"] == "ip":
        hits = tim.lookup_ip(p["value"], include_abuseipdb=False)
        return {"kind": "ip", "value": p["value"],
                "listed": hits.get("listed") or [],
                "note": "local feeds only"}
    hits = tim.lookup_domain(p["value"])
    return {"kind": "domain", "value": p["value"], "listed": hits,
            "note": "local feeds only (exact + parent-domain match)"}


def _intel_value_check(clean):
    """Kind-aware scope check: IPs must parse, domains must be shaped
    like real domains. Runs as the tool's extra validator so the error
    names the value, not just the parameter."""
    scope = SCOPE_IP if clean["kind"] == "ip" else SCOPE_DOMAIN
    err = _scope_check(scope, clean["value"])
    return f"value: {err}" if err else None


register_tool(ToolSpec(
    name="lookup_threat_intel",
    description=("Check an IP or domain against the monitor's local"
                 " threat-intel feeds (malware/phishing blocklists)."
                 " Local-only, no external lookups."),
    params={
        "kind": ParamSpec(PTYPE_ENUM, required=True,
                          enum_values=_INTEL_KINDS,
                          description="what to look up"),
        "value": ParamSpec(PTYPE_STR, required=True, max_len=253,
                           description="the IP or domain"),
    },
    timeout_s=30, idempotent=True, handler=_tool_lookup_threat_intel,
    extra=_intel_value_check))


def _tool_get_pipeline_health(_p):
    """Pipeline liveness snapshot. Read-only."""
    from . import pipeline as pipem
    expected = pipem.get_capture_expected()
    return {"capture_expected": expected,
            "stages": pipem.health_snapshot(
                capture_expected=expected)}


register_tool(ToolSpec(
    name="get_pipeline_health",
    description=("Monitor self-health: per-stage liveness (capture,"
                 " detection rules, threat-intel feeds, notifications) --"
                 " ok, stale, or unknown."),
    params={},
    timeout_s=30, idempotent=True, handler=_tool_get_pipeline_health))


# ---------------------------------------------------------------------------
# Debug CLI: list the registry without touching the dashboard
# ---------------------------------------------------------------------------

def _cli():
    ap = argparse.ArgumentParser(
        description="brutedash tool server -- list registered tools")
    ap.add_argument("--list", action="store_true",
                    help="list registered tools and exit")
    ap.add_argument("--describe", metavar="TOOL",
                    help="show one tool's full schema and exit")
    args = ap.parse_args()
    if args.describe:
        spec = get_tool(args.describe)
        if spec is None:
            print(f"unknown tool: {args.describe}")
            raise SystemExit(2)
        print(json.dumps(
            [t for t in list_tools() if t["name"] == spec.name][0],
            indent=2))
        return
    # Default action (also --list): print the registry.
    for t in list_tools():
        params = ", ".join(
            f"{n}{' (required)' if d['required'] else ''}"
            for n, d in t["params"].items()) or "none"
        print(f"{t['name']}: {t['description']}")
        print(f"    params: {params}; timeout {t['timeout_s']:g}s;"
              f" idempotent={t['idempotent']}")
    return


if __name__ == "__main__":
    _cli()
