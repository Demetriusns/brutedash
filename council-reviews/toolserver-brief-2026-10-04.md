# Council review brief — brutedash Phase 3.5 batch 15: MCP tool server

For: security seat (critical) + primary seat (robustness). Head: Orion (main agent).
Repo: ~/workspace/brutedash, files: netmon/tools.py (new), netmon/ai_assist.py
(modified: /ask tool loop), netmon/db.py (modified: +38 lines), tests/test_toolserver.py (new).
State: 49 new tests, 591/591 green on both pythons; scripts/audit_llm_sinks.py
on the full diff: 0 blockers, 0 suggestions, 0 nits. NOT YET COMMITTED.

## What it is (verified facts only)

netmon/tools.py is a tool registry letting the AI analyst (/ask path) invoke
tools. Pattern adapted from HexStrike AI (MIT) — registry + schemas + process
management + error recovery; no offensive tooling. Six tools, explicit
registration, no auto-discovery: get_alerts, get_incidents, get_devices,
get_scan_status, scan, lookup_threat_intel, get_pipeline_health.

Trust model, as built:
- Model proposes calls as DATA: {"tool": name, "params": {...}}. invoke()
  validates the name (exact dict lookup) and every param (type, range, enum,
  scope) BEFORE execution. Unknown params are rejected, not ignored.
- Scan targets: the `scan` tool's optional target_ip must be RFC1918/loopback
  (scan._ok_target) AND a member of the asset inventory (scan_targets()).
  nuclei/amass take NO model-supplied target: nuclei uses inventory targets,
  amass uses config.yaml domains only. Validation is re-checked inside
  build_argv/scan_device.
- Tool scans are EPHEMERAL: they call the pure scan primitives and return
  findings as data. They never write scan_runs/findings rows and never call
  add_alert (test-proven: latest_scan_run() stays None, alert count unchanged).
- Execution: daemon thread + join(timeout_s); timeout → structured error.
  Retries: idempotent tools retry ONCE on transient errors only
  ("locked"/"timeout"/"temporary"/"try again"/"busy"); non-idempotent never
  auto-retry. Every invocation (success, validation rejection, unknown tool,
  timeout, crash) is audit-logged via dbm.audit("tool_call", actor, tool,
  outcome-summary); db.recent_tool_calls() feeds the escalation bundle's
  "what the user already tried".
- Error messages to the model: param name + what was expected. No tracebacks,
  no file paths, no SQL.
- tools.py contains no shell=True, os.system, eval, exec, or subprocess calls
  at all (source-inspection test enforces this). All SQL is parameterized.
- ai_assist.py /ask loop: max 2 tool rounds, max 3 calls/round, then a final
  answer-only prompt. Model output shape-checked (_validate_tool_calls) AND
  registry-validated (defense in depth). Tool results appended to next prompt
  as data.

Known limitation (documented in the module docstring): CPython cannot kill
threads. A timed-out call abandons its daemon worker; the CALLER gets the
timeout error on time, but the worker finishes on its own. Subprocess-backed
scans carry their own internal timeouts (nuclei/amass modules).

## Verdicts wanted

For each finding: APPLY (must fix before commit), ADAPT (fix differently),
or REJECT (with the source evidence that refutes it). Rank top 5. No
flattery, no hedging. Cap: 600 words per seat.

Hunt list:
1. Any path where model-proposed data reaches execution (SQL, subprocess,
   file path, network target) without passing schema validation first.
2. Timeout bypasses: can a tool run unbounded despite its declared timeout?
   (Note the documented thread-kill limitation — judge whether the residual
   risk is acceptable or needs a design change.)
3. Audit-log gaps: any invoke() path that executes or rejects WITHOUT
   writing a tool_call audit row.
4. Tools mutating state beyond their declared scope (read-only + ephemeral
   scans). In particular: does the `scan` tool REALLY avoid all DB writes
   and alerts on every path (self/nuclei/amass, success and failure)?
5. Error messages leaking internals to the model (anything beyond
   param-name + expected-value that an attacker could use).
6. Robustness: retry policy (once, transient-only, idempotent-only) —
   sound or racy? Registry thread-safety under concurrent /ask calls?
   _jsonable sanitizer adequate for arbitrary handler returns? Validation
   edge cases (bool-vs-int, enum exactness, overlong strings)?
7. The /ask loop: can the model escape the 2-round budget, smuggle
   instructions via tool results, or get tool output into a privileged
   channel?
