"""netmon/nuclei.py -- scheduled vulnerability scanning via Nuclei.

Nuclei (github.com/projectdiscovery/nuclei, MIT) is a template-based
vulnerability scanner with thousands of community checks -- far deeper
than our built-in port-knocking scan. It runs as an OPTIONAL external
tool, like bettercap and Amass: the operator installs the binary
themselves; we never bundle it, never download it. When it is missing,
everything degrades gracefully -- the dashboard says so with install
instructions, and scheduled runs are skipped silently.

UPSTREAM WARNING, honored: Nuclei is never run as a network-exposed
service. It runs here as a short-lived SUBPROCESS with STRICT target
scoping -- nothing listens, nothing accepts remote input.

SECURITY BOUNDARIES (hard rules, reviewed):
  * Scan targets come ONLY from the asset inventory -- LAN devices we
    discovered ourselves, plus this box's own LAN addresses (the same
    scan_targets() the built-in scan uses). Every target is re-validated
    as RFC1918/loopback inside build_argv; anything else raises instead
    of scanning. The UI never supplies targets: there is no endpoint
    that accepts an address, and the on-demand button scans the
    inventory only. An attacker who can reach the dashboard must not be
    able to point our scanner at someone else's network.
  * No shell=True, ever. The binary runs via argv lists; targets travel
    in a temp file passed with -l, never on a command line string.
  * -dut (disable unsigned templates) is ALWAYS on: only signed
    templates from the official feed run. Supply-chain safety.
  * -duc (disable update check): no interactive prompts, no surprise
    network calls on our schedule -- template updates are the
    operator's job, run by hand.
  * Bounded output parsing: JSONL parsed line-by-line with per-line and
    total-line caps; garbage lines are skipped, never fatal.
  * Severity filter (default: medium and above): low/info noise stays in
    the findings table but never alerts. Quiet is a feature.
  * First run is the silent baseline; later runs diff and alert only on
    genuinely new findings (capped per run).

Run it: maybe_weekly_nuclei() (scheduled entry, called from run.py's
monitor loop) or start_nuclei_async() (dashboard on-demand button).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import db as dbm

WEEK_SECONDS = 7 * 86400
SCAN_TIMEOUT_MIN = 30       # nuclei-side -timeout flag (seconds; see below)
SUBPROC_TIMEOUT_S = 35 * 60  # our own kill switch, a bit longer
MAX_JSONL_LINE = 1_000_000  # one output line may never exceed 1MB
MAX_JSONL_LINES = 200_000   # total findings cap per run
MAX_ALERTS_PER_RUN = 10     # individual "new finding" alerts per run
MAX_TARGETS = 64            # same bound as the built-in scan

# One nuclei run at a time (same pattern as scan.py/amass.py: the real
# guard is this in-process lock, not a DB flag).
_NUCLEI_GUARD = threading.Lock()
_nuclei_in_flight = False


def _nuclei_already_running():
    with _NUCLEI_GUARD:
        return _nuclei_in_flight


def _claim_nuclei():
    global _nuclei_in_flight
    with _NUCLEI_GUARD:
        if _nuclei_in_flight:
            return False
        _nuclei_in_flight = True
        return True


def _release_nuclei():
    global _nuclei_in_flight
    with _NUCLEI_GUARD:
        _nuclei_in_flight = False


# ---------------------------------------------------------------------------
# Binary discovery + version
# ---------------------------------------------------------------------------

def find_binary():
    """Path to the nuclei binary, or None when not installed."""
    try:
        return shutil.which("nuclei")
    except Exception:
        return None


def binary_version(binary=None):
    """Version string like 'v3.3.9', or '' when unknown. Never raises."""
    binary = binary or find_binary()
    if not binary:
        return ""
    try:
        proc = subprocess.run(
            [binary, "-version"], capture_output=True, text=True,
            timeout=15)
        out = (proc.stdout or "") + (proc.stderr or "")
        m = re.search(r"v\d+\.\d+\.\d+", out)
        return m.group(0) if m else out.strip().splitlines()[0][:32]
    except Exception:
        return ""


def check_binary():
    """(ok, note): startup check with install instructions when missing.

    Called at startup and by the dashboard; the note is plain-English
    and safe to show in the UI.
    """
    binary = find_binary()
    if binary:
        ver = binary_version(binary)
        return True, (f"Nuclei found{f' ({ver})' if ver else ''} at"
                      f" {binary}.")
    return False, (
        "Nuclei is not installed -- it is optional. Install it for"
        " deeper vulnerability checks of your own network: download the"
        " release for your system from"
        " github.com/projectdiscovery/nuclei/releases and put the binary"
        " on your PATH (or `go install"
        " github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest`).")


# ---------------------------------------------------------------------------
# Config: targets ALWAYS come from the asset inventory (the boundary)
# ---------------------------------------------------------------------------

def nuclei_targets():
    """Validated scan targets: LAN devices we discovered + this box's
    own LAN addresses -- the same set the built-in scan uses. Every
    address is RFC1918/loopback or it is not here.

    The dashboard never supplies targets; there is deliberately no
    parameter for it.
    """
    try:
        from . import scan as scanm
        return scanm.scan_targets()[:MAX_TARGETS]
    except Exception:
        return []


def nuclei_enabled():
    """Feature switch: config nuclei.enabled (default False -- opt-in)."""
    try:
        from . import config as cfgm
        return bool(cfgm.get(cfgm.load_cached(), "nuclei.enabled", False))
    except Exception:
        return False


def _nuclei_cfg(key, default):
    try:
        from . import config as cfgm
        return cfgm.get(cfgm.load_cached(), f"nuclei.{key}", default)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Severity mapping + filter
# ---------------------------------------------------------------------------

# Nuclei severity -> our alert severity. A home scanner reports hygiene
# issues, not emergencies: even a nuclei "critical" becomes a High on
# our side (it still notifies -- High and Critical do -- but it never
# claims the sky is falling). info/unknown map to None: stored, never
# alerted.
_SEVERITY_MAP = {
    "critical": "High",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "info": None,
    "unknown": None,
}
_SEVERITY_ORDER = ["low", "medium", "high", "critical"]


def map_severity(nuclei_sev):
    """Nuclei severity string -> our severity, or None when it should
    never alert (info/unknown)."""
    return _SEVERITY_MAP.get(str(nuclei_sev or "").strip().lower())


def min_severity():
    """Configured alert floor (default 'medium'). Normalized to one of
    low|medium|high|critical."""
    raw = str(_nuclei_cfg("min_severity", "medium")).strip().lower()
    return raw if raw in _SEVERITY_ORDER else "medium"


def passes_filter(nuclei_sev):
    """True when a finding at this nuclei severity may alert."""
    try:
        return (_SEVERITY_ORDER.index(
            str(nuclei_sev or "").strip().lower())
            >= _SEVERITY_ORDER.index(min_severity()))
    except ValueError:
        return False


def _severity_csv():
    """-severity flag value: the configured floor and everything above.
    The binary filters too, so low/info noise never even reaches us."""
    floor = _SEVERITY_ORDER.index(min_severity())
    return ",".join(_SEVERITY_ORDER[floor:])


# ---------------------------------------------------------------------------
# Running the scan (argv list -- never shell=True)
# ---------------------------------------------------------------------------

def build_argv(targets, targets_path, out_path):
    """argv for `nuclei -l <targets> -jsonl -o <out> ...`.

    Every target is re-validated as RFC1918/loopback here -- this
    function must be safe no matter who calls it: a non-LAN target
    raises instead of reaching the command line. Targets travel in a
    file (-l), never interpolated into a shell string. -dut is always
    on (unsigned templates never run); -duc keeps it non-interactive.
    """
    from . import scan as scanm
    clean = []
    for t in targets or []:
        t = str(t or "").strip()
        if not scanm._ok_target(t):
            raise ValueError(
                f"refusing non-LAN nuclei target: {t!r}")
        if t not in clean:
            clean.append(t)
    if not clean:
        raise ValueError("no valid LAN targets")
    binary = find_binary()
    if not binary:
        raise ValueError("nuclei binary not found")
    try:
        timeout_min = max(1, min(240, int(_nuclei_cfg(
            "timeout_min", SCAN_TIMEOUT_MIN))))
    except (TypeError, ValueError):
        timeout_min = SCAN_TIMEOUT_MIN
    # nuclei -timeout is in seconds.
    argv = [binary,
            "-l", targets_path,
            "-jsonl",
            "-o", out_path,
            "-dut",            # only signed templates, always
            "-duc",            # no interactive update checks
            "-silent",
            "-severity", _severity_csv(),
            "-timeout", str(timeout_min * 60)]
    return argv, timeout_min


def run_scan(targets):
    """Run nuclei against validated LAN targets.

    Returns {"ok": True, "jsonl_path": ..., "duration_s": ...} or
    {"ok": False, "error": ...}. Never raises. The output lands in a
    temp dir that the caller owns (parse, then clean up).
    """
    binary = find_binary()
    if not binary:
        return {"ok": False, "error": "nuclei not installed"}
    work_dir = tempfile.mkdtemp(prefix="brutedash-nuclei-")
    targets_path = os.path.join(work_dir, "targets.txt")
    out_path = os.path.join(work_dir, "nuclei.jsonl")
    try:
        argv, timeout_min = build_argv(targets, targets_path, out_path)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)[:200],
                "work_dir": work_dir}
    try:
        with open(targets_path, "w", encoding="utf-8") as fh:
            # build_argv already validated every line; one IP per line.
            fh.write("\n".join(
                t for t in targets if t) + "\n")
    except OSError as exc:
        return {"ok": False, "error": f"cannot write targets: {exc}"[:200],
                "work_dir": work_dir}
    started = time.time()
    try:
        # No shell=True -- argv list only.
        proc = subprocess.run(
            argv, capture_output=True, text=True,
            timeout=timeout_min * 60 + 300)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "scan timed out",
                "work_dir": work_dir}
    except Exception as exc:
        return {"ok": False, "error": f"scan failed: {exc}"[:200],
                "work_dir": work_dir}
    duration = time.time() - started
    if not os.path.exists(out_path):
        err = (proc.stderr or "")[-500:]
        return {"ok": False,
                "error": f"nuclei produced no output"
                         f"{': ' + err if err else ''}"[:300],
                "work_dir": work_dir}
    return {"ok": True, "jsonl_path": out_path, "work_dir": work_dir,
            "duration_s": round(duration, 1),
            "version": binary_version(binary)}


# ---------------------------------------------------------------------------
# Parsing: defensive JSONL -> finding dicts
# ---------------------------------------------------------------------------

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)


def _finding_ip(obj):
    """Best-effort LAN IP for a finding: the ip field, else the host."""
    ip = str(obj.get("ip") or "").strip()
    if ip:
        return ip
    host = str(obj.get("host") or "").strip()
    # host is usually a URL like http://192.168.1.10:8080/...
    m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})", host)
    return m.group(1) if m else ""


def _extract_cves(info):
    """CVE ids from a template's classification block and tags."""
    cves = []
    cls = info.get("classification") or {}
    raw = cls.get("cve-id") if isinstance(cls, dict) else None
    if isinstance(raw, str):
        raw = [raw]
    for c in raw or []:
        c = str(c).strip().upper()
        if _CVE_RE.fullmatch(c) and c not in cves:
            cves.append(c)
    for tag in info.get("tags") or []:
        for m in _CVE_RE.finditer(str(tag)):
            c = m.group(0).upper()
            if c not in cves:
                cves.append(c)
    return cves[:10]


def parse_jsonl_text(text):
    """Parse nuclei -jsonl output (one JSON object per line).

    Defensive by design: per-line and total-line caps, garbage lines
    skipped, every field coerced. Returns [{ip, template_id, name,
    severity (OUR scale; None when it should never alert), nuclei_severity,
    matched_at, description, cves}].
    """
    findings = []
    if not text:
        return findings
    for i, line in enumerate(text.splitlines()):
        if i >= MAX_JSONL_LINES:
            break
        line = line.strip()
        if not line or len(line) > MAX_JSONL_LINE:
            continue
        try:
            obj = json.loads(line)
        except (ValueError, TypeError):
            continue
        if not isinstance(obj, dict):
            continue
        template_id = str(obj.get("template-id") or "").strip()[:120]
        if not template_id:
            continue
        info = obj.get("info")
        if not isinstance(info, dict):
            info = {}
        nuclei_sev = str(info.get("severity") or "unknown").strip().lower()
        findings.append({
            "ip": _finding_ip(obj),
            "template_id": template_id,
            "name": str(info.get("name") or template_id).strip()[:200],
            "severity": map_severity(nuclei_sev),
            "nuclei_severity": nuclei_sev,
            "matched_at": str(obj.get("matched-at") or "").strip()[:500],
            "description": str(info.get("description") or "").strip()
                           [:1000],
            "cves": ",".join(_extract_cves(info)),
        })
    return findings


def parse_jsonl_file(path):
    """Parse a -jsonl output file. Never raises; missing file -> []."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return parse_jsonl_text(fh.read())
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Storage + diffing + alerting
# ---------------------------------------------------------------------------

def alert_new_findings(new_findings, ts=None):
    """Alert on genuinely new Nuclei findings (severity-filtered).

    One alert per finding, capped at MAX_ALERTS_PER_RUN per run -- a big
    diff becomes one summary instead of a storm. Findings below the
    configured severity floor are stored but never alert. The FIRST run
    is the baseline and never alerts (everything would be 'new').
    """
    ts = ts if ts is not None else time.time()
    alertable = [f for f in new_findings
                 if f.get("severity") and passes_filter(
                     f.get("nuclei_severity", "unknown"))]
    shown = alertable[:MAX_ALERTS_PER_RUN]
    for f in shown:
        cve_txt = (f" Known CVE: {f['cves']}." if f.get("cves") else "")
        dbm.add_alert(
            "nuclei_finding", f["severity"],
            f"Vulnerability scan found: {f['name']} on {f['ip']}",
            (f"The deeper vulnerability scan checked {f['ip']} and the"
             f" '{f['template_id']}' check matched at {f['matched_at'] or 'the device'}."
             f"{cve_txt}"),
            meaning=("Nuclei runs thousands of known vulnerability checks"
                     " against your own devices -- the same checks an"
                     " attacker would run. A match means the device shows"
                     " a weakness with a known fix or workaround."),
            is_normal=("Most matches are outdated software or default"
                       " settings on gadgets -- worth fixing, rarely an"
                       " emergency. It matters most on devices that face"
                       " the internet or hold important files."),
            what_to_do=("Check the device for a software/firmware update"
                        " first -- that fixes most of these. The finding"
                        " name above is what to search for."),
            ts=ts,
        )
    if len(alertable) > MAX_ALERTS_PER_RUN:
        rest = len(alertable) - MAX_ALERTS_PER_RUN
        dbm.add_alert(
            "nuclei_finding", "Medium",
            f"{rest} more new vulnerability findings",
            (f"The deeper scan found {rest} more new findings beyond the"
             f" {MAX_ALERTS_PER_RUN} listed separately."),
            meaning=("A batch of new findings at once -- often a new"
                     " device on the network or a template update."),
            is_normal=("Normal when a new device joins the network."),
            what_to_do=("Review the full list in the Open doors check"
                        " section."),
            ts=ts,
        )
        return len(alertable) + 1
    return len(shown)


def run_full_nuclei_scan(note="scheduled"):
    """One full pass: scan inventory targets, parse, store, alert on
    genuinely new findings. Returns a summary dict. Never raises -- a
    failed scan is a missed scan, not a crash."""
    if not _claim_nuclei():
        return {"ok": False, "error": "a scan is already running"}
    started = time.time()
    work_dir = None
    try:
        targets = nuclei_targets()
        if not targets:
            return {"ok": False, "error": "no LAN targets discovered"}
        dbm.set_meta("nuclei_scan_running", "1")
        result = run_scan(targets)
        work_dir = result.get("work_dir")
        if not result.get("ok"):
            dbm.record_nuclei_run(started, 0, len(targets), 0, 0,
                                  note=f"failed: {result.get('error','')}"
                                  [:200])
            return {"ok": False, "error": result.get("error")}
        findings = parse_jsonl_file(result["jsonl_path"])
        # Drop findings that don't name a LAN target (defensive: a
        # template should never match outside our target list).
        from . import scan as scanm
        findings = [f for f in findings if scanm._ok_target(f.get("ip"))]
        had_run = dbm.latest_nuclei_run() is not None
        new, resolved, changed = dbm.record_nuclei_findings(started,
                                                            findings)
        by_key = {(f.get("ip"), f.get("template_id"),
                   f.get("matched_at")): f for f in findings}
        alertable = [by_key[k] for k in (new + changed) if k in by_key]
        dbm.record_nuclei_run(
            started, result.get("duration_s", 0), len(targets),
            len(findings), len(new), note=note)
        alerts_fired = 0
        if had_run and alertable:
            # First run is the baseline: everything is "new", so it
            # stays silent. Only later runs alert on changes.
            try:
                alerts_fired = alert_new_findings(alertable, ts=started)
            except Exception:
                pass  # alerting is a bonus; findings are stored
        dbm.set_meta("nuclei_scan_last_ts", str(started))
        return {"ok": True, "targets": len(targets),
                "findings": len(findings), "new": len(new),
                "resolved": len(resolved), "changed": len(changed),
                "alerts": alerts_fired,
                "duration_s": round(time.time() - started, 1),
                "version": result.get("version", "")}
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:200]}
    finally:
        _release_nuclei()
        try:
            dbm.set_meta("nuclei_scan_running", "0")
        except Exception:
            pass
        if work_dir:
            import shutil as _sh
            try:
                _sh.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass


def start_nuclei_async():
    """Start a nuclei scan in a background thread.

    Targets still come from the asset inventory only -- the dashboard
    button just kicks the scheduled path with note='manual'. Always
    launches the thread; the worker claims the single-scan slot inside
    run_full_nuclei_scan.
    """
    threading.Thread(target=run_full_nuclei_scan,
                     kwargs={"note": "manual"}, daemon=True).start()
    return True


def maybe_weekly_nuclei():
    """Launch the nuclei scan in the background if due and configured.

    Called from run.py's monitor loop. Skips silently when the feature
    is off, the binary is missing, or no targets exist -- an
    unconfigured optional tool is not an error.
    """
    if not nuclei_enabled():
        return None
    if not find_binary():
        return None
    if not nuclei_targets():
        return None
    if not _nuclei_cfg("weekly", True):
        return None
    raw = dbm.get_meta("nuclei_scan_last_ts")
    try:
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    if time.time() - last < WEEK_SECONDS:
        return None
    if _nuclei_already_running():
        return None
    dbm.set_meta("nuclei_scan_last_ts", str(time.time()))
    start_nuclei_async()
    return True


def nuclei_status():
    """Dashboard status: binary, config, last run, open findings. Never
    raises."""
    ok, note = check_binary()
    lr = None
    try:
        r = dbm.latest_nuclei_run()
        if r:
            lr = {"when": r["ts"], "duration_s": r["duration_s"],
                  "targets": r["targets"], "findings": r["findings"],
                  "new_findings": r["new_findings"], "note": r["note"]}
    except Exception:
        lr = None
    findings = []
    try:
        for f in dbm.list_nuclei_findings(status="open", limit=200):
            findings.append({
                "ip": f["ip"], "template_id": f["template_id"],
                "name": f["name"], "severity": f["severity"],
                "matched_at": f["matched_at"],
                "description": f["description"], "cves": f["cves"],
            })
    except Exception:
        findings = []
    return {
        "installed": ok,
        "install_note": note,
        "enabled": nuclei_enabled(),
        "running": dbm.get_meta("nuclei_scan_running") == "1",
        "min_severity": min_severity(),
        "last_run": lr,
        "findings": findings,
    }
