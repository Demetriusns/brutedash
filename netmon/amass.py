"""netmon/amass.py -- external attack-surface mapping via OWASP Amass.

The other half of the attack surface view: brutedash maps the INSIDE
(LAN inventory, open doors, what the internet can reach); Amass maps the
OUTSIDE -- what the internet can see of the customer's OWN domain(s):
subdomains, IPs, ASNs, certificates, via DNS enumeration, certificate
transparency logs, reverse-DNS sweeps, and passive sources.

Amass (github.com/owasp-amass/amass, Apache-2.0, Go CLI) is an OPTIONAL
external tool, like bettercap: the operator installs the binary
themselves; we never bundle it, never download it, never run it without
being asked. When it is missing, everything degrades gracefully -- the
dashboard says so with install instructions, and scheduled runs are
skipped silently (no errors, no nagging).

SECURITY BOUNDARIES (hard rules, reviewed):
  * Scan targets come ONLY from config.yaml (amass.domains) -- the
    customer's own domains. The UI never supplies targets: there is no
    endpoint that accepts a domain, and the on-demand run button scans
    the configured domains only. An attacker who can reach the dashboard
    must not be able to point our scanner at someone else's domain.
  * No shell=True, ever. The binary runs via argv lists, and every
    domain is validated against a strict hostname pattern before it
    reaches the command line (see valid_domain).
  * Passive mode by default: no direct contact with the target's
    infrastructure -- third-party sources only. Active mode is a
    config opt-in and still only ever targets configured domains.
  * Bounded output parsing: JSONL parsed line-by-line with per-line and
    total-line caps; garbage lines are skipped, never fatal.
  * Data-source API keys are Amass's business, not ours: Amass reads
    its own config file (~/.config/amass/config.yaml) for keys. We pass
    the environment through to the subprocess untouched and never read,
    log, or store keys. Without keys, free passive sources (crtsh and
    friends) still work; keyed sources are skipped silently by Amass.

Run it: maybe_weekly_amass() (scheduled entry, called from run.py's
monitor loop) or start_amass_async() (dashboard on-demand button).
"""

import ipaddress
import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time

from . import db as dbm

# Strict hostname shape for scan targets (linear-time, no ReDoS).
# This is the security gate: anything not shaped like a real domain
# never reaches the command line.
_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$")

WEEK_SECONDS = 7 * 86400
SCAN_TIMEOUT_MIN = 20      # amass-side -timeout flag (minutes)
SUBPROC_TIMEOUT_S = 25 * 60  # our own kill switch, a bit longer
MAX_JSONL_LINE = 1_000_000  # one output line may never exceed 1MB
MAX_JSONL_LINES = 200_000   # total findings cap per run
MAX_ALERTS_PER_RUN = 10     # individual "new asset" alerts per run

# One external scan at a time (same pattern as scan.py: the real guard
# is this in-process lock, not a DB flag).
_AMASS_GUARD = threading.Lock()
_amass_in_flight = False


def _amass_already_running():
    with _AMASS_GUARD:
        return _amass_in_flight


def _claim_amass():
    global _amass_in_flight
    with _AMASS_GUARD:
        if _amass_in_flight:
            return False
        _amass_in_flight = True
        return True


def _release_amass():
    global _amass_in_flight
    with _AMASS_GUARD:
        _amass_in_flight = False


# ---------------------------------------------------------------------------
# Binary discovery + version
# ---------------------------------------------------------------------------

def find_binary():
    """Path to the amass binary, or None when not installed."""
    try:
        return shutil.which("amass")
    except Exception:
        return None


def binary_version(binary=None):
    """Version string like 'v4.2.0', or '' when unknown.

    Runs `amass -version` with a short timeout; never raises. The
    version is informational (the enum flags we use are stable across
    v3/v4), but we record it so the dashboard can say what it ran.
    """
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
        return True, (f"Amass found{f' ({ver})' if ver else ''} at"
                      f" {binary}.")
    return False, (
        "Amass is not installed -- it is optional. Install it to map what"
        " the internet sees of your domain(s): `go install"
        " github.com/owasp-amass/amass/v4/...@latest` (needs Go), or on"
        " Kali `sudo apt install amass`. Then list your own domain(s) under"
        " amass.domains in config.yaml.")


# ---------------------------------------------------------------------------
# Config: ONLY ever scan configured domains (the security boundary)
# ---------------------------------------------------------------------------

def valid_domain(domain):
    """True for something shaped like a real domain name.

    This is the gate every scan target passes through -- before config
    load, before the command line. Anything else is rejected, never
    sanitized: 'evil.com; rm -rf /' fails closed.
    """
    if not domain or not isinstance(domain, str):
        return False
    return bool(_DOMAIN_RE.match(domain.strip().lower()))


def configured_domains():
    """Validated scan targets from config.yaml ONLY.

    The dashboard never supplies targets; there is deliberately no
    parameter for it. Returns the de-duplicated list of valid domains,
    or [] when the operator hasn't configured any.
    """
    try:
        from . import config as cfgm
        raw = cfgm.get(cfgm.load_cached(), "amass.domains", [])
    except Exception:
        return []
    if isinstance(raw, str):
        # Tolerate a comma-separated string (e.g. from env override).
        raw = [d.strip() for d in raw.split(",")]
    domains = []
    for d in raw or []:
        d = str(d or "").strip().lower()
        if valid_domain(d) and d not in domains:
            domains.append(d)
    return domains


def amass_enabled():
    """Feature switch: config amass.enabled (default False -- opt-in)."""
    try:
        from . import config as cfgm
        return bool(cfgm.get(cfgm.load_cached(), "amass.enabled", False))
    except Exception:
        return False


def _amass_cfg(key, default):
    try:
        from . import config as cfgm
        return cfgm.get(cfgm.load_cached(), f"amass.{key}", default)
    except Exception:
        return default


# ---------------------------------------------------------------------------
# Running the scan (argv list -- never shell=True)
# ---------------------------------------------------------------------------

def build_argv(domain, out_path, work_dir):
    """argv for `amass enum -d <domain> -json <out>`.

    The domain has already passed valid_domain(); it travels as ONE
    argv element, never interpolated into a shell string. Flags mirror
    the v4 CLI (stable across v3/v4 for these options). Re-validated
    here anyway: this function must be safe no matter who calls it.
    """
    if not valid_domain(domain):
        raise ValueError(f"refusing to build argv for invalid domain: {domain!r}")
    binary = find_binary()
    if not binary:
        raise ValueError("amass binary not found")
    passive = _amass_cfg("passive", True)
    timeout_min = _amass_cfg("timeout_min", SCAN_TIMEOUT_MIN)
    try:
        timeout_min = max(1, min(120, int(timeout_min)))
    except (TypeError, ValueError):
        timeout_min = SCAN_TIMEOUT_MIN
    argv = [binary, "enum",
            "-passive" if passive else "-active",
            "-d", domain,
            "-json", out_path,
            "-timeout", str(timeout_min),
            "-dir", work_dir,
            "-silent"]
    return argv


def run_enum(domain):
    """Run one amass enum for a configured domain.

    Returns {"ok": True, "jsonl_path": ..., "duration_s": ...} or
    {"ok": False, "error": ...}. Never raises. The output lands in a
    temp dir that the caller owns (parse, then clean up).
    """
    if not valid_domain(domain):
        return {"ok": False, "error": "rejected: not a valid domain"}
    binary = find_binary()
    if not binary:
        return {"ok": False, "error": "amass not installed"}
    work_dir = tempfile.mkdtemp(prefix="brutedash-amass-")
    out_path = os.path.join(work_dir, "amass.jsonl")
    argv = build_argv(domain, out_path, work_dir)
    started = time.time()
    try:
        # No shell=True -- argv list only. Env passes through untouched
        # (Amass reads its own data-source API keys from its own config).
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=SUBPROC_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": "scan timed out", "work_dir": work_dir}
    except Exception as exc:
        return {"ok": False, "error": f"scan failed: {exc}"[:200],
                "work_dir": work_dir}
    duration = time.time() - started
    if not os.path.exists(out_path):
        err = (proc.stderr or "")[-500:]
        return {"ok": False,
                "error": f"amass produced no output{': ' + err if err else ''}"[:300],
                "work_dir": work_dir}
    return {"ok": True, "jsonl_path": out_path, "work_dir": work_dir,
            "duration_s": round(duration, 1),
            "version": binary_version(binary)}


# ---------------------------------------------------------------------------
# Parsing: defensive JSONL -> asset dicts
# ---------------------------------------------------------------------------

def _looks_like_ip(s):
    """True for strings that parse as an IP address.

    Amass -json output should only carry IPs in `addresses`, but a
    malformed line must not plant garbage in the asset table.
    """
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def parse_jsonl_text(text):
    """Parse amass -json output (one JSON object per line).

    Defensive by design: the exact schema drifts between Amass versions,
    so both address shapes are accepted (plain IP strings, or objects
    with ip/cidr/asn/desc). Garbage lines are skipped; per-line and
    total-line caps bound memory. Returns [{name, domain, ips, cidrs,
    asns, tag, sources}].
    """
    assets = []
    if not text:
        return assets
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
        name = str(obj.get("name") or "").strip().lower()
        if not valid_domain(name):
            continue
        ips, cidrs, asns = [], [], []
        for a in obj.get("addresses") or []:
            if isinstance(a, str):
                a = a.strip()
                if a and _looks_like_ip(a):
                    ips.append(a)
            elif isinstance(a, dict):
                ip = str(a.get("ip") or "").strip()
                if ip and _looks_like_ip(ip):
                    ips.append(ip)
                cidr = str(a.get("cidr") or "").strip()
                if cidr:
                    cidrs.append(cidr)
                asn = a.get("asn")
                try:
                    asn = int(asn)
                except (TypeError, ValueError):
                    asn = None
                if asn:
                    asns.append(asn)
        sources = obj.get("sources") or obj.get("source") or []
        if isinstance(sources, str):
            sources = [sources]
        assets.append({
            "name": name,
            "domain": str(obj.get("domain") or "").strip().lower(),
            "ips": sorted(set(ips)),
            "cidrs": sorted(set(cidrs)),
            "asns": sorted(set(asns)),
            "tag": str(obj.get("tag") or ""),
            "sources": sorted({str(s) for s in sources if s})[:10],
        })
    return assets


def parse_jsonl_file(path):
    """Parse a -json output file. Never raises; missing file -> []."""
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return parse_jsonl_text(fh.read())
    except OSError:
        return []


# ---------------------------------------------------------------------------
# Storage + diffing
# ---------------------------------------------------------------------------

def asset_rows(domain, assets):
    """Flatten parsed assets into (kind, value, detail) rows for storage.

    kinds: 'subdomain' (the name), 'ip' (each discovered IP), 'asn'
    (each ASN seen). detail is a small JSON blob with sources/tags.
    """
    rows = []
    for a in assets:
        rows.append(("subdomain", a["name"], json.dumps({
            "ips": a["ips"][:20], "tag": a["tag"],
            "sources": a["sources"][:10]})[:500]))
        for ip in a["ips"]:
            rows.append(("ip", ip, json.dumps({
                "name": a["name"], "sources": a["sources"][:10]})[:500]))
        for asn in a["asns"]:
            rows.append(("asn", str(asn), ""))
    # De-dupe while keeping order (bounded).
    seen, out = set(), []
    for kind, value, detail in rows:
        key = (kind, value)
        if key not in seen:
            seen.add(key)
            out.append((kind, value, detail))
    return out


def diff_assets(prev_set, cur_rows):
    """(new_subdomains, new_ips, new_asns): what appeared since the
    previous run. Sets of (kind, value) vs the stored rows."""
    cur = {(k, v) for k, v, _ in cur_rows}
    new_subs = sorted(v for k, v in cur - prev_set if k == "subdomain")
    new_ips = sorted(v for k, v in cur - prev_set if k == "ip")
    new_asns = sorted(v for k, v in cur - prev_set if k == "asn")
    return new_subs, new_ips, new_asns


def alert_new_assets(domain, new_subs, new_ips, ts=None):
    """Medium alerts for newly discovered public-facing assets.

    One alert per asset, capped at MAX_ALERTS_PER_RUN per run -- a big
    diff becomes one summary instead of a storm. The FIRST run for a
    domain is the baseline and never alerts (everything would be 'new').
    """
    ts = ts if ts is not None else time.time()
    items = ([("subdomain", s) for s in new_subs]
             + [("IP address", ip) for ip in new_ips])
    if not items:
        return 0
    shown = items[:MAX_ALERTS_PER_RUN]
    for kind_word, value in shown:
        dbm.add_alert(
            "amass_new_asset", "Medium",
            f"New public-facing asset discovered: {value}",
            (f"The external scan of {domain} found a {kind_word} it had"
             f" not seen before: {value}."),
            meaning=("Amass maps what the internet can see of your"
                     " domain -- subdomains, addresses, certificates. A"
                     " new entry means something new is now visible to"
                     " everyone, which is worth knowing about: sometimes"
                     " it is a new service you launched, sometimes it is"
                     " something you forgot was public."),
            is_normal=("New assets are normal when you launch something"
                       " -- a new site, a VPN, a test server. They are"
                       " worth a look when you did NOT launch anything."),
            what_to_do=("Check whether you recognize this asset. If you"
                        " launched it, all good. If not, find out what it"
                        " is and whether it should be public."),
            ts=ts,
        )
    if len(items) > MAX_ALERTS_PER_RUN:
        rest = len(items) - MAX_ALERTS_PER_RUN
        dbm.add_alert(
            "amass_new_asset", "Medium",
            f"{rest} more new public-facing assets on {domain}",
            (f"The external scan of {domain} found {rest} more new"
             f" assets beyond the {MAX_ALERTS_PER_RUN} listed separately."),
            meaning=("A batch of new public-facing assets appeared at"
                     " once -- often a bulk DNS change or a new batch of"
                     " services."),
            is_normal=("Normal during a migration or launch; surprising"
                       " otherwise."),
            what_to_do=("Review the full list in the Attack Surface"
                        " section under 'What the internet sees'."),
            ts=ts,
        )
        return len(items) + 1
    return len(items)


def run_domain_scan(domain, note="scheduled"):
    """One full pass for a configured domain: scan, parse, store, diff,
    alert on genuinely new assets. Returns a summary dict. Never raises
    -- a failed scan is a missed scan, not a crash."""
    if not valid_domain(domain):
        return {"ok": False, "domain": domain,
                "error": "rejected: not a valid domain"}
    if not _claim_amass():
        return {"ok": False, "domain": domain,
                "error": "a scan is already running"}
    started = time.time()
    work_dir = None
    try:
        result = run_enum(domain)
        work_dir = result.get("work_dir")
        if not result.get("ok"):
            dbm.record_amass_run(started, domain, 0, 0, 0,
                                 note=f"failed: {result.get('error','')}"[:200])
            return {"ok": False, "domain": domain,
                    "error": result.get("error")}
        assets = parse_jsonl_file(result["jsonl_path"])
        rows = asset_rows(domain, assets)
        prev_set = dbm.amass_asset_set(domain)
        had_run = dbm.latest_amass_run(domain) is not None
        dbm.record_amass_assets(domain, rows, started)
        new_subs, new_ips, new_asns = diff_assets(prev_set, rows)
        dbm.record_amass_run(
            started, domain, result.get("duration_s", 0),
            len({v for k, v, _ in rows if k == "subdomain"}),
            len({v for k, v, _ in rows if k == "ip"}),
            note=note)
        alerts_fired = 0
        if had_run and (new_subs or new_ips):
            # First run is the baseline: everything is "new", so it
            # stays silent. Only later runs alert on changes.
            try:
                alerts_fired = alert_new_assets(domain, new_subs, new_ips,
                                                ts=started)
            except Exception:
                pass  # alerting is a bonus; findings are stored
        return {"ok": True, "domain": domain,
                "subdomains": len({v for k, v, _ in rows
                                   if k == "subdomain"}),
                "ips": len({v for k, v, _ in rows if k == "ip"}),
                "new_subdomains": new_subs, "new_ips": new_ips,
                "new_asns": new_asns,
                "alerts": alerts_fired,
                "duration_s": round(time.time() - started, 1),
                "version": result.get("version", "")}
    except Exception as exc:
        return {"ok": False, "domain": domain,
                "error": str(exc)[:200]}
    finally:
        _release_amass()
        if work_dir:
            import shutil as _sh
            try:
                _sh.rmtree(work_dir, ignore_errors=True)
            except Exception:
                pass


def start_amass_async():
    """Start scans for all configured domains in a background thread.

    Targets still come from config.yaml only -- the dashboard button
    just kicks the same scheduled path. Always launches the thread;
    the worker claims the single-scan slot inside run_domain_scan.
    """
    domains = configured_domains()

    def _worker():
        for domain in domains:
            try:
                run_domain_scan(domain, note="manual")
            except Exception:
                pass

    threading.Thread(target=_worker, daemon=True).start()
    return list(domains)


def maybe_weekly_amass():
    """Launch the external scan in the background if due and configured.

    Called from run.py's monitor loop. Skips silently when the feature
    is off, the binary is missing, or no domains are configured -- an
    unconfigured optional tool is not an error.
    """
    if not amass_enabled():
        return None
    if not find_binary():
        return None
    domains = configured_domains()
    if not domains:
        return None
    if not _amass_cfg("weekly", True):
        return None
    raw = dbm.get_meta("amass_last_ts")
    try:
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    if time.time() - last < WEEK_SECONDS:
        return None
    if _amass_already_running():
        return None
    dbm.set_meta("amass_last_ts", str(time.time()))
    start_amass_async()
    return True


def amass_status():
    """Dashboard status: binary, version, config, last runs. Never raises."""
    ok, note = check_binary()
    domains = configured_domains()
    runs = []
    try:
        for d in domains:
            r = dbm.latest_amass_run(d)
            if r:
                runs.append({"domain": d, "when": r["ts"],
                             "duration_s": r["duration_s"],
                             "subdomains": r["subdomains"],
                             "ips": r["ips"], "note": r["note"]})
    except Exception:
        runs = []
    assets = {}
    try:
        for d in domains:
            assets[d] = dbm.list_amass_assets(d, limit=500)
    except Exception:
        assets = {}
    return {
        "installed": ok,
        "install_note": note,
        "enabled": amass_enabled(),
        "domains": domains,
        "runs": runs,
        "assets": assets,
    }
