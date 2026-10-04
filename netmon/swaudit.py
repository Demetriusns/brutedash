"""netmon/swaudit.py -- software inventory + CVE correlation.

The cheaper, safer complement to active scanning (the Wazuh pattern --
methodology inspiration only, no Wazuh code, which is GPLv2): instead
of probing the network, we ask the sensor box what software IT runs and
check that list against CISA's Known Exploited Vulnerabilities (KEV)
catalog -- the short list of flaws attackers are ACTUALLY using in the
wild, kept as a local feed by netmon/threatintel.py.

  * Inventory: installed Python packages (importlib.metadata -- the venv
    brutedash runs in) plus the OS package/app list where readable
    (dpkg/rpm on Linux, Uninstall registry keys on Windows). Local reads
    only; the software list never leaves the box and is never sent
    anywhere.
  * Correlation: each inventory name is matched against KEV product
    names (exact or whole-word match, with a stoplist against generic
    words). A match means "you run software with a flaw attackers are
    exploiting right now" -- a Medium alert with the CVE id, the
    plain-English flaw name, and CISA's fix-by date.
  * Honesty note: KEV lists affected products, not fixed versions, so a
    match is "check whether you're patched", not "you are definitely
    vulnerable". The alert says exactly that.
  * Quiet is a feature: a match alerts once per (package, CVE); repeats
    stay silent until the match goes away.

Runs daily from the monitor loop (maybe_daily_swaudit); the KEV feed
itself refreshes on the threat-intel schedule (12h).
"""

import os
import re
import subprocess
import sys
import time

from . import db as dbm

DAY_SECONDS = 86400
MAX_ALERTS_PER_RUN = 10
MAX_INVENTORY = 2000


# ---------------------------------------------------------------------------
# Normalization + matching
# ---------------------------------------------------------------------------

def normalize_name(s):
    """Lowercase, non-alphanumerics to spaces, collapsed. 'Google Chrome'
    and 'google-chrome' become the same string."""
    s = re.sub(r"[^a-z0-9]+", " ", str(s or "").lower()).strip()
    return re.sub(r"\s+", " ", s)


# Generic words that must never match on their own ("Server" matching
# "Microsoft Exchange Server" would cry wolf on every box).
_STOPWORDS = frozenset({
    "app", "apps", "application", "software", "program", "tool", "tools",
    "suite", "server", "servers", "client", "service", "services",
    "manager", "agent", "system", "systems", "windows", "microsoft",
    "update", "updates", "installer", "setup", "core", "lib", "libs",
    "library", "api", "web", "pro", "plus", "enterprise", "cloud",
    "desktop", "mobile", "package",
})


def product_matches(package_name, product_norm):
    """True when an inventory package name matches a KEV product name.

    Exact normalized match, or the package name is a whole word inside
    the product name (and not a generic stopword). Deterministic --
    code decides, no guessing.
    """
    pkg = normalize_name(package_name)
    prod = normalize_name(product_norm)
    if not pkg or not prod:
        return False
    if pkg == prod:
        return True
    tokens = set(prod.split())
    return (pkg in tokens and len(pkg) >= 4 and pkg not in _STOPWORDS)


def build_kev_index():
    """{normalized product -> [kev entries]} from the local KEV feed.

    The KEV catalog is ~1,500 rows; the whole index lives in memory
    for the duration of one correlation pass.
    """
    index = {}
    try:
        entries = dbm.list_kev_entries()
    except Exception:
        return {}
    for e in entries:
        prod = normalize_name(e.get("product"))
        if not prod:
            continue
        index.setdefault(prod, []).append(e)
        # Also index by vendor+product ("Fortinet FortiOS") -- some
        # inventory names carry the vendor.
        vp = normalize_name(
            (e.get("vendor") or "") + " " + (e.get("product") or ""))
        if vp and vp != prod:
            index.setdefault(vp, []).append(e)
    return index


def match_package(package_name, kev_index):
    """KEV entries matching one inventory package name."""
    hits = []
    seen = set()
    for prod_norm, entries in kev_index.items():
        if product_matches(package_name, prod_norm):
            for e in entries:
                if e["cve_id"] not in seen:
                    seen.add(e["cve_id"])
                    hits.append(e)
    return hits


# ---------------------------------------------------------------------------
# Inventory: Python packages + OS apps (local reads only)
# ---------------------------------------------------------------------------

def inventory_python():
    """[(name, version)] from importlib.metadata -- the packages in the
    Python environment brutedash runs in. Never raises."""
    out = []
    try:
        from importlib import metadata
        for dist in metadata.distributions():
            try:
                name = dist.metadata["Name"] or ""
            except Exception:
                name = ""
            name = (name or "").strip()
            if not name:
                continue
            try:
                version = str(dist.version or "").strip()
            except Exception:
                version = ""
            out.append((name, version))
    except Exception:
        pass
    return out


def _run_capture(cmd, timeout=30):
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True,
                              timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout or ""
        return ""
    except Exception:
        return ""


def inventory_os():
    """[(name, version)] of OS-level software. Linux: dpkg or rpm.
    Windows: Uninstall registry keys. Best-effort; never raises."""
    try:
        if sys.platform.startswith("win"):
            return _inventory_windows()
        return _inventory_linux()
    except Exception:
        return []


def _inventory_linux():
    out = _run_capture(
        ["dpkg-query", "-W", "-f=${Package}\t${Version}\n"], timeout=30)
    if out:
        rows = []
        for line in out.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[0].strip():
                rows.append((parts[0].strip(), parts[1].strip()))
        if rows:
            return rows[:MAX_INVENTORY]
    out = _run_capture(
        ["rpm", "-qa", "--queryformat", "%{NAME}\t%{VERSION}\n"],
        timeout=30)
    rows = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip():
            rows.append((parts[0].strip(), parts[1].strip()))
    return rows[:MAX_INVENTORY]


def _inventory_windows():
    """DisplayName/DisplayVersion from the Uninstall registry keys."""
    try:
        import winreg
    except ImportError:
        return []
    rows = []
    hives = [
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE,
         r"SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_CURRENT_USER,
         r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]
    for hive, subkey in hives:
        try:
            key = winreg.OpenKey(hive, subkey)
        except OSError:
            continue
        try:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(key, i)
                except OSError:
                    break
                i += 1
                try:
                    sk = winreg.OpenKey(key, sub)
                except OSError:
                    continue
                try:
                    name, _ = winreg.QueryValueEx(sk, "DisplayName")
                    try:
                        ver, _ = winreg.QueryValueEx(sk,
                                                     "DisplayVersion")
                    except OSError:
                        ver = ""
                except OSError:
                    continue
                finally:
                    winreg.CloseKey(sk)
                name = str(name or "").strip()
                if name:
                    rows.append((name, str(ver or "").strip()))
        finally:
            winreg.CloseKey(key)
    # De-dupe, keep first version seen.
    seen = {}
    for name, ver in rows:
        seen.setdefault(name, ver)
    return [(n, v) for n, v in seen.items()][:MAX_INVENTORY]


def collect_inventory():
    """Full inventory: [(name, version, source)]. Never raises."""
    rows = []
    try:
        for name, ver in inventory_python():
            rows.append((name, ver, "python"))
    except Exception:
        pass
    try:
        for name, ver in inventory_os():
            rows.append((name, ver, "os"))
    except Exception:
        pass
    return rows[:MAX_INVENTORY]


# ---------------------------------------------------------------------------
# Correlation + alerting
# ---------------------------------------------------------------------------

def correlate(inventory, kev_index):
    """[(package, version, source, kev_entry)] for inventory items with
    a KEV-listed flaw. Pure function of its inputs (testable)."""
    matches = []
    for name, version, source in inventory or []:
        for entry in match_package(name, kev_index or {}):
            matches.append({
                "package": name, "version": version, "source": source,
                "cve_id": entry["cve_id"], "vendor": entry["vendor"],
                "product": entry["product"],
                "vuln_name": entry["vuln_name"],
                "description": entry["description"],
                "due_date": entry["due_date"],
            })
    return matches


def alert_new_matches(new_matches, ts=None):
    """Medium alerts for newly matched (package, CVE) pairs.

    Capped per run with a summary overflow. Each alert carries the CVE
    id, the plain-English flaw name, and the honest caveat: the KEV
    list names products, not fixed versions, so this means "check
    whether you're patched".
    """
    ts = ts if ts is not None else time.time()
    shown = (new_matches or [])[:MAX_ALERTS_PER_RUN]
    for m in shown:
        due = (f" CISA's fix-by date was {m['due_date']}."
               if m.get("due_date") else "")
        dbm.add_alert(
            "cve_match", "Medium",
            f"Software on this box has a known-exploited flaw:"
            f" {m['package']} ({m['cve_id']})",
            (f"{m['package']} {m['version'] or '(version unknown)'} matches"
             f" the CISA known-exploited list: {m['cve_id']} --"
             f" {m['vuln_name'] or m['product']}.{due}"),
            meaning=("CISA keeps a short list of security flaws that"
                     " attackers are actively using in the real world"
                     " right now -- not theoretical, actually exploited."
                     " Software on the box running your monitor matches"
                     " one of them."),
            is_normal=("Matches are common -- almost every box runs"
                       " something on this list at some point. It is NOT"
                       " proof you are hacked, and the list names"
                       " products, not fixed versions: you may already be"
                       " patched."),
            what_to_do=(f"Update {m['package']} to the latest version"
                        " (Windows Update / the app's own updater / pip"
                        " -- whichever installed it). Then you can dismiss"
                        " this; it will not come back once the match is"
                        " gone."),
            ts=ts,
        )
    if len(new_matches or []) > MAX_ALERTS_PER_RUN:
        rest = len(new_matches) - MAX_ALERTS_PER_RUN
        dbm.add_alert(
            "cve_match", "Medium",
            f"{rest} more software matches on the known-exploited list",
            (f"The software check found {rest} more new matches beyond"
             f" the {MAX_ALERTS_PER_RUN} listed separately."),
            meaning=("Several installed programs match flaws attackers"
                     " are actively exploiting."),
            is_normal=("Common after the list updates with a batch of"
                       " new entries."),
            what_to_do=("Update the listed software, then review the"
                        " full list under the sensor health section."),
            ts=ts,
        )
        return len(new_matches) + 1
    return len(shown)


def run_swaudit():
    """One full pass: inventory, correlate, store, alert on new matches.

    Returns a summary dict. Never raises -- a failed run is a missed
    run, not a crash (the next daily run retries).
    """
    started = time.time()
    try:
        inventory = collect_inventory()
        dbm.record_sw_inventory(inventory, started)
        kev_index = build_kev_index()
        matches = correlate(inventory, kev_index) if kev_index else []
        new_matches = dbm.record_cve_matches(started, matches)
        alerts = 0
        if new_matches:
            try:
                alerts = alert_new_matches(new_matches, ts=started)
            except Exception:
                pass  # alerting is a bonus; matches are stored
        try:
            dbm.set_meta("swaudit_last_ts", str(started))
            dbm.set_meta("swaudit_last_counts",
                         f"{len(inventory)} packages,"
                         f" {len(matches)} matches")
        except Exception:
            pass
        return {"ok": True, "packages": len(inventory),
                "kev_entries": sum(len(v) for v in kev_index.values()),
                "matches": len(matches), "new": len(new_matches),
                "alerts": alerts,
                "duration_s": round(time.time() - started, 1)}
    except Exception as exc:
        try:
            dbm.set_meta("swaudit_error", str(exc)[:200])
        except Exception:
            pass
        return {"ok": False, "error": str(exc)[:200]}


def swaudit_enabled():
    try:
        from . import config as cfgm
        return bool(cfgm.get(cfgm.load_cached(), "swaudit.enabled", True))
    except Exception:
        return True


def maybe_daily_swaudit():
    """Run if due (>24h) and enabled. Called from the monitor loop.
    Never raises."""
    try:
        if not swaudit_enabled():
            return None
        try:
            from . import config as cfgm
            daily = bool(cfgm.get(cfgm.load_cached(), "swaudit.daily",
                                  True))
        except Exception:
            daily = True
        if not daily:
            return None
        raw = dbm.get_meta("swaudit_last_ts")
        try:
            last = float(raw) if raw else 0
        except (TypeError, ValueError):
            last = 0
        if time.time() - last < DAY_SECONDS:
            return None
        return run_swaudit()
    except Exception:
        return None


def swaudit_status():
    """Last-run summary + current matches for the dashboard. Never
    raises."""
    raw = dbm.get_meta("swaudit_last_ts")
    try:
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    matches = []
    try:
        matches = dbm.list_cve_matches(limit=100)
    except Exception:
        matches = []
    inv_count = 0
    try:
        inv_count = len(dbm.list_sw_inventory(limit=5000))
    except Exception:
        inv_count = 0
    kev_count = 0
    try:
        kev_count = len(dbm.list_kev_entries())
    except Exception:
        kev_count = 0
    return {
        "enabled": swaudit_enabled(),
        "last_run_ts": last or None,
        "packages": inv_count,
        "kev_entries": kev_count,
        "matches": matches,
    }
