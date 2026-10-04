"""netmon/selfcheck.py -- sensor-box self-health.

Lightweight checks on the box running brutedash itself, using only
Python + OS APIs (no kernel drivers, no memory forensics -- that is EDR
territory and explicitly out of scope):

  * listening_ports: what TCP ports this box listens on (Linux: /proc,
    Windows: netstat). New ports vs. baseline -> Medium alert.
  * services: installed Windows service names vs. baseline -> Low alert.
  * autorun: Windows Run/RunOnce registry entries vs. baseline -> Low alert.
  * defender_rtp: is Defender real-time protection on? (Windows only)
    Off -> High alert -- that is genuinely risky.

First run learns the baseline silently; later runs alert on drift.
Everything degrades gracefully: an unsupported platform or a failed
command reports "unavailable", never an error. Runs every 6h from the
monitor loop (see run.py).
"""

import os
import platform
import socket
import subprocess
import sys
import time

from . import db as dbm

CHECK_INTERVAL = 6 * 3600


def _is_windows():
    return sys.platform.startswith("win")


def _run(cmd, timeout=15):
    """Run a command, return stdout text or '' on any failure."""
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout)
        if proc.returncode == 0:
            return proc.stdout or ""
        return ""
    except Exception:
        return ""


# --- listening ports ---------------------------------------------------------

def _linux_listening_ports():
    """{(proto, port)} from /proc/net/tcp and tcp6 (state 0A = LISTEN)."""
    found = set()
    for path, proto in (("/proc/net/tcp", "TCP"), ("/proc/net/tcp6", "TCP")):
        try:
            with open(path) as fh:
                lines = fh.readlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            if len(parts) < 4 or parts[3] != "0A":
                continue
            try:
                port = int(parts[1].rsplit(":", 1)[1], 16)
                found.add((proto, port))
            except (ValueError, IndexError):
                continue
    return found


def _windows_listening_ports():
    """{(proto, port)} from netstat (TCP LISTENING rows)."""
    out = _run(["netstat", "-ano", "-p", "TCP"])
    found = set()
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "TCP":
            continue
        if "LISTENING" not in line.upper():
            continue
        local = parts[1]
        try:
            port = int(local.rsplit(":", 1)[1])
            found.add(("TCP", port))
        except (ValueError, IndexError):
            continue
    return found


def check_listening_ports():
    """Return (status, detail, current_set).

    status: ok | drift | unavailable | error.
    """
    try:
        current = (_windows_listening_ports() if _is_windows()
                   else _linux_listening_ports())
    except Exception:
        return "error", "could not read listening ports", set()
    if not current and not _is_windows():
        # /proc missing and empty would be ambiguous; treat empty as
        # unavailable only when we truly couldn't read.
        if not os.path.exists("/proc/net/tcp"):
            return "unavailable", "not supported on this platform", set()
    base = dbm.selfcheck_baseline_get("listening_ports")
    if base is None:
        dbm.selfcheck_baseline_set("listening_ports",
                                   sorted(f"{p}:{n}" for p, n in current))
        return ("ok",
                f"baseline learned: {len(current)} listening ports",
                current)
    base_set = set(base)
    cur_set = {f"{p}:{n}" for p, n in current}
    new = sorted(cur_set - base_set)
    if not new:
        return "ok", f"{len(cur_set)} listening ports, no change", current
    return ("drift",
            f"new listening ports vs baseline: {', '.join(new)}", current)


# --- windows services ----------------------------------------------------------

def check_services():
    """Installed Windows service names vs baseline. Linux: unavailable."""
    if not _is_windows():
        return "unavailable", "Windows-only check", set()
    out = _run(["powershell", "-NoProfile", "-Command",
                "Get-Service | Select-Object -ExpandProperty Name"],
               timeout=30)
    current = {l.strip() for l in out.splitlines() if l.strip()}
    if not current:
        return "error", "could not enumerate services", set()
    base = dbm.selfcheck_baseline_get("services")
    if base is None:
        dbm.selfcheck_baseline_set("services", sorted(current))
        return "ok", f"baseline learned: {len(current)} services", current
    new = sorted(current - set(base))
    if not new:
        return "ok", f"{len(current)} services, no change", current
    return ("drift", f"new services vs baseline: {', '.join(new[:10])}"
            + (f" (+{len(new) - 10} more)" if len(new) > 10 else ""),
            current)


# --- windows autorun -----------------------------------------------------------

_AUTORUN_KEYS = [
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "HKCU"),
    (r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU"),
]


def check_autorun():
    """Windows Run/RunOnce entries vs baseline. Linux: unavailable."""
    if not _is_windows():
        return "unavailable", "Windows-only check", set()
    try:
        import winreg
    except ImportError:
        return "unavailable", "winreg not available", set()
    hives = {"HKLM": winreg.HKEY_LOCAL_MACHINE,
             "HKCU": winreg.HKEY_CURRENT_USER}
    current = set()
    try:
        for subkey, hive_name in _AUTORUN_KEYS:
            try:
                key = winreg.OpenKey(hives[hive_name], subkey)
            except OSError:
                continue
            try:
                i = 0
                while True:
                    try:
                        name, _val, _typ = winreg.EnumValue(key, i)
                    except OSError:
                        break
                    current.add(f"{hive_name}\\{subkey}\\{name}")
                    i += 1
            finally:
                winreg.CloseKey(key)
    except Exception:
        return "error", "could not read autorun entries", set()
    base = dbm.selfcheck_baseline_get("autorun")
    if base is None:
        dbm.selfcheck_baseline_set("autorun", sorted(current))
        return "ok", f"baseline learned: {len(current)} autorun entries", \
            current
    new = sorted(current - set(base))
    if not new:
        return "ok", f"{len(current)} autorun entries, no change", current
    short = [n.split("\\")[-1] for n in new]
    return ("drift",
            f"new autorun entries vs baseline: {', '.join(short[:10])}"
            + (f" (+{len(short) - 10} more)" if len(short) > 10 else ""),
            current)


# --- defender real-time protection -----------------------------------------------

def check_defender_rtp():
    """Is Defender real-time protection on? Windows only."""
    if not _is_windows():
        return "unavailable", "Windows-only check", None
    out = _run(["powershell", "-NoProfile", "-Command",
                "(Get-MpComputerStatus).RealTimeProtectionEnabled"],
               timeout=30).strip().lower()
    if out not in ("true", "false"):
        return "error", "could not query Defender status", None
    if out == "true":
        return "ok", "Defender real-time protection is on", True
    return "drift", "Defender real-time protection is OFF", False


# --- the run ---------------------------------------------------------------------

def run_selfcheck():
    """Run every check, learn-or-compare baselines, alert on drift.

    Returns {"checks": {name: {"status", "detail"}}, "alerts": n}.
    Never raises.
    """
    now = time.time()
    results = {}
    alerts = 0
    checks = [
        ("listening_ports", check_listening_ports, "Medium",
         "Something new is listening on this box",
         ("A new program on the monitor box started accepting network"
          " connections -- like a new door opening in your house. Often"
          " just a software update, but worth knowing about."),
         ("Check what you installed or updated recently. If nothing"
          " explains the new port, look up which program uses it.")),
        ("services", check_services, "Low",
         "New Windows service on the monitor box",
         ("A new background service appeared on the box running the"
          " monitor. Software installs add these constantly."),
         ("Search the web for the service name. If it belongs to"
          " software you installed, ignore this.")),
        ("autorun", check_autorun, "Low",
         "New autorun entry on the monitor box",
         ("A new program set itself to start automatically when the box"
          " boots. Legitimate installers do this; so does malware."),
         ("Search the web for the entry name. If you recognize the"
          " program, ignore this.")),
    ]
    for name, fn, severity, title, meaning, what_to_do in checks:
        try:
            status, detail, _current = fn()
        except Exception:
            status, detail = "error", "check crashed"
        results[name] = {"status": status, "detail": detail}
        if status == "drift":
            key = f"selfcheck:{name}:{detail}"
            if not dbm.recent_alert_kind("self_drift", key, 86400):
                try:
                    dbm.add_alert(
                        "self_drift", severity, title, detail,
                        meaning=meaning,
                        is_normal=("Normal after installing or updating"
                                   " software on this box. Not normal if"
                                   " nothing changed and you don't"
                                   " recognize the entry."),
                        what_to_do=what_to_do, ts=now)
                    alerts += 1
                except Exception:
                    pass
    # Defender RTP is special: off is High, and it needs no baseline.
    try:
        status, detail, _on = check_defender_rtp()
    except Exception:
        status, detail = "error", "check crashed"
    results["defender_rtp"] = {"status": status, "detail": detail}
    if status == "drift":  # protection is OFF
        if not dbm.recent_alert_kind("self_drift", "defender_rtp_off",
                                     86400):
            try:
                dbm.add_alert(
                    "self_drift", "High",
                    "Defender real-time protection is OFF on the monitor box",
                    "The always-on antivirus guard on the box running"
                    " brutedash is disabled.",
                    meaning=("The monitor box itself is unprotected: files"
                             " opened on it are not being scanned. An"
                             " unprotected monitor is a blind spot -- and a"
                             " target."),
                    is_normal=("Only normal if you deliberately turned it"
                               " off yourself just now."),
                    what_to_do=("Turn real-time protection back on in"
                                " Windows Security. If you didn't turn it"
                                " off, treat this as urgent."),
                    ts=now)
                alerts += 1
            except Exception:
                pass
    try:
        import json as _json
        dbm.set_meta("selfcheck_last_ts", str(now))
        dbm.set_meta("selfcheck_last_status",
                     "drift" if any(r["status"] == "drift"
                                    for r in results.values()) else "ok")
        dbm.set_meta("selfcheck_last_results", _json.dumps(results))
    except Exception:
        pass
    return {"checks": results, "alerts": alerts}


def maybe_scheduled_selfcheck():
    """Run if due (>6h). Called from the monitor loop. Never raises."""
    try:
        raw = dbm.get_meta("selfcheck_last_ts")
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    if time.time() - last < CHECK_INTERVAL:
        return None
    try:
        return run_selfcheck()
    except Exception:
        return None


def status_summary():
    """Last run summary for the dashboard."""
    raw = dbm.get_meta("selfcheck_last_ts")
    try:
        last = float(raw) if raw else 0
    except (TypeError, ValueError):
        last = 0
    return {
        "last_run_ts": last or None,
        "status": dbm.get_meta("selfcheck_last_status") or "never run",
        "platform": platform.system(),
        "hostname": socket.gethostname(),
    }
