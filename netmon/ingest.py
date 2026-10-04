"""netmon/ingest.py -- Windows Event Log + firewall log ingestion.

The network monitor sees packets; this sees the host. Point it at a
folder of *exported* logs (see INGEST.md for the export steps) and it
parses:

  * Windows Firewall pfirewall.log files (DROP events)
  * Windows Security / System / Defender event XML exports
    (Event Viewer -> "Save All Events As" -> XML)

Detection focus (deterministic -- code decides, the LLM only narrates):
  * 4625 failed logons -> correlate with brute-force-style network
    alerts (port_scan / beaconing / unusual_port naming the same source
    IP); 5+ in 10 min from one IP -> Medium alert.
  * 7045 new service installed -> Low alert, once per service name.
  * USB mass-storage inserts (Security 6416, DriverFrameworks 2003/2102)
    -> Medium alert for a device never seen before ("unknown USB device
    plugged into <host>").
  * Defender detections/quarantines (1116/1117) -> High/Medium alert;
    a detection on a host that also showed C2-style network traffic in
    the last 24h -> one Critical "host_compromise" alert (correlated
    into the same incident via the shared external IP).

What this is NOT: brutedash never replaces on-device AV. It does not
scan files, quarantine anything, or kill processes -- Defender and
friends own real-time file/process prevention. brutedash detects,
correlates, and proposes.

Degrades gracefully: no watch dir configured, or an empty dir, means
"no host events" on the dashboard -- never an error. Unparsable lines
are counted and skipped.
"""

import datetime
import json
import os
import re
import socket
import time
import xml.etree.ElementTree as ET

from . import db as dbm

MAX_FILES = 50
MAX_FILE_BYTES = 50 * 1024 * 1024
ALLOWED_EXTS = {".log", ".xml", ".txt"}

# Event IDs we care about (everything else is stored, not alerted on).
ID_FAILED_LOGON = "4625"      # failed logon (Security)
ID_NEW_SERVICE = "7045"       # new service installed (System)
ID_USB_NEW_DEVICE = "6416"    # new external device recognized (Security)
ID_USB_ARRIVAL = ("2003", "2102")  # DriverFrameworks-UserMode: device arrival
ID_DEFENDER_HIT = ("1116", "1117")  # Defender: malware detected / action taken
ID_DEFENDER_CONFIG = "5007"   # Defender: configuration changed

_USB_CLASS_GUID = "{53f56307-b6bf-11d0-94f2-00a0c91efb8b}"  # disk drives

_FAILED_LOGON_BURST = 5       # 5+ failed logons ...
_FAILED_LOGON_WINDOW = 600    # ... in 10 minutes from one IP -> alert
_FAILED_LOGON_COOLDOWN = 86400


def watch_dir():
    """Configured log watch folder, or ''. Empty = ingestion disabled."""
    try:
        from . import config as cfgm
        d = cfgm.get(cfgm.load_cached(), "ingest.watch_dir", "")
    except Exception:
        d = ""
    return (d or "").strip()


def _safe_files(directory):
    """Files directly inside `directory` that are safe to read.

    No recursion, no dotfiles, no symlinks escaping the dir, allowlisted
    extensions, size-capped. Yields absolute real paths."""
    if not directory:
        return
    try:
        real = os.path.realpath(directory)
        if not os.path.isdir(real):
            return
        names = sorted(os.listdir(real))
    except OSError:
        return
    count = 0
    for name in names:
        if name.startswith("."):
            continue
        if os.path.splitext(name)[1].lower() not in ALLOWED_EXTS:
            continue
        p = os.path.join(real, name)
        try:
            rp = os.path.realpath(p)
            if not rp.startswith(real + os.sep):
                continue  # symlink escaping the watch dir
            if not os.path.isfile(rp):
                continue  # no recursion into subdirectories
            if os.path.getsize(rp) > MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        count += 1
        if count > MAX_FILES:
            return
        yield rp


# --- Windows Firewall log (pfirewall.log) ----------------------------------
# Lines look like:
#   #Fields: date time action protocol src-ip dst-ip src-port dst-port ...
#   2026-10-03 14:22:01 DROP TCP 192.168.1.50 203.0.113.7 51234 443 60 ...
# ALLOW rows are counted but not stored (too noisy); DROP rows become
# host_events so spikes of blocked inbound traffic are visible.

def _parse_fw_ts(date_s, time_s):
    try:
        dt = datetime.datetime.strptime(f"{date_s} {time_s}",
                                        "%Y-%m-%d %H:%M:%S")
        return dt.timestamp()  # log times are local; so is this box
    except (ValueError, TypeError):
        return None


def parse_pfirewall(path, offset=0):
    """Parse new pfirewall.log content from byte `offset`.

    Returns (events, new_offset, skipped): events are
    (ts, "firewall", action, computer, user, detail_json) tuples ready
    for dbm.insert_host_events; only DROP rows are returned as events.
    """
    events = []
    skipped = 0
    columns = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            fh.seek(offset)
            for line in fh:
                line = line.rstrip("\n")
                if not line:
                    continue
                if line.startswith("#"):
                    if line.lower().startswith("#fields:"):
                        columns = [c.strip().lower().replace("-", "_")
                                   for c in line[8:].split()]
                    continue
                if not columns:
                    skipped += 1
                    continue
                parts = line.split()
                if len(parts) < len(columns):
                    skipped += 1
                    continue
                row = dict(zip(columns, parts))
                ts = _parse_fw_ts(row.get("date"), row.get("time"))
                if ts is None:
                    skipped += 1
                    continue
                action = (row.get("action") or "").upper()
                if action != "DROP":
                    continue  # ALLOW/OPEN rows: counted, not stored
                detail = {
                    "summary": (f"{action} {row.get('protocol','')} "
                                f"{row.get('src_ip','')}:{row.get('src_port','')}"
                                f" -> {row.get('dst_ip','')}:{row.get('dst_port','')}"),
                    "action": action,
                    "protocol": row.get("protocol", ""),
                    "src_ip": row.get("src_ip", ""),
                    "dst_ip": row.get("dst_ip", ""),
                    "src_port": row.get("src_port", ""),
                    "dst_port": row.get("dst_port", ""),
                    "file": os.path.basename(path),
                }
                events.append((ts, "firewall", action, "", "",
                               json.dumps(detail)[:2000]))
            new_offset = fh.tell()
    except OSError:
        return [], offset, skipped + 1
    return events, new_offset, skipped


# --- Windows event XML exports ----------------------------------------------
# Event Viewer -> "Save All Events As" -> XML gives <Events><Event>...
# with <System> (EventID, TimeCreated, Computer, Channel) and <EventData>
# (<Data Name="...">value</Data>). Parsed generically so any exported log
# works; the focus IDs above get rules, everything else is stored.

def _strip_ns(tag):
    return tag.rsplit("}", 1)[-1] if "}" in tag else tag


def _parse_event_xml(el):
    """One <Event> element -> dict, or None when unparsable."""
    try:
        system = None
        eventdata = None
        for child in el:
            name = _strip_ns(child.tag)
            if name == "System":
                system = child
            elif name == "EventData":
                eventdata = child
        if system is None:
            return None
        sys_fields = {}
        for f in system:
            fn = _strip_ns(f.tag)
            if fn == "EventID":
                sys_fields["event_id"] = (f.text or "").strip()
            elif fn == "TimeCreated":
                sys_fields["time"] = f.attrib.get("SystemTime", "")
            elif fn in ("Computer", "Channel", "Level"):
                sys_fields[fn.lower()] = (f.text or "").strip()
        fields = {}
        if eventdata is not None:
            for d in eventdata:
                if _strip_ns(d.tag) != "Data":
                    continue
                key = d.attrib.get("Name") or f"field_{len(fields)}"
                fields[key] = (d.text or "").strip()
        ts = _parse_xml_ts(sys_fields.get("time", ""))
        if ts is None or not sys_fields.get("event_id"):
            return None
        return {
            "ts": ts,
            "event_id": sys_fields["event_id"],
            "computer": sys_fields.get("computer", ""),
            "channel": sys_fields.get("channel", ""),
            "fields": fields,
        }
    except Exception:
        return None


def _parse_xml_ts(s):
    """'2026-10-03T14:22:01.1234567Z' -> epoch. None when unparsable."""
    if not s:
        return None
    try:
        s2 = s.strip().rstrip("Z")
        # Trim to microseconds; fromisoformat handles the rest.
        if "." in s2:
            head, frac = s2.split(".", 1)
            s2 = head + "." + frac[:6]
        dt = datetime.datetime.fromisoformat(s2)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return None


def _event_summary(event_id, fields):
    """One human-readable line for the dashboard."""
    if event_id == ID_FAILED_LOGON:
        return (f"Failed logon for user '{fields.get('TargetUserName', '?')}'"
                f" from {fields.get('IpAddress', 'unknown')}"
                f" (logon type {fields.get('LogonType', '?')})")
    if event_id == ID_NEW_SERVICE:
        return (f"New service installed: '{fields.get('ServiceName', '?')}'"
                f" ({fields.get('ImagePath', '')})")
    if event_id == ID_USB_NEW_DEVICE:
        return (f"New external device: {fields.get('DeviceDescription', '?')}"
                f" [{fields.get('DeviceId', '')}]")
    if event_id in ID_USB_ARRIVAL:
        dev = (fields.get("DeviceId") or fields.get("InstanceId")
               or fields.get("DeviceInstanceId") or "?")
        return f"USB device arrival: {dev}"
    if event_id in ID_DEFENDER_HIT:
        return (f"Defender: {fields.get('Threat Name', fields.get('ThreatName', 'threat'))}"
                f" -- {fields.get('Action Name', fields.get('ActionName', 'action taken'))}"
                f" on {fields.get('Path', '')}")
    if event_id == ID_DEFENDER_CONFIG:
        return f"Defender configuration changed: {fields.get('New Value', fields.get('Old Value', ''))[:120]}"
    interesting = {k: v for k, v in fields.items() if v}
    bits = "; ".join(f"{k}={v}" for k, v in list(interesting.items())[:4])
    return f"Event {event_id}: {bits}"[:300]


def parse_security_xml(path, since_ts=0):
    """Parse a Windows event XML export.

    Returns (events, skipped): events are
    (ts, "eventlog", event_id, computer, user, detail_json) tuples;
    only events newer than `since_ts` are returned (incremental).
    """
    events = []
    skipped = 0
    try:
        tree = ET.parse(path)
    except (ET.ParseError, OSError):
        return [], 1
    root = tree.getroot()
    for el in root.iter():
        if _strip_ns(el.tag) != "Event":
            continue
        parsed = _parse_event_xml(el)
        if parsed is None:
            skipped += 1
            continue
        if parsed["ts"] <= since_ts:
            continue
        fields = parsed["fields"]
        user = (fields.get("TargetUserName") or fields.get("SubjectUserName")
                or "")
        detail = {
            "summary": _event_summary(parsed["event_id"], fields),
            "channel": parsed["channel"],
            "fields": fields,
            "file": os.path.basename(path),
        }
        events.append((parsed["ts"], "eventlog", parsed["event_id"],
                       parsed["computer"], user[:128],
                       json.dumps(detail)[:2000]))
    return events, skipped


def _xml_max_ts(basename):
    """Newest stored event ts from this export file (incremental)."""
    rows = dbm.query(
        "SELECT MAX(ts) FROM host_events WHERE source='eventlog'"
        " AND json_extract(detail, '$.file') = ?",
        (basename,))
    return rows[0][0] if rows and rows[0][0] else 0


def _host_ip_for(computer):
    """Best-effort LAN IP(s) for the computer that logged the event.

    Only resolves when the event came from this box itself (name match
    against the local hostname) -- anything else would be a guess, and
    we don't guess.
    """
    try:
        if not computer:
            return []
        if computer.strip().lower().rstrip(".") not in (
                socket.gethostname().lower(), "localhost"):
            return []
        from .capture import get_local_ips
        return sorted(get_local_ips())
    except Exception:
        return []


# --- detection rules over ingested host events -------------------------------
# All deterministic. Watermarked via meta so each poll only looks at new
# events; failures never break ingestion (events stay stored for retry).

def _new_events(since_ts, source=None, event_ids=()):
    rows = dbm.host_events_since(since_ts, limit=5000)
    out = []
    for r in rows:
        if source and r["source"] != source:
            continue
        if event_ids and r["event_id"] not in event_ids:
            continue
        try:
            r["_detail"] = json.loads(r["detail"] or "{}")
        except Exception:
            r["_detail"] = {}
        out.append(r)
    return out


def _watermark(key):
    raw = dbm.get_meta(key)
    try:
        return float(raw) if raw else 0
    except (TypeError, ValueError):
        return 0


def check_failed_logons():
    """4625: 5+ failed logons in 10 min from one IP -> Medium alert.

    Also correlates each 4625's source IP against brute-force-style
    network alerts (port_scan / beaconing / unusual_port) in the last
    24h and links them (matched_alert), so the host story and the
    network story meet in one place.
    """
    since = _watermark("ingest_correlate_4625_ts")
    events = _new_events(since, source="eventlog", event_ids=(ID_FAILED_LOGON,))
    if not events:
        return 0
    now = time.time()
    by_ip = {}
    for ev in events:
        ip = (ev["_detail"].get("fields") or {}).get("IpAddress", "").strip()
        if not ip or ip in ("-", "127.0.0.1", "::1"):
            continue
        by_ip.setdefault(ip, []).append(ev)
        # Correlate: did the network see this IP acting hostile recently?
        for kind in ("port_scan", "beaconing", "unusual_port"):
            row = dbm.query(
                "SELECT id, title FROM alerts WHERE kind=? AND detail LIKE ?"
                " AND ts > ? ORDER BY ts DESC LIMIT 1",
                (kind, f"%{ip}%", now - 86400))
            if row:
                dbm.mark_host_event_matched(ev["id"], row[0][0])
                break
    fired = 0
    for ip, evs in by_ip.items():
        evs.sort(key=lambda e: e["ts"])
        # sliding window: any 10-minute span with 5+ failures
        burst = False
        for i, ev in enumerate(evs):
            n = sum(1 for e in evs[i:] if e["ts"] - ev["ts"] <= _FAILED_LOGON_WINDOW)
            if n >= _FAILED_LOGON_BURST:
                burst = True
                break
        if not burst:
            continue
        if dbm.recent_alert_kind("host_event", f"4625:{ip}",
                                 _FAILED_LOGON_COOLDOWN):
            continue
        comp = evs[0]["computer"] or "a Windows PC"
        user = (evs[0]["_detail"].get("fields") or {}).get("TargetUserName", "")
        dbm.add_alert(
            "host_event", "Medium",
            f"Repeated failed logins on {comp}",
            (f"{len(evs)} failed logins for '{user or 'unknown user'}' from"
             f" {ip} in the last 10 minutes (event 4625)."),
            meaning=("Someone -- or something -- tried to log into a"
                     " Windows account several times and kept getting the"
                     " password wrong. A few typos are normal; a burst from"
                     " one address is what password-guessing looks like."),
            is_normal=("Normal if you just mistyped your password a few"
                       " times in a row. Not normal when the attempts come"
                       " from an address you don't recognize, or keep"
                       " coming in waves."),
            what_to_do=("Check whether the account owner was actually"
                        " logging in then. If not, make sure the account"
                        " has a strong, unique password and look for the"
                        " source address in your router's device list."),
            ts=now,
        )
        fired += 1
    dbm.set_meta("ingest_correlate_4625_ts", str(now))
    return fired


def check_new_services():
    """7045: a never-before-seen Windows service name -> Low alert."""
    since = _watermark("ingest_correlate_7045_ts")
    events = _new_events(since, source="eventlog", event_ids=(ID_NEW_SERVICE,))
    if not events:
        return 0
    now = time.time()
    fired = 0
    for ev in events:
        name = ((ev["_detail"].get("fields") or {}).get("ServiceName")
                or "").strip()
        if not name:
            continue
        if dbm.get_first_seen("win_service", name) is not None:
            continue
        dbm.note_first_seen("win_service", name, now)
        if dbm.recent_alert_kind("host_event", f"7045:{name}", 86400):
            continue
        comp = ev["computer"] or "a Windows PC"
        img = ((ev["_detail"].get("fields") or {}).get("ImagePath") or "")
        dbm.add_alert(
            "host_event", "Low",
            f"New Windows service installed on {comp}",
            f"Service '{name}' was installed ({img}).".rstrip(" "),
            meaning=("A new background service was installed on a Windows"
                     " machine -- a program that starts itself and runs all"
                     " the time. Legitimate software does this constantly; "
                     " malware also likes to hide as a service."),
            is_normal=("Normal right after installing or updating software."
                       " Worth a look if you didn't install anything and"
                       " don't recognize the name."),
            what_to_do=("Search the web for the service name. If it's tied"
                        " to software you installed, ignore this. If not,"
                        " check when it was installed and consider removing"
                        " the program that put it there."),
            ts=now,
        )
        fired += 1
    dbm.set_meta("ingest_correlate_7045_ts", str(now))
    return fired


def _usb_device_id(fields):
    """Stable identity for a USB insert event."""
    for key in ("DeviceId", "DeviceInstanceId", "InstanceId",
                "DeviceInstanceID"):
        val = (fields.get(key) or "").strip()
        if val:
            return val
    desc = (fields.get("DeviceDescription") or "").strip()
    if desc:
        return f"desc:{desc}"
    return ""


def _is_usb_storage(fields):
    """Best-effort: is this insert a USB mass-storage device?"""
    blob = " ".join(str(v) for v in fields.values()).upper()
    if _USB_CLASS_GUID.upper() in blob:
        return True
    return "USBSTOR" in blob or "USB MASS STORAGE" in blob


def check_usb_devices():
    """USB inserts (6416 / 2003 / 2102): unknown device -> Medium alert.

    "Unknown" = a device ID this monitor has never seen. First sighting
    of a device alerts once; the device is then known and stays quiet.
    Non-storage USB devices (keyboards, mice) are stored but only
    storage devices alert -- quiet is a feature.
    """
    since = _watermark("ingest_correlate_usb_ts")
    events = _new_events(
        since, source="eventlog",
        event_ids=(ID_USB_NEW_DEVICE,) + ID_USB_ARRIVAL)
    if not events:
        return 0
    now = time.time()
    fired = 0
    for ev in events:
        fields = ev["_detail"].get("fields") or {}
        devid = _usb_device_id(fields)
        if not devid:
            continue
        known = dbm.get_first_seen("usb_device", devid) is not None
        if not known:
            dbm.note_first_seen("usb_device", devid, ev["ts"])
        if known or not _is_usb_storage(fields):
            continue
        if dbm.recent_alert_kind("usb_insert", devid, 86400):
            continue
        comp = ev["computer"] or "a Windows PC"
        desc = fields.get("DeviceDescription", "") or devid
        dbm.add_alert(
            "usb_insert", "Medium",
            f"Unknown USB device plugged into {comp}",
            f"A USB storage device never seen before was connected: {desc}.",
            meaning=("Someone plugged a USB drive (or a device acting like"
                     " one) into a Windows machine for the first time. USB"
                     " drives are a classic way malware walks into a network"
                     " -- and a classic way files walk out of it."),
            is_normal=("Normal if you or someone at home just plugged in"
                       " their own drive. Not normal if nobody did, or the"
                       " device name looks odd."),
            what_to_do=("Ask who plugged it in. If it was you, you can"
                        " dismiss this -- the device is now known and won't"
                        " alert again. If nobody claims it, unplug it and"
                        " run an antivirus scan on that machine."),
            ts=now,
        )
        fired += 1
    dbm.set_meta("ingest_correlate_usb_ts", str(now))
    return fired


def check_defender():
    """Defender 1116/1117 detections -> alert; correlate with C2 traffic.

    A Defender detection on a host that also showed C2-style network
    traffic (beaconing / unusual_port / new_external_ip / volume_anomaly)
    in the last 24h becomes one Critical host_compromise alert, and the
    shared external IP lands in the detail so incident grouping puts
    both in the same case. 5007 with real-time protection turned off ->
    High alert on its own (that is genuinely risky).
    """
    since = _watermark("ingest_correlate_defender_ts")
    events = _new_events(
        since, source="eventlog",
        event_ids=ID_DEFENDER_HIT + (ID_DEFENDER_CONFIG,))
    if not events:
        return 0
    now = time.time()
    fired = 0
    for ev in events:
        fields = ev["_detail"].get("fields") or {}
        comp = ev["computer"] or "a Windows PC"
        eid = ev["event_id"]
        if eid == ID_DEFENDER_CONFIG:
            blob = json.dumps(fields).lower()
            if ("real-time protection" in blob
                    and ("disabled" in blob or "false" in blob)):
                if not dbm.recent_alert_kind("host_event",
                                             "defender_rtp_off", 86400):
                    dbm.add_alert(
                        "host_event", "High",
                        f"Defender real-time protection turned OFF on {comp}",
                        "A Defender configuration change (event 5007) shows"
                        " real-time protection was disabled.",
                        meaning=("The always-on guard that checks files as"
                                 " they're opened was switched off. Malware"
                                 " does this to itself to avoid being"
                                 " caught; people also do it by accident"
                                 " when troubleshooting."),
                        is_normal=("Rarely normal. Only expected if you"
                                   " deliberately turned it off yourself"
                                   " just now."),
                        what_to_do=("Turn real-time protection back on in"
                                    " Windows Security unless you have a"
                                    " specific reason it is off. If you"
                                    " didn't turn it off, treat this as"
                                    " urgent."),
                        ts=now,
                    )
                    fired += 1
            continue
        # 1116/1117: a detection or an action (quarantine/removal).
        threat = (fields.get("Threat Name") or fields.get("ThreatName")
                  or "a threat")
        sev_name = (fields.get("Severity Name") or fields.get("SeverityName")
                    or "").lower()
        action = (fields.get("Action Name") or fields.get("ActionName")
                  or "detected")
        path = fields.get("Path") or ""
        severity = "High" if sev_name in ("severe", "critical", "high") \
            else "Medium"
        key = f"defender:{threat}:{path}"
        if dbm.recent_alert_kind("defender_detection", key, 86400):
            continue
        # Correlate: did this host talk to anything C2-shaped recently?
        host_ips = _host_ip_for(comp)
        c2_ip = None
        for hip in host_ips:
            for kind in ("beaconing", "unusual_port", "new_external_ip",
                         "volume_anomaly"):
                row = dbm.query(
                    "SELECT detail FROM alerts WHERE kind=? AND ts > ?"
                    " AND (detail LIKE ? OR title LIKE ?)"
                    " ORDER BY ts DESC LIMIT 1",
                    (kind, now - 86400, f"%{hip}%", f"%{hip}%"))
                if row:
                    # The alert names both the host and the outside address;
                    # take the first EXTERNAL one (not the host's own IP).
                    for cand in re.findall(
                            r"\b(?:\d{1,3}\.){3}\d{1,3}\b", row[0][0] or ""):
                        if cand != hip and not _is_lan(cand):
                            c2_ip = cand
                            break
                    if c2_ip:
                        break
            if c2_ip:
                break
        detail = (f"Defender {action} '{threat}' on {comp}"
                  + (f" ({path})" if path else "") + ".")
        if c2_ip:
            # Critical: endpoint detection + network C2 from the same host.
            dbm.add_alert(
                "host_compromise", "Critical",
                f"Host under attack: {comp}",
                (f"Defender {action} '{threat}' on {comp}, and the network"
                 f" monitor saw that same host talking suspiciously to"
                 f" {c2_ip} in the last 24 hours. {detail}"),
                meaning=("Two independent witnesses agree: the antivirus"
                         " caught something bad on this machine, and the"
                         " network saw it phoning out to a suspicious"
                         " address. Either one alone is worth a look;"
                         " together they strongly suggest this machine is"
                         " compromised."),
                is_normal=("This is not normal. Treat it as a real"
                           " incident until proven otherwise."),
                what_to_do=("Disconnect the machine from the network, then"
                            " run a full Defender scan. Change passwords"
                            " used on that machine from a different,"
                            " clean device."),
                ts=now,
            )
            fired += 1
            continue
        dbm.add_alert(
            "defender_detection", severity,
            f"Defender caught something on {comp}",
            detail,
            meaning=("Windows Defender -- the built-in antivirus -- found"
                     " malware or unwanted software on this machine and"
                     f" {action} it. Defender handled the file itself;"
                     " this alert is the network monitor noting it happened"
                     " so the full story is in one place."),
            is_normal=("Detections happen: Defender catches adware,"
                       " trojans in downloads, and PUAs regularly. The"
                       " network monitor stays quiet about the network side"
                       " unless the machine was also talking to something"
                       " suspicious."),
            what_to_do=("Open Windows Security on that machine and check"
                        " the Protection history entry. If it was a real"
                        " trojan (not a false positive on a tool you"
                        " trust), run a full scan."),
            ts=now,
        )
        fired += 1
    dbm.set_meta("ingest_correlate_defender_ts", str(now))
    return fired


def _is_lan(ip):
    """True for this network (RFC1918/loopback/link-local), False otherwise.

    Uses explicit ranges rather than ipaddress.is_global: Python 3.11+
    counts TEST-NET documentation ranges (203.0.113.0/24 etc.) as
    non-global, and those must still count as "outside the LAN" for
    C2-correlation purposes.
    """
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if a.is_loopback or a.is_link_local or a.is_multicast:
        return True
    packed = a.packed
    if len(packed) == 4:
        o0, o1 = packed[0], packed[1]
        if (o0 == 10 or (o0 == 172 and 16 <= o1 <= 31)
                or (o0 == 192 and o1 == 168)):
            return True
    return False


def run_detection_rules():
    """Run all host-event detection rules. Returns alerts fired.

    Best-effort: a failing rule never breaks the others, and the
    watermark only advances for rules that completed.
    """
    fired = 0
    for rule in (check_failed_logons, check_new_services,
                 check_usb_devices, check_defender):
        try:
            fired += rule() or 0
        except Exception:
            continue
    return fired


# --- the poll -----------------------------------------------------------------

def run_ingest():
    """One ingestion pass: read new log content, store events, run rules.

    Returns a summary dict. Disabled (no watch dir) -> {"enabled": False}.
    Never raises.
    """
    directory = watch_dir()
    if not directory:
        return {"enabled": False}
    if not os.path.isdir(directory):
        return {"enabled": False, "error": "watch dir missing"}
    summary = {"enabled": True, "dir": directory, "files": 0,
               "events": 0, "skipped": 0, "alerts": 0}
    try:
        for path in _safe_files(directory):
            summary["files"] += 1
            state = dbm.ingest_state_get(path) or {}
            mtime = os.path.getmtime(path)
            try:
                ino = os.stat(path).st_ino
            except OSError:
                ino = None
            ext = os.path.splitext(path)[1].lower()
            if ext == ".xml":
                if state.get("mtime") == mtime:
                    continue  # unchanged export
                events, skipped = parse_security_xml(
                    path, since_ts=_xml_max_ts(os.path.basename(path)))
                new_offset = 0
            else:  # .log / .txt: append-style firewall logs
                offset = state.get("offset") or 0
                if os.path.getsize(path) < offset:
                    offset = 0  # rotated/truncated: start over
                elif (ino is not None and state.get("inode") is not None
                        and state["inode"] != ino):
                    # Council review: the file was replaced wholesale under
                    # the same name (new export/log copy) with a size >= the
                    # old one. The stale offset would silently skip the new
                    # file's head mid-line, so start over. Plain appends keep
                    # the same inode, so the fast path is unaffected.
                    offset = 0
                events, new_offset, skipped = parse_pfirewall(path, offset)
            summary["skipped"] += skipped
            if events:
                dbm.insert_host_events(events)
                summary["events"] += len(events)
            dbm.ingest_state_set(path, mtime, new_offset, ino)
        try:
            summary["alerts"] = run_detection_rules()
        except Exception:
            pass
        dbm.set_meta("ingest_last_run_ts", str(time.time()))
    except Exception as exc:
        summary["error"] = str(exc)[:200]
    return summary
