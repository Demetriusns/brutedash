"""Reproduction snippets for the 2026-11-08 robustness council review.
Run: ../venv/bin/python repro-2026-11-08-robust.py  (from council-reviews/)
Each block prints PASS-DEFECT (bug reproduced) or NO-DEFECT.
"""
import json
import os
import sys
import tempfile
import threading
import time
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

TMP = tempfile.mkdtemp(prefix="robust-repro-")


def block(name):
    print(f"\n=== {name} ===")


# ---------------------------------------------------------------- R1 capture
block("R1 capture.run_live sets the SHARED stop_event on sniff failure")
from netmon import capture as capm

capm.HAVE_SCAPY = True
calls = {"n": 0}


def _boom_sniff(**kw):
    calls["n"] += 1
    raise RuntimeError("Npcap driver hiccup (simulated)")


capm.sniff = _boom_sniff
shared = threading.Event()
try:
    capm.run_live(interface="ethX", stop_event=shared)
    print("run_live returned without raising (unexpected)")
except RuntimeError as exc:
    print(f"run_live raised: {exc}")
print(f"shared stop_event.is_set() after capture failure: {shared.is_set()}")
agg = capm.run_live(interface="ethX", stop_event=shared)
print(f"restarted capture: sniff calls total={calls['n']} "
      f"(a healthy restart would call sniff again)")
print("PASS-DEFECT" if shared.is_set() and calls["n"] == 1 else "NO-DEFECT")

# ---------------------------------------------------------------- R2 canary
block("R2 canary: dead listener thread is never restarted")
from netmon import canary as canarym

dead = threading.Thread(target=lambda: None)
dead.start()
dead.join()
with canarym._lock:
    canarym._state.update(thread=dead, stop=threading.Event(), sock=None,
                          port=canarym.DEFAULT_PORT, bind="127.0.0.1",
                          running=True)
print(f"is_running() with dead thread: {canarym.is_running()}")
ret = canarym.start(bind_ip="127.0.0.1")
print(f"start() returned: {ret}; is_running() after: {canarym.is_running()}")
print("PASS-DEFECT" if ret is True and not canarym.is_running()
      else "NO-DEFECT")
with canarym._lock:
    canarym._state.update(thread=None, stop=None, sock=None, running=False)

# ------------------------------------------------------------- R3 reverse DNS
block("R3 threatintel.reverse_dns caches a failed/timed-out lookup for 7 days")
from netmon import db as dbm
from netmon import threatintel as tim
import socket as _socket

scratch = os.path.join(TMP, "rdns.db")
with dbm.isolated_db(scratch):
    orig = _socket.gethostbyaddr
    def _down(ip):
        raise OSError("resolver down (simulated)")
    _socket.gethostbyaddr = _down
    try:
        first = tim.reverse_dns("203.0.113.7")
    finally:
        _socket.gethostbyaddr = orig
    _socket.gethostbyaddr = lambda ip: ("recovered.example.com", [], [ip])
    try:
        second = tim.reverse_dns("203.0.113.7")
    finally:
        _socket.gethostbyaddr = orig
    print(f"during outage: {first!r}; after resolver recovers: {second!r}")
    print("PASS-DEFECT" if first == "" and second == "" else "NO-DEFECT")

# ------------------------------------------------------------- R4 quiet hours
block("R4 notify.in_quiet_hours: post-midnight spill checks the wrong weekday")
from netmon import notify as notifm

dbm.get_quiet_hours = lambda: [
    {"days": [4], "start": "22:00", "end": "06:00", "kinds": ["all"]}]
fri_2300 = datetime(2026, 11, 6, 23, 0).timestamp()   # Friday 23:00 local
sat_0300 = datetime(2026, 11, 7, 3, 0).timestamp()    # Saturday 03:00 local
print(f"Fri 23:00 in quiet hours (Fri 22:00-06:00 window): "
      f"{notifm.in_quiet_hours('beaconing', fri_2300)}")
print(f"Sat 03:00 in quiet hours (same window, post-midnight spill): "
      f"{notifm.in_quiet_hours('beaconing', sat_0300)}")
print("PASS-DEFECT" if notifm.in_quiet_hours('beaconing', fri_2300)
      and not notifm.in_quiet_hours('beaconing', sat_0300) else "NO-DEFECT")

# ------------------------------------------------------- R5 weekly stamps
block("R5 nuclei/amass: 'last run' stamped at launch, failure eats the week")
from netmon import nuclei as nucleim
from netmon import amass as amassm

scratch2 = os.path.join(TMP, "weekly.db")
with dbm.isolated_db(scratch2):
    nucleim.find_binary = lambda: "/bin/true"
    nucleim.nuclei_enabled = lambda: True
    nucleim.nuclei_targets = lambda: ["192.168.1.50"]
    nucleim._nuclei_cfg = lambda k, d: True
    nucleim.start_nuclei_async = lambda: None  # launched scan will fail
    r1 = nucleim.maybe_weekly_nuclei()
    stamp = dbm.get_meta("nuclei_scan_last_ts")
    r2 = nucleim.maybe_weekly_nuclei()
    print(f"nuclei: first maybe_weekly -> {r1}, last_ts stamped: "
          f"{bool(stamp)}, second call (retry after failure) -> {r2}")
    n_ok = r1 is True and stamp and r2 is None

    amassm.find_binary = lambda: "/bin/true"
    amassm.amass_enabled = lambda: True
    amassm.configured_domains = lambda: ["example.com"]
    amassm._amass_cfg = lambda k, d: True
    amassm.start_amass_async = lambda: []
    a1 = amassm.maybe_weekly_amass()
    astamp = dbm.get_meta("amass_last_ts")
    a2 = amassm.maybe_weekly_amass()
    print(f"amass:  first maybe_weekly -> {a1}, last_ts stamped: "
          f"{bool(astamp)}, second call (retry after failure) -> {a2}")
    a_ok = a1 is True and astamp and a2 is None
print("PASS-DEFECT" if (n_ok and a_ok) else "NO-DEFECT")

# ------------------------------------------------- R6 selfcheck empty baseline
block("R6 selfcheck: failed netstat on Windows learns an EMPTY port baseline")
from netmon import selfcheck as scm

scratch3 = os.path.join(TMP, "selfcheck.db")
with dbm.isolated_db(scratch3):
    scm._is_windows = lambda: True
    scm._run = lambda cmd, timeout=15: ""  # netstat timed out / failed
    status, detail, _cur = scm.check_listening_ports()
    print(f"netstat failed -> ({status!r}, {detail!r})")
    scm._windows_listening_ports = lambda: {("TCP", 5001), ("TCP", 445)}
    status2, detail2, _ = scm.check_listening_ports()
    print(f"netstat recovers -> ({status2!r}, {detail2!r})")
    print("PASS-DEFECT" if status == "ok" and status2 == "drift"
          else "NO-DEFECT")

# ------------------------------------------------------- R7 ingest watermark
block("R7 ingest: >5000-event backlog -- oldest events skipped forever")
from netmon import ingest as ingm

scratch4 = os.path.join(TMP, "ingest.db")
with dbm.isolated_db(scratch4):
    base = time.time() - 100000
    rows = []
    # Oldest: a textbook 4625 burst (6 in 5 min from one external IP).
    for i in range(6):
        rows.append((base + i * 60, "eventlog", "4625", "HOST1", "victim",
                     json.dumps({"summary": "x", "fields": {
                         "IpAddress": "203.0.113.9",
                         "TargetUserName": "victim", "LogonType": "3"}})))
    # Newest 6000: filler events the rule skips (IpAddress '-').
    for i in range(6000):
        rows.append((base + 1000 + i, "eventlog", "4625", "HOST1", "u",
                     json.dumps({"summary": "x", "fields": {
                         "IpAddress": "-", "TargetUserName": "u"}})))
    dbm.insert_host_events(rows)
    fired = ingm.check_failed_logons()
    wm = float(dbm.get_meta("ingest_correlate_4625_ts") or 0)
    print(f"alerts fired for the old burst: {fired}; "
          f"watermark now {wm:.0f} vs burst ts {base:.0f} "
          f"(burst is {'BEHIND' if wm > base + 300 else 'ahead of'} watermark)")
    print("PASS-DEFECT" if fired == 0 and wm > base + 300 else "NO-DEFECT")

# ------------------------------------------------------- R8 rewind live segment
block("R8 rewind.enforce_caps can unlink the ACTIVE segment (POSIX)")
from netmon import rewind as rwm

rdir = tempfile.mkdtemp(prefix="rewind-", dir=TMP)
rwm.rewind_dir = lambda: __import__("pathlib").Path(rdir)
rwm._caps = lambda: (1.0, 1024.0)  # 1-minute retention, huge size cap
rwm._ENABLED = True
try:
    # Active segment as it looks 120s after rotation: segment files are
    # named by their OPEN epoch and rotate only every SEGMENT_SECONDS
    # (300s), while the monitor loop calls enforce_caps every 60s and
    # _caps() allows a 1-minute retention -- so an open segment's name
    # can be older than the cutoff while it is still being written.
    aged = int(time.time()) - 120
    seg_path = os.path.join(rdir, f"seg_{aged:010d}.pcap")
    fh = open(seg_path, "ab")
    fh.write(rwm._GLOBAL_HDR)
    fh.flush()
    rwm._seg_file = fh
    rwm._seg_start = aged
    rwm._seg_bytes = len(rwm._GLOBAL_HDR)
    segs = [n for n in os.listdir(rdir) if n.startswith("seg_")]
    print(f"active segment: {segs}; handle open: {rwm._seg_file is not None}")
    kept, freed = rwm.enforce_caps(now=time.time())
    exists = seg_path and os.path.exists(seg_path)
    print(f"after enforce_caps: file exists={exists}, "
          f"handle still open={rwm._seg_file is not None}")
    print("PASS-DEFECT" if seg_path and not exists
          and rwm._seg_file is not None else "NO-DEFECT")
finally:
    rwm._reset_for_tests()

print("\ndone")
