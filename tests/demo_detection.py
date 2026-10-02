"""Demo detection tests: synthetic home + small-business networks.

Feeds crafted traffic through the real detection rules (netmon/detect.py)
on a scratch DB and verifies the right things flag -- and that normal
devices stay quiet. Never touches the real netmon.db.
"""
import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from netmon import db as dbm

random.seed(20261002)  # deterministic demo

SCRATCH = "/tmp/demo-netmon.db"
if os.path.exists(SCRATCH):
    os.remove(SCRATCH)
dbm.DB_PATH = SCRATCH
dbm._conn = None  # force fresh connection on the scratch DB

from netmon import detect as detm
from netmon import explainer as expl

NOW = int(time.time())
HOUR = time.localtime(NOW).tm_hour


def flow(ts, src, dst, dport, nbytes, direction="outbound", proto="TCP",
         sport=50000):
    return (ts, src, dst, sport, dport, proto, max(nbytes // 1500, 1),
            nbytes, direction)


def seed_baseline(prefix, devices, minutes=65):
    """Normal background traffic: jittered buckets so it doesn't look
    like clockwork beaconing -- real devices aren't metronomes."""
    flows = []
    buckets = list(range(minutes, 0, -5))
    for ip, mb in devices:
        for m in random.sample(buckets, k=random.randint(4, 6)):
            ts = NOW - m * 60 + random.randint(0, 120)
            jitter = random.uniform(0.5, 1.5)
            flows.append(flow(ts, ip, "1.1.1.1", 443, int(mb * jitter * 1e6)))
            # this pair is "known" -- don't flag first-contact on a fresh DB
            dbm.note_first_seen("ext_ip", f"{ip}|1.1.1.1",
                                NOW - 3 * 86400)
    dbm.insert_flows(flows)


def keep_profiles_fresh():
    """Pretend the profiler ran recently so run_all doesn't rebuild (and
    wipe) the hand-seeded device_profiles rows used by the demo."""
    dbm.query(
        "INSERT INTO meta (key, value) VALUES ('profiles_built_ts', ?)"
        " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        (str(NOW),))


def seed_arp(devices, old_days=3):
    """devices: [(ip, mac)]; old sighting (join time) + recent sighting."""
    rows = []
    for ip, mac in devices:
        rows.append((NOW - old_days * 86400, ip, mac))
        rows.append((NOW - 300, ip, mac))
        dbm.note_first_seen("mac", mac, NOW - old_days * 86400)
    dbm.insert_arp_observations(rows)


def seed_profile(mac, avg_mb, days=5):
    dbm.query(
        "INSERT OR REPLACE INTO device_profiles"
        " (mac, hour, avg_bytes, avg_contacts, days, built_ts)"
        " VALUES (?,?,?,?,?,?)",
        (mac, HOUR, avg_mb * 1e6, 3.0, days, NOW))


def run_and_report(name):
    detm.run_all(now=NOW)
    alerts = dbm.query(
        "SELECT kind, severity, title, meaning, is_normal, what_to_do"
        " FROM alerts ORDER BY ts")
    print(f"\n===== {name}: {len(alerts)} alerts =====")
    kinds = []
    for kind, sev, title, meaning, is_normal, what_to_do in alerts:
        kinds.append(kind)
        human = all([meaning, is_normal, what_to_do])
        print(f"  [{sev:8s}] {kind:22s} {title}"
              f"  human-readable={'YES' if human else 'NO <-- PROBLEM'}")
    return kinds


def check(name, kinds, must_fire, must_not_fire=()):
    ok = True
    for k in must_fire:
        if k not in kinds:
            print(f"  FAIL: expected '{k}' did not fire")
            ok = False
    for k in must_not_fire:
        if k in kinds:
            print(f"  FAIL: '{k}' fired but should have stayed quiet")
            ok = False
    print(f"  {'PASS' if ok else 'FAIL'}: {name}")
    return ok


def reset():
    if os.path.exists(SCRATCH):
        os.remove(SCRATCH)
    dbm._conn = None


results = []

# ---------------------------------------------------------------- home ---
reset()
TV = ("192.168.1.13", "aa:bb:cc:00:00:13")
known = [("192.168.1.10", "aa:bb:cc:00:00:10"),   # laptop
         ("192.168.1.11", "aa:bb:cc:00:00:11"),   # phone
         ("192.168.1.12", "aa:bb:cc:00:00:12"),   # roku
         TV]
seed_baseline("192.168.1", [("192.168.1.10", 2), ("192.168.1.11", 1),
                             ("192.168.1.12", 3), ("192.168.1.13", 3)])
seed_arp(known)
seed_profile(TV[1], avg_mb=40)  # TV usually ~40 MB/hr at this hour
keep_profiles_fresh()

# Attack 1: smart TV exfiltrating 4 GB in the last 5 minutes
dbm.insert_flows([flow(NOW - 120, TV[0], "45.155.204.9", 443,
                       4_000_000_000)])
# Attack 2: brand-new unknown device appears and talks on port 4444
dbm.insert_arp_observations([(NOW - 60, "192.168.1.99",
                              "de:ad:be:ef:00:99")])
dbm.insert_flows([flow(NOW - 600, "192.168.1.99", "91.203.67.4", 4444,
                       5_000_000)])
# Attack 3: laptop hammering DNS for a shady domain
dbm.insert_dns_queries(
    [(NOW - 300 + i, "192.168.1.10", "x7q-malware-c2.ru", "1")
     for i in range(250)])
# Normal DNS that must stay quiet
dbm.insert_dns_queries(
    [(NOW - 200 + i * 30, "192.168.1.10", "netflix.com", "1")
     for i in range(5)])

kinds = run_and_report("HOME NETWORK")
results.append(check(
    "home flags the attacks",
    kinds,
    must_fire=["traffic_spike", "behavior_deviation", "unusual_port",
               "dns_lookup_burst", "new_busy_domain", "new_device",
               "new_external_ip"]))
# rule-based summary must not crash on demo data
summary, origin = expl.summarize(save=True, now=NOW)
print(f"  summary [{origin}]: {summary['headline'][:90]}")

# ------------------------------------------------------------- business ---
reset()
POS, PC, SRV = "10.0.5.20", "10.0.5.21", "10.0.5.5"
WS, PRN = "10.0.5.22", "10.0.5.40"
staff = [(POS, "aa:bb:cc:00:00:20"), (PC, "aa:bb:cc:00:00:21"),
         (SRV, "aa:bb:cc:00:00:05"), (WS, "aa:bb:cc:00:00:22"),
         (PRN, "aa:bb:cc:00:00:40")]
seed_baseline("10.0.5", [(POS, 0.5), (PC, 2)])
seed_arp(staff)
# printer: local-only chatter, must stay silent
dbm.insert_flows([flow(NOW - m * 60, PRN, "10.0.5.21", 9100, 200_000,
                       direction="local")
                  for m in range(60, 0, -10)])

# Attack 1: POS terminal talking to Russia on port 4444 (80 MB)
dbm.insert_flows([flow(NOW - 600, POS, "185.220.70.5", 4444,
                       80_000_000)])
# Attack 2: RDP brute force hammering the office server (900 MB inbound)
dbm.insert_flows([flow(NOW - 120, "198.51.100.9", SRV, 3389, 900_000_000,
                       direction="inbound", sport=3389)])
# Attack 3: workstation beaconing to C2 every 5 min for an hour
for b in range(12):
    dbm.insert_flows([flow(NOW - b * 300 - 60, WS, "192.0.2.44", 8080,
                            50_000)])
# Vendor laptop joins (new device, benign)
dbm.insert_arp_observations([(NOW - 60, "10.0.5.30", "de:ad:be:ef:00:30")])
dbm.insert_flows([flow(NOW - 300, "10.0.5.30", "1.1.1.1", 443, 3_000_000)])

kinds = run_and_report("SMALL BUSINESS NETWORK")
results.append(check(
    "business flags the attacks",
    kinds,
    must_fire=["unusual_port", "traffic_spike", "beaconing",
               "new_device", "new_external_ip"]))
# printer must not appear in any alert detail/title
rows = dbm.query("SELECT title, detail FROM alerts")
noisy = [t for t, d in rows if PRN in (t or "") or PRN in (d or "")]
if noisy:
    print(f"  FAIL: printer {PRN} mentioned in alerts: {noisy}")
    results.append(False)
else:
    print(f"  PASS: printer {PRN} stayed quiet (local-only traffic)")
    results.append(True)

print("\n" + ("ALL DEMO TESTS PASSED" if all(results)
              else "SOME DEMO TESTS FAILED"))
os.remove(SCRATCH)
sys.exit(0 if all(results) else 1)
