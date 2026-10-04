"""netmon/quarantine.py -- one-click per-device quarantine (ARP isolation).

THE core safety rule: approval-only. A human clicks "Isolate" on the
dashboard; nothing in this repo may ever quarantine a device on its own.
The ONLY code path that calls request_quarantine() / release_quarantine()
is the dashboard route (tests/test_response.py enforces this by
inspecting the source tree -- add a caller and the suite goes red).

How it works (descendant of the 2026-09-30 kill-switch test, which ARP-
spoofed the whole LAN through bettercap): to isolate ONE device we send
two forged ARP replies -- one tells the device "the router is at MY
hardware address", one tells the router "that device is at MY hardware
address". Both sides then send the device's internet traffic to this box,
which simply drops it. The device can still talk to other devices on the
home network directly; its internet access is what's cut.

Re-poisoning: ARP entries expire, so a daemon thread re-sends the forged
replies every POISON_INTERVAL_S for every device whose quarantines row is
'active'. The thread only ever re-enforces rows a human created -- it
creates nothing on its own.

Release: we send the CORRECT mappings a few times ("no really, the router
is at the router's address"), the entries heal, and the row flips to
'released'. Full access comes back in seconds.

HARD SAFETY RULES (enforced in safety_check, not just the UI):
  * never the gateway -- isolating the router would take the whole
    network down;
  * never this box itself (the sensor running brutedash);
  * never the device the dashboard viewer is browsing from (lockout
    protection -- isolating your own laptop while you stare at the
    dashboard would be a very bad afternoon);
  * never a device the monitor has never seen (no blind firing).

Everything -- granted, refused, and released -- is written to the
append-only audit log (netmon/db.py audit()).

No subprocesses, no shell: packets go out through scapy's sendp, and the
send function is a module-level indirection (_SENDP) so tests and the
smoke boot can record packets without ever touching a real network.
"""

import re
import threading
import time
import uuid

from . import db as dbm

MAC_RE = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")

# How often the worker re-sends forged ARP replies (ARP entries age out).
POISON_INTERVAL_S = 10
# Restore bursts on release: correct mappings, sent this many times.
RESTORE_BURSTS = 3

# Packet sink. None = really send via scapy. Tests and the smoke boot set
# this to a recorder so no packet ever touches a real network there.
_SENDP = None


def _sendp(pkt):
    """Send one packet, or hand it to the test recorder."""
    fn = _SENDP
    if fn is not None:
        fn(pkt)
        return
    from scapy.all import sendp  # pinned dependency; ImportError -> caller
    sendp(pkt, verbose=False)


def _own_mac():
    """This box's MAC on the sniffed interface, best effort."""
    try:
        from scapy.all import conf, get_if_hwaddr
        mac = get_if_hwaddr(conf.iface)
        if mac and MAC_RE.match(str(mac).lower()):
            return str(mac).lower()
    except Exception:
        pass
    try:
        n = uuid.getnode()
        return ":".join(("%012x" % n)[i:i + 2] for i in range(0, 12, 2))
    except Exception:
        return None


def _own_ips():
    """IPs that mean 'this box' -- never quarantine these."""
    ips = {"127.0.0.1", "::1"}
    try:
        from . import relay as relaym
        ip = relaym._default_ip()
        if ip:
            ips.add(ip)
    except Exception:
        pass
    return ips


def _gateway():
    """(ip, mac) of the router, or (None, None). Never raises."""
    try:
        from . import topology as topom
        return topom.gateway_info()
    except Exception:
        return None, None


def _device_ip(mac):
    """Most recently seen IP for a MAC, or None if never observed."""
    try:
        rows = dbm.query(
            "SELECT ip FROM arp_observations WHERE mac=?"
            " ORDER BY ts DESC LIMIT 1", (mac,))
    except Exception:
        return None
    if rows and rows[0][0]:
        return rows[0][0]
    return None


def _viewer_mac(viewer_ip):
    """The MAC of whoever is viewing the dashboard, best effort."""
    if not viewer_ip:
        return None
    try:
        return dbm.ip_to_mac_map().get(viewer_ip)
    except Exception:
        return None


def safety_check(mac, viewer_ip):
    """(ok, reason): may this device be isolated?

    Returns (True, "") when it's safe, else (False, plain-English reason
    for the UI). The dashboard calls this AND request_quarantine calls it
    again -- the check lives server-side so a crafted POST can't skip it.
    """
    mac = (mac or "").strip().lower()
    if not MAC_RE.match(mac):
        return False, "That doesn't look like a device address."
    ip = _device_ip(mac)
    if not ip:
        return False, ("I haven't seen that device on the network -- I only"
                       " isolate devices I've actually observed.")
    gw_ip, gw_mac = _gateway()
    if (gw_mac and mac == gw_mac.lower()) or (gw_ip and ip == gw_ip):
        return False, ("That's your router -- isolating it would take the"
                       " whole network down, so that's not allowed.")
    own_mac = _own_mac()
    if (own_mac and mac == own_mac) or ip in _own_ips():
        return False, ("That's this monitor box itself -- isolating it"
                       " would blind the monitor and kill the dashboard"
                       " you're looking at.")
    viewer_mac = (_viewer_mac(viewer_ip) or "").lower()
    if (viewer_mac and mac == viewer_mac) or (viewer_ip and ip == viewer_ip):
        return False, ("That's the device you're browsing from -- isolating"
                       " it would lock you out of this dashboard mid-click.")
    return True, ""


def _arp_packets(target_mac, target_ip, gw_ip, gw_mac, own_mac, poison):
    """Forged (poison=True) or corrective (poison=False) ARP replies.

    Returns a list of scapy packets. When the gateway MAC is unknown we
    can only poison the target side -- enough to kill its outbound, which
    is what "cut off from the internet" means.
    """
    from scapy.all import ARP, Ether
    pkts = []
    if poison:
        # Target: "the router is at MY address."
        pkts.append(Ether(dst=target_mac) / ARP(
            op=2, psrc=gw_ip, pdst=target_ip,
            hwsrc=own_mac, hwdst=target_mac))
        if gw_mac:
            # Router: "that device is at MY address."
            pkts.append(Ether(dst=gw_mac) / ARP(
                op=2, psrc=target_ip, pdst=gw_ip,
                hwsrc=own_mac, hwdst=gw_mac))
    else:
        # Tell the truth, loudly: router is at the router's address...
        pkts.append(Ether(dst=target_mac) / ARP(
            op=2, psrc=gw_ip, pdst=target_ip,
            hwsrc=gw_mac, hwdst=target_mac))
        if gw_mac:
            # ...and the device is at the device's address.
            pkts.append(Ether(dst=gw_mac) / ARP(
                op=2, psrc=target_ip, pdst=gw_ip,
                hwsrc=target_mac, hwdst=gw_mac))
    return pkts


def _poison(mac, ip):
    """Send one round of forged ARP replies for an isolated device."""
    own_mac = _own_mac()
    if not own_mac:
        raise RuntimeError("could not determine this box's hardware address")
    gw_ip, gw_mac = _gateway()
    if not gw_ip:
        raise RuntimeError("could not determine the router's address")
    for pkt in _arp_packets(mac, ip, gw_ip,
                            (gw_mac or "").lower() or None, own_mac,
                            poison=True):
        _sendp(pkt)


def _restore(mac, ip):
    """Send corrective ARP replies so the device heals."""
    gw_ip, gw_mac = _gateway()
    if not gw_ip or not gw_mac:
        return  # without the real mapping there's nothing true to say
    for _ in range(RESTORE_BURSTS):
        for pkt in _arp_packets(mac, ip, gw_ip, gw_mac.lower(), None,
                                poison=False):
            try:
                _sendp(pkt)
            except Exception:
                pass
        time.sleep(0.2)


def request_quarantine(mac, actor, viewer_ip):
    """Isolate one device. THE approval-only entry point.

    Only the dashboard route calls this (see module docstring). Returns
    (True, message) on success, (False, plain-English reason) when the
    safety check refuses or the network layer fails. Every outcome is
    audit-logged.
    """
    mac = (mac or "").strip().lower()
    actor = actor or "dashboard"
    ok, reason = safety_check(mac, viewer_ip)
    if not ok:
        dbm.audit("quarantine_refused", actor, mac, reason)
        return False, reason
    ip = _device_ip(mac)
    try:
        _poison(mac, ip)
    except Exception as exc:
        msg = f"Couldn't isolate it: {exc}"
        dbm.audit("quarantine_refused", actor, mac, msg)
        return False, msg
    dbm.quarantine_upsert(mac, ip, actor,
                          note=f"isolated from dashboard ({viewer_ip or '?'})")
    dbm.audit("quarantine", actor, mac,
              f"isolated {mac} ({ip}); re-poison every"
              f" {POISON_INTERVAL_S}s until released")
    ensure_worker()
    return True, (f"{mac} is isolated -- cut off from the internet. Click"
                  f" Release on its device row any time to bring it back.")


def release_quarantine(mac, actor):
    """Lift the isolation. Returns (True, message) / (False, reason)."""
    mac = (mac or "").strip().lower()
    actor = actor or "dashboard"
    q = dbm.get_quarantine(mac)
    if not q or q["state"] != "active":
        return False, "That device isn't isolated right now."
    try:
        _restore(mac, q.get("ip") or "")
    except Exception:
        pass  # the row still flips; entries heal on their own shortly
    dbm.quarantine_release(mac, actor, note="released from dashboard")
    dbm.audit("release", actor, mac,
              f"isolation lifted for {mac}; corrective ARP sent")
    return True, f"{mac} is back -- full network access restored."


# --- re-poison worker -------------------------------------------------------
# Daemon thread. Re-sends forged replies for every 'active' row so the
# isolation survives ARP expiry. It NEVER creates isolations -- rows only
# appear via request_quarantine(), i.e. via a human click.

_worker_lock = threading.Lock()
_worker_thread = None
_worker_stop = threading.Event()


def _worker_loop():
    while not _worker_stop.wait(POISON_INTERVAL_S):
        try:
            active = dbm.active_quarantines()
        except Exception:
            continue
        for q in active:
            try:
                _poison(q["mac"], q["ip"])
            except Exception:
                pass  # next tick retries; never let one device kill the loop


def ensure_worker():
    """Start the re-poison worker if it isn't running. Safe to call any
    number of times, from anywhere -- it does nothing until a human has
    isolated a device."""
    global _worker_thread
    with _worker_lock:
        if _worker_thread is not None and _worker_thread.is_alive():
            return
        _worker_stop.clear()
        _worker_thread = threading.Thread(target=_worker_loop,
                                          name="quarantine-worker",
                                          daemon=True)
        _worker_thread.start()


def _reset_for_tests():
    """Stop the worker thread. Tests only -- never called in production."""
    global _worker_thread
    _worker_stop.set()
    with _worker_lock:
        t, _worker_thread = _worker_thread, None
    if t is not None:
        t.join(timeout=5)
    _worker_stop.clear()
