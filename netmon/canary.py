"""netmon/canary.py -- a lightweight tripwire (Phase 3.5, batch 17).

Two traps, both local and passive. Real devices never touch them;
scanners do -- so a touch is a High alert by definition.

1. A fake open port: a TCP listener on a high, unusual port on the
   LAN interface. On accept it records the touch (source address,
   port, time), fires ONE High alert per source per day, and closes
   the socket IMMEDIATELY. The listener never reads, never writes,
   never serves a banner: there is no protocol to speak and no data
   to take, so it cannot be used for anything. It is a tripwire, not
   a service.

2. A fake credentials file: ``canary-passwords.txt`` in the config
   dir, full of obviously-fake secrets. The monitor loop watches its
   mtime; a change means something opened and rewrote it.

Safety rules (council-reviewed):
- Binds the LAN address (auto-detected), never 0.0.0.0: the trap is
  only reachable from the LAN it watches.
- A bind failure (port already in use) is one stderr line and a quiet
  disable -- never a crash, never an alert storm.
- The self-check's listening-port baseline excludes the canary port,
  so the trap never trips the "new listener" self-alert.
- No shell, no subprocess, no network calls. One daemon thread.

Config (config.yaml ``canary``): enabled (default true), port
(default 23231), bind (empty = auto-detect the LAN address).
"""
import os
import socket
import sys
import threading
import time

DEFAULT_PORT = 23231
TOUCH_COOLDOWN_S = 86400  # one alert per touching address per day

_lock = threading.Lock()
_state = {"thread": None, "stop": None, "sock": None,
          "port": None, "bind": None, "running": False,
          "touches": []}


def _config():
    """(enabled, port, bind) from config.yaml, with safe defaults."""
    try:
        from . import config as cfgm
        cfg = cfgm.load_cached()
        enabled = cfgm.get(cfg, "canary.enabled", True)
        port = int(cfgm.get(cfg, "canary.port", DEFAULT_PORT))
        bind = str(cfgm.get(cfg, "canary.bind", "") or "").strip()
        if not 1 <= port <= 65535:
            port = DEFAULT_PORT
        return bool(enabled), port, bind
    except Exception:
        return True, DEFAULT_PORT, ""


def _lan_bind_ip():
    """This box's LAN address for the trap. None when unknown."""
    try:
        from . import capture as capm
        for ip in sorted(capm.get_local_ips()):
            if ip.startswith("192.168.") or ip.startswith("10.") or \
                    ip.startswith("172."):
                return ip
    except Exception:
        pass
    return None


def canary_port():
    """The configured trap port (for the self-check exclusion)."""
    return _config()[1]


def is_running():
    with _lock:
        return bool(_state["running"]) and _state["thread"] is not None \
            and _state["thread"].is_alive()


def _toucher_label(ip):
    """Friendly name when the toucher is a known LAN device."""
    try:
        from . import db as dbm
        mac = (dbm.ip_to_mac_map() or {}).get(ip)
        name = (dbm.device_name_map() or {}).get(mac, "") if mac else ""
        if name:
            return f"{name} ({ip})"
    except Exception:
        pass
    return ip


def _record_touch(src_ip, src_port):
    """One touch of the trap: count it, alert (cooldown-guarded)."""
    now = time.time()
    with _lock:
        _state["touches"].append({"ip": src_ip, "port": src_port,
                                  "ts": now})
        _state["touches"] = _state["touches"][-100:]
    try:
        from . import db as dbm
        if dbm.recent_alert_kind("canary_touch", src_ip,
                                 TOUCH_COOLDOWN_S):
            return
        label = _toucher_label(src_ip)
        dbm.add_alert(
            "canary_touch", "High",
            f"Something touched the trap ({label})",
            (f"An address that should never knock here -- {src_ip},"
             f" port {src_port} -- connected to the fake open port"
             f" ({_state['port']}). The connection was closed"
             f" immediately; nothing was exchanged."),
            meaning=("The monitor leaves one fake door slightly open that"
                     " no real device should ever use. Phones, TVs,"
                     " laptops, and printers never knock on it. Scanners"
                     " do -- this looks like something actively looking"
                     " for a way in."),
            is_normal=("Not normal. The only benign cause is a port scan"
                       " you ran yourself, or a security tool sweeping the"
                       " network."),
            what_to_do=("Check the Devices page for the address above. If"
                        " you don't recognize it, consider isolating it"
                        " with the Isolate button -- and don't run port"
                        " scans yourself unless you want to trip the trap."),
            ts=now)
    except Exception as exc:
        try:
            print(f"netmon canary: touch handling failed: {exc!r}",
                  file=sys.stderr)
        except Exception:
            pass


def _serve(sock, stop_event):
    """Accept loop: record the touch, close immediately. Never reads,
    never writes -- there is nothing useful to do with the socket."""
    sock.settimeout(1.0)
    while not stop_event.is_set():
        try:
            conn, addr = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            break
        try:
            src_ip = addr[0] if addr else "unknown"
            src_port = addr[1] if addr and len(addr) > 1 else 0
        except Exception:
            src_ip, src_port = "unknown", 0
        try:
            conn.close()
        except Exception:
            pass
        _record_touch(src_ip, src_port)


def start(bind_ip=None):
    """Start the trap listener. Returns True when listening.

    bind_ip: explicit bind address (tests use 127.0.0.1). None =
    auto-detect the LAN address. Never raises.
    """
    enabled, port, cfg_bind = _config()
    if not enabled:
        return False
    bind = bind_ip or cfg_bind or _lan_bind_ip()
    if not bind:
        try:
            print("netmon canary: no LAN address found; trap disabled",
                  file=sys.stderr)
        except Exception:
            pass
        return False
    if bind in ("0.0.0.0", "::"):
        # Never a wildcard bind: the trap watches the LAN, and a
        # wildcard could expose it on a public interface.
        try:
            print(f"netmon canary: refusing wildcard bind {bind};"
                  " set canary.bind to the LAN address",
                  file=sys.stderr)
        except Exception:
            pass
        return False
    with _lock:
        if _state["running"]:
            return True
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((bind, port))
            sock.listen(5)
        except OSError as exc:
            try:
                print(f"netmon canary: can't listen on {bind}:{port}"
                      f" ({exc}); trap disabled", file=sys.stderr)
            except Exception:
                pass
            try:
                sock.close()
            except Exception:
                pass
            return False
        stop = threading.Event()
        thread = threading.Thread(target=_serve, args=(sock, stop),
                                  name="canary", daemon=True)
        _state.update(thread=thread, stop=stop, sock=sock, port=port,
                      bind=bind, running=True)
        thread.start()
        return True


def stop():
    """Stop the trap listener. Never raises."""
    with _lock:
        _state["running"] = False
        stop_ev, sock = _state["stop"], _state["sock"]
        _state["thread"], _state["stop"], _state["sock"] = None, None, None
    try:
        if stop_ev is not None:
            stop_ev.set()
    except Exception:
        pass
    try:
        if sock is not None:
            sock.close()
    except Exception:
        pass


def ensure_running():
    """Monitor-loop step: restart the trap if it died. Never raises."""
    try:
        if not is_running():
            start()
    except Exception:
        pass


def status():
    """Trap state for the dashboard sensor-health view. Never raises."""
    with _lock:
        touches = list(_state["touches"])[-5:]
        running = bool(_state["running"])
        port, bind = _state["port"], _state["bind"]
    try:
        enabled, cfg_port, _ = _config()
    except Exception:
        enabled, cfg_port = True, DEFAULT_PORT
    return {"enabled": enabled, "running": running,
            "port": port or cfg_port, "bind": bind or "",
            "recent_touches": touches}


# --- the fake credentials file -----------------------------------------------
# Obviously-fake secrets in the config dir. The monitor loop watches
# the mtime; a change means something opened and rewrote it.

_CANARY_FILENAME = "canary-passwords.txt"
_CANARY_CONTENT = """\
# !!! THESE ARE FAKE -- TRIPWIRE FILE !!!
# This file is bait. It is full of made-up secrets so the network
# monitor can tell if something is snooping around the computer.
# Nothing in here is real. Do not "use" any of it.

wifi_password = hunter2-hunter2-fake
router_admin = admin / definitely-not-real-12345
nas_backup_key = FAKER-FAKER-FAKER-0000
"""


def canary_file_path():
    try:
        from . import config as cfgm
        base = cfgm.config_dir()
    except Exception:
        base = os.path.expanduser("~/.config/brutedash")
    return os.path.join(str(base), _CANARY_FILENAME)


def ensure_canary_file():
    """Create the bait file once (never overwrite -- an existing file
    with different content is exactly what we're watching for)."""
    path = canary_file_path()
    try:
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(_CANARY_CONTENT)
            os.chmod(path, 0o600)
    except Exception:
        pass
    return path


def check_canary_file(now=None):
    """Monitor-loop step: has the bait file changed? Never raises."""
    now = now if now is not None else time.time()
    path = ensure_canary_file()
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return
    try:
        from . import db as dbm
        last = dbm.get_meta("canary_file_mtime")
        if last is None:
            dbm.set_meta("canary_file_mtime", str(mtime))
            return
        if abs(mtime - float(last)) < 1:
            return
        dbm.set_meta("canary_file_mtime", str(mtime))
        if dbm.recent_alert_kind("canary_touch", "bait-file",
                                 TOUCH_COOLDOWN_S):
            return
        dbm.add_alert(
            "canary_touch", "High",
            "Something opened the fake passwords file",
            ("The bait credentials file changed -- something on this"
             " computer opened and rewrote it. The secrets inside are"
             " fake, so nothing real leaked; the touch itself is the"
             " signal."),
            meaning=("The monitor keeps a file of made-up passwords as a"
                     " tripwire. Nothing legitimate ever touches it, so a"
                     " change means something was snooping around the"
                     " computer."),
            is_normal=("Not normal. The only benign cause is you opening"
                       " it yourself out of curiosity."),
            what_to_do=("Think about what ran on this computer recently."
                        " If nothing explains it, run a full Defender scan"
                        " -- and don't put real secrets in odd files."),
            ts=now)
    except Exception:
        pass
