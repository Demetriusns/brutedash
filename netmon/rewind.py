"""netmon/rewind.py -- forensic rewind: a bounded rolling packet buffer.

When enabled, live capture keeps the last N minutes of RAW packets on
disk so a case can be rewound after the fact ("what did that device
actually send during the incident?"). From a case view, "download
packets from this case's window" exports that time slice as a .pcap you
can open in Wireshark.

Storage is HARD-BOUNDED: the buffer is a ring of segment files and the
oldest segments are evicted whenever EITHER cap is hit:

  - rewind_minutes (default 60): segments older than this are deleted.
  - rewind_max_mb (default 256): the whole directory is kept under this.

Whichever fills first wins. There is no unbounded growth: eviction runs
on every segment rotation and on a schedule from run.py's monitor loop,
plus a low-disk guard pauses recording when the disk is nearly full.

Privacy: this buffer holds RAW packets from YOUR OWN network -- website
addresses, unencrypted content, everything the wire carried. It lives
only on this box, it is never sent anywhere, and it deletes itself as
it fills. The dashboard says exactly this before offering a download.

Only live capture writes here (run_live); --pcap analysis mode never
touches the buffer (that is someone else's capture, not your network).
"""
import os
import struct
import threading
import time
from pathlib import Path

from . import config as cfgm

# pcap global header, little-endian: magic, ver 2.4, tz 0, sigfigs 0,
# snaplen 65535, network 1 (Ethernet).
_GLOBAL_HDR = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
_REC_HDR = struct.Struct("<IIII")  # ts_sec, ts_usec, incl_len, orig_len
SNAPLEN = 65535

SEGMENT_SECONDS = 300          # rotate the segment file every 5 minutes
SEGMENT_MAX_BYTES = 64 * 1024 * 1024   # ...or when a segment passes 64 MB
MIN_FREE_MB = 256              # stop recording when the disk is this full
EXPORT_MAX_BYTES = 512 * 1024 * 1024   # never build an export bigger than this
FLUSH_EVERY_PACKETS = 64
FLUSH_EVERY_SECONDS = 5.0

_lock = threading.Lock()
_ENABLED = False               # set by refresh(); capture checks this
_seg_file = None               # open file handle for the current segment
_seg_start = 0                 # epoch the current segment started
_seg_bytes = 0
_seg_since_flush = 0
_seg_last_flush = 0.0


def refresh():
    """Re-read the enabled flag from config. Called at import and on a
    schedule from run.py; capture's hot path only reads _ENABLED."""
    global _ENABLED
    try:
        _ENABLED = bool(cfgm.get(cfgm.load_cached(), "reporting.rewind_enabled",
                                 False))
    except Exception:
        _ENABLED = False
    return _ENABLED


refresh()


def enabled():
    """True when the forensic buffer is recording (hot-path cheap)."""
    return _ENABLED


def rewind_dir():
    """Directory holding the segment files. Created on demand."""
    override = ""
    try:
        override = (cfgm.get(cfgm.load_cached(), "reporting.rewind_dir", "")
                    or "").strip()
    except Exception:
        override = ""
    d = Path(override) if override else (cfgm.config_dir() / "rewind")
    try:
        d.mkdir(parents=True, exist_ok=True)
    except OSError:
        pass
    return d


def _caps():
    """(max_minutes, max_bytes) from config, with sane fallbacks."""
    try:
        cfg = cfgm.load_cached()
        minutes = float(cfgm.get(cfg, "reporting.rewind_minutes", 60) or 60)
        mb = float(cfgm.get(cfg, "reporting.rewind_max_mb", 256) or 256)
    except Exception:
        minutes, mb = 60.0, 256.0
    return max(1.0, minutes), max(1.0, mb) * 1024 * 1024


def _segments(directory):
    """Sorted [(start_epoch, Path)] of segment files; junk names ignored.
    Names are seg_<epoch>.pcap or seg_<epoch>_<n>.pcap (same-second
    rotations get a suffix)."""
    out = []
    try:
        names = os.listdir(directory)
    except OSError:
        return out
    for name in names:
        if not (name.startswith("seg_") and name.endswith(".pcap")):
            continue
        try:
            start = int(name[4:-5].split("_")[0])
        except ValueError:
            continue  # not ours / malformed: leave it alone
        out.append((start, name, Path(directory) / name))
    out.sort()
    return [(start, path) for start, _name, path in out]


def _disk_ok(directory):
    """False when the disk is nearly full -- recording pauses."""
    try:
        free_mb = __import__("shutil").disk_usage(str(directory)).free / (
            1024 * 1024)
        return free_mb >= MIN_FREE_MB
    except Exception:
        return True  # can't tell: keep recording rather than break


def _rotate(now):
    """Close the current segment, open a fresh one. Caller holds _lock."""
    global _seg_file, _seg_start, _seg_bytes, _seg_since_flush, _seg_last_flush
    if _seg_file is not None:
        try:
            _seg_file.flush()
            _seg_file.close()
        except Exception:
            pass
        _seg_file = None
    _seg_start = int(now)
    _seg_bytes = 0
    _seg_since_flush = 0
    _seg_last_flush = now
    directory = rewind_dir()
    # Unique name: two rotations can land in the same second (busy
    # networks, tiny test segments). A second global header appended
    # mid-file would corrupt the segment, so collide -> suffix.
    base = f"seg_{_seg_start:010d}"
    path = directory / f"{base}.pcap"
    n = 0
    while path.exists():
        n += 1
        path = directory / f"{base}_{n}.pcap"
    try:
        _seg_file = open(path, "ab")
        _seg_file.write(_GLOBAL_HDR)
        _seg_bytes = len(_GLOBAL_HDR)
    except OSError:
        _seg_file = None


def record_packet(raw, ts=None):
    """Append one raw packet (bytes) with timestamp ts (epoch float).

    No-op unless the buffer is enabled. Never raises: the capture path
    must not break because the forensic buffer had a bad day. Packets
    are truncated to the 64KB snaplen (a jumbo frame's tail is not
    forensically interesting, and it bounds per-packet cost).
    """
    if not _ENABLED:
        return
    try:
        data = bytes(raw or b"")
    except Exception:
        return
    if not data:
        return
    now = time.time()
    ts = float(ts) if ts is not None else now
    if len(data) > SNAPLEN:
        data = data[:SNAPLEN]
    global _seg_file, _seg_start, _seg_bytes
    global _seg_since_flush, _seg_last_flush
    did_rotate = False
    with _lock:
        try:
            rotate = (_seg_file is None
                      or now - _seg_start >= SEGMENT_SECONDS
                      or _seg_bytes >= SEGMENT_MAX_BYTES)
            if rotate:
                # Disk guard runs at rotation time (not per packet: one
                # disk_usage call every few minutes, not thousands per
                # second). When the disk is nearly full we write nothing
                # -- not even an empty segment file.
                if not _disk_ok(rewind_dir()):
                    return
                _rotate(now)
                did_rotate = True
            if _seg_file is None:
                return
            sec = int(ts)
            usec = int((ts - sec) * 1_000_000)
            _seg_file.write(_REC_HDR.pack(sec, usec, len(data), len(data)))
            _seg_file.write(data)
            _seg_bytes += _REC_HDR.size + len(data)
            _seg_since_flush += 1
            if (_seg_since_flush >= FLUSH_EVERY_PACKETS
                    or now - _seg_last_flush >= FLUSH_EVERY_SECONDS):
                _seg_file.flush()
                _seg_since_flush = 0
                _seg_last_flush = now
        except Exception:
            pass
    # Enforce the storage caps on every rotation, outside the lock
    # (enforce_caps takes _lock itself; the lock is not reentrant).
    # run.py's monitor loop also sweeps every 60s as a backstop.
    if did_rotate:
        try:
            enforce_caps(now=now)
        except Exception:
            pass


def maybe_record(pkt):
    """Capture-path entry: record one scapy packet if enabled. Cheap
    no-op when disabled. Never raises."""
    if not _ENABLED:
        return
    try:
        ts = float(getattr(pkt, "time", None) or time.time())
        record_packet(bytes(pkt), ts)
    except Exception:
        pass


def enforce_caps(now=None):
    """Delete oldest segments until both caps hold. Returns (kept, freed
    bytes). Never raises. Called on rotation and from run.py's loop."""
    now = now if now is not None else time.time()
    max_minutes, max_bytes = _caps()
    directory = rewind_dir()
    freed = 0
    with _lock:
        segs = _segments(directory)
        # Time cap first: anything older than the window goes.
        cutoff = now - max_minutes * 60
        fresh = []
        for start, path in segs:
            if start < cutoff:
                try:
                    freed += path.stat().st_size
                    path.unlink()
                except OSError:
                    fresh.append((start, path))
            else:
                fresh.append((start, path))
        # Size cap: keep deleting the oldest until we're under.
        try:
            total = sum(p.stat().st_size for _, p in fresh)
        except OSError:
            total = 0
        kept = list(fresh)
        while kept and total > max_bytes:
            _start, path = kept.pop(0)
            try:
                size = path.stat().st_size
                path.unlink()
                total -= size
                freed += size
            except OSError:
                pass
    return len(kept), freed


def _iter_segment_packets(path):
    """Yield (ts, data) for each record in a segment file. Defensive:
    a truncated tail (crash mid-write) stops iteration, never raises."""
    try:
        with open(path, "rb") as f:
            blob = f.read()
    except OSError:
        return
    off = len(_GLOBAL_HDR)
    if blob[:off] != _GLOBAL_HDR:
        return  # not a segment we wrote
    n = len(blob)
    while off + _REC_HDR.size <= n:
        sec, usec, incl, _orig = _REC_HDR.unpack_from(blob, off)
        off += _REC_HDR.size
        if incl > SNAPLEN or off + incl > n:
            break  # corrupt or truncated tail: stop, don't raise
        yield sec + usec / 1_000_000, blob[off:off + incl]
        off += incl


def export_window(start_ts, end_ts):
    """Build a .pcap of packets with start_ts <= ts <= end_ts.

    Returns (pcap_bytes, packet_count). Bounded: the export never exceeds
    EXPORT_MAX_BYTES (packets past that are dropped, count notes it).
    An empty window still returns a valid pcap (header only) -- it opens
    cleanly in Wireshark instead of 404ing.
    """
    start_ts = float(start_ts)
    end_ts = float(end_ts)
    if end_ts < start_ts:
        start_ts, end_ts = end_ts, start_ts
    out = bytearray(_GLOBAL_HDR)
    count = 0
    with _lock:
        segs = _segments(rewind_dir())
        for start, path in segs:
            # A segment covers at most SEGMENT_SECONDS after its start;
            # include it if that span can overlap the window (per-packet
            # timestamps do the exact filtering below).
            if start > end_ts or start + SEGMENT_SECONDS < start_ts:
                continue
            for ts, data in _iter_segment_packets(path):
                if not (start_ts <= ts <= end_ts):
                    continue
                need = _REC_HDR.size + len(data)
                if len(out) + need > EXPORT_MAX_BYTES:
                    break
                sec = int(ts)
                usec = int((ts - sec) * 1_000_000)
                out += _REC_HDR.pack(sec, usec, len(data), len(data))
                out += data
                count += 1
    return bytes(out), count


def incident_window(incident_id):
    """(start, end) timestamps for a case, or None if it doesn't exist.

    The window runs from the case's first member alert to its last,
    padded by 5 minutes on each side so the trigger packets are in frame.
    """
    try:
        from . import db as dbm
        case = dbm.get_incident(int(incident_id))
    except Exception:
        return None
    if not case or not case.get("alerts"):
        return None
    times = [a["ts"] for a in case["alerts"] if a.get("ts")]
    if not times:
        return None
    return min(times) - 300, max(times) + 300


def status(now=None):
    """Dashboard read: {enabled, retention label, segments, bytes kept}."""
    now = now if now is not None else time.time()
    max_minutes, max_bytes = _caps()
    with _lock:
        segs = _segments(rewind_dir())
        total = 0
        for _, p in segs:
            try:
                total += p.stat().st_size
            except OSError:
                pass
        oldest = segs[0][0] if segs else None
    if max_minutes >= 60:
        time_part = (f"{int(max_minutes // 60)} hour"
                     f"{'s' if max_minutes >= 120 else ''}")
    else:
        time_part = f"{int(max_minutes)} minutes"
    return {
        "enabled": _ENABLED,
        "retention": (f"Keeps the last {time_part} of packets or"
                      f" {int(max_bytes / 1024 / 1024)} MB on disk,"
                      " whichever fills first -- oldest packets are"
                      " deleted automatically."),
        "segments": len(segs),
        "bytes_kept": total,
        "oldest_ts": oldest,
        "privacy_note": (
            "This buffer holds RAW packets from your own network --"
            " website addresses, unencrypted content, everything the wire"
            " carried. It lives only on this box, it is never sent"
            " anywhere, and it deletes itself as it fills."),
    }


def _reset_for_tests():
    """Close the current segment. Tests only."""
    global _seg_file, _seg_start, _seg_bytes, _seg_since_flush, _seg_last_flush
    global _ENABLED
    with _lock:
        if _seg_file is not None:
            try:
                _seg_file.flush()
                _seg_file.close()
            except Exception:
                pass
        _seg_file = None
        _seg_start = 0
        _seg_bytes = 0
        _seg_since_flush = 0
        _seg_last_flush = 0.0
        _ENABLED = False
