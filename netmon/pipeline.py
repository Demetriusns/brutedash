"""netmon/pipeline.py -- detection-pipeline robustness.

Failure modes, fallback chains, and observability for the
capture -> parse -> rules -> alert -> incident -> notify -> dashboard
pipeline. The full enumeration lives in docs/PIPELINE-FAILURE-MODES.md;
this module is the code half.

What lives here:
  * trace_id: one uuid4-hex id minted at rule-fire time (db.add_alert),
    carried on alerts -> incidents -> notifications, so a single
    detection can be followed end to end. The dashboard shows it as the
    "Follow-up ID". It NEVER goes into external sends (emails/feeds) --
    it is an internal tracking id, and there is a test proving emails
    don't carry it.
  * watermarks: per-stage "last healthy" timestamps -- capture tick,
    rule pass, feed refresh, notification. The dashboard's sensor-health
    view reads them. A stage silent too long raises ONE self-alert, then
    stays quiet until it recovers.
  * disk guard: when the disk is nearly full, non-essential writes stop
    (the rewind buffer pauses first -- it has its own guard), one
    self-alert fires, detection keeps running. The disk-full path is
    allocation-light by design: one stat call, small strings, one small
    row; if even that write fails, the stderr line is the record.
  * capture watchdog: restarts a dead capture thread, bounded (max 3
    restarts per hour), then gives up quietly -- the stale-capture
    watermark raises the self-alert instead of a restart storm.
  * safe_step: run one pipeline step; on failure log one stderr line and
    continue. Fallback transitions log; they don't page the user --
    except the disk-full and stale-stage self-alerts, which are the two
    cases worth waking someone over.

Stdlib only. Nothing here raises out of its public helpers.
"""
import os
import sys
import time
import uuid

from . import db as dbm

# --- trace ids ---------------------------------------------------------------
# Minted at rule-fire time inside db.add_alert (uuid4 hex, 32 chars, no
# dashes -- cheap, no new deps). Carried: alerts.trace_id ->
# incident_alerts.trace_id -> notify hook dict -> stderr log lines ->
# dashboard alert detail ("Follow-up ID").

_TRACE_ID_LEN = 32


def new_trace_id():
    """One fresh trace id. Never raises."""
    try:
        return uuid.uuid4().hex
    except Exception:
        # uuid4 should not fail; if it does, fall back to something
        # unique-enough rather than breaking the alert path.
        return "%032x" % (int(time.time() * 1000) & 0xFFFFFFFFFFFFFFFF)


def is_trace_id(value):
    """True for a well-formed trace id (32 hex chars)."""
    if not isinstance(value, str) or len(value) != _TRACE_ID_LEN:
        return False
    try:
        int(value, 16)
        return True
    except (TypeError, ValueError):
        return False


def _log(msg):
    """One stderr line. Fallback transitions log; they don't alert."""
    try:
        print(f"netmon pipeline: {msg}", file=sys.stderr)
    except Exception:
        pass


# --- watermarks: per-stage liveness -------------------------------------------
# "Last healthy" timestamps. capture reuses last_flow_ts (the capture
# flush already writes it); feeds reuses ti_feeds_refreshed_ts (the feed
# refresh already writes it). Only rules/notify are written here.
#
# A missing watermark is "unknown" (never stale): a fresh install or a
# stage that was never healthy must not page on day one.

STAGES = {
    "capture": {"label": "Capture (seeing traffic)",
                "stale_after_s": 5 * 60,
                "meta_key": "last_flow_ts"},
    "rules": {"label": "Detection rules",
              "stale_after_s": 5 * 60,
              "meta_key": "wm_rules_ts"},
    "feeds": {"label": "Threat-intel feeds",
              "stale_after_s": 36 * 3600,
              "meta_key": "ti_feeds_refreshed_ts"},
    "notify": {"label": "Email notifications",
               "stale_after_s": 24 * 3600,
               "meta_key": "wm_notify_ts"},
}

_SELF_SEV = {"capture": "High", "rules": "Medium", "feeds": "Low",
             "notify": "Medium", "loop": "High"}


def mark(stage):
    """Record stage `stage` as healthy right now. Never raises."""
    try:
        spec = STAGES[stage]
    except KeyError:
        return
    try:
        dbm.set_meta(spec["meta_key"], str(time.time()))
    except Exception:
        pass


def watermark(stage, now=None):
    """(last_ts|None, age_s|None) for a stage. Never raises."""
    now = now if now is not None else time.time()
    try:
        raw = dbm.get_meta(STAGES[stage]["meta_key"])
        last = float(raw) if raw else 0.0
    except (KeyError, TypeError, ValueError):
        return None, None
    except Exception:
        return None, None
    if last <= 0:
        return None, None
    age = now - last
    if age < 0:
        age = 0.0  # clock jumped backwards; never report a negative age
    return last, age


def is_stale(stage, now=None):
    """True when a stage was healthy before but has been silent too long.
    A stage with no watermark yet is unknown, never stale."""
    now = now if now is not None else time.time()
    try:
        threshold = STAGES[stage]["stale_after_s"]
    except KeyError:
        return False
    _last, age = watermark(stage, now=now)
    return age is not None and age > threshold


def stale_stages(now=None, capture_expected=True):
    """Every stale stage: [{stage, label, last_ts, age_s}]. Never raises.

    capture_expected=False (dashboard-only mode) skips the capture stage:
    an intentionally-stopped capture is not a failure.
    """
    now = now if now is not None else time.time()
    out = []
    try:
        for stage, spec in STAGES.items():
            if stage == "capture" and not capture_expected:
                continue
            if is_stale(stage, now=now):
                last, age = watermark(stage, now=now)
                out.append({"stage": stage, "label": spec["label"],
                            "last_ts": last, "age_s": age})
    except Exception as exc:
        _log(f"stale_stages failed: {exc!r}")
    return out


def _age_words(age_s):
    if age_s is None:
        return "no data yet"
    if age_s < 90:
        return "just now"
    if age_s < 3600:
        return f"{int(age_s // 60)} minutes ago"
    if age_s < 86400:
        return f"{int(age_s // 3600)} hours ago"
    return f"{int(age_s // 86400)} days ago"


def health_snapshot(now=None, capture_expected=True):
    """Dashboard sensor-health payload: one row per stage.

    [{stage, label, last_ts, age_s, state, note}] where state is
    ok | stale | unknown. Never raises.
    """
    now = now if now is not None else time.time()
    rows = []
    try:
        for stage, spec in STAGES.items():
            if stage == "capture" and not capture_expected:
                rows.append({"stage": stage, "label": spec["label"],
                             "last_ts": None, "age_s": None,
                             "state": "unknown",
                             "note": "capture not running in this mode"})
                continue
            last, age = watermark(stage, now=now)
            if age is None:
                state, note = "unknown", "no data yet"
            elif age > spec["stale_after_s"]:
                state = "stale"
                note = f"silent for {_age_words(age)} -- needs a look"
            else:
                state, note = "ok", f"healthy {_age_words(age)}"
            rows.append({"stage": stage, "label": spec["label"],
                         "last_ts": last, "age_s": age,
                         "state": state, "note": note})
    except Exception as exc:
        _log(f"health_snapshot failed: {exc!r}")
    return rows


# --- loop watchdog: "the monitor itself went quiet" -------------------------------
# Batch 16. The stale-stage checks above catch a sick pipeline, but they
# all run INSIDE the monitor loop -- if the loop thread itself dies, none
# of them run. This is the independent layer: the loop stamps a tick
# watermark every pass and leaves a pid file at startup (removed on clean
# shutdown). The dashboard -- which usually outlives a dead loop thread --
# checks both on every page view (cached, 60s): pid file present + tick
# stale = the monitor stopped, one High self-alert per episode.
#
# Design notes:
#   * A missing tick watermark is "unknown", never stale: a fresh install
#     or a loop that never ticked must not page on day one.
#   * A clean shutdown removes the pid file, so a deliberately-stopped
#     monitor never pages. A crash leaves the pid file behind -- that is
#     exactly the case this catches.
#   * If the whole process died, nothing local can page -- that is what
#     the external heartbeat (health.py) is for. This layer covers the
#     loop-thread-died-but-dashboard-alive case.

LOOP_STALE_S = 10 * 60  # the loop ticks every 60s; 10x is unambiguously dead
_LOOP_PID_NAME = "loop.pid"
_LOOP_TICK_KEY = "wm_loop_ts"
_LOOP_DOWN_FLAG = "loop_down_alerted_ts"


def _loop_pid_path():
    from . import config as cfgm
    return cfgm.config_dir() / _LOOP_PID_NAME


def write_loop_pid():
    """Record that the monitor loop started. Never raises."""
    try:
        import os as _os
        p = _loop_pid_path()
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(str(_os.getpid()))
    except Exception as exc:
        _log(f"write_loop_pid failed: {exc!r}")


def clear_loop_pid():
    """Remove the pid file on clean shutdown. Never raises."""
    try:
        _loop_pid_path().unlink(missing_ok=True)
    except Exception:
        pass


def note_loop_tick(now=None):
    """Stamp the loop's tick watermark. Called every monitor pass.
    Never raises."""
    now = now if now is not None else time.time()
    try:
        dbm.set_meta(_LOOP_TICK_KEY, str(now))
    except Exception:
        pass


def loop_tick_fresh(max_age_s=LOOP_STALE_S, now=None):
    """True/False/None: is the monitor loop's tick watermark fresh?

    None = unknown (no watermark yet -- never treated as stale).
    Never raises.
    """
    now = now if now is not None else time.time()
    try:
        raw = dbm.get_meta(_LOOP_TICK_KEY)
        last = float(raw) if raw else 0.0
    except (TypeError, ValueError):
        return None
    except Exception:
        return None
    if last <= 0:
        return None
    age = now - last
    if age < 0:
        age = 0.0  # clock jumped backwards; never report a negative age
    return age <= max_age_s


def check_loop_down(now=None):
    """(down: bool, detail: str|None).

    down is True when a monitor loop was started (pid file present) but
    its tick watermark is stale -- the loop died without a clean
    shutdown. Never raises.
    """
    now = now if now is not None else time.time()
    try:
        if not _loop_pid_path().exists():
            return False, None  # no loop was started here; nothing to miss
        if disk_pressure():
            # The tick write itself can fail on a full disk -- the
            # disk-full self-alert already owns that episode, and a
            # second "the monitor stopped" would be noise blaming the
            # wrong cause.
            return False, None
        fresh = loop_tick_fresh(now=now)
        if fresh is None:
            return False, None  # unknown, never stale
        if fresh:
            return False, None
        _last, age = now, None
        try:
            raw = dbm.get_meta(_LOOP_TICK_KEY)
            _last = float(raw) if raw else now
            age = max(0.0, now - _last)
        except Exception:
            pass
        return True, (f"the monitor loop last checked in"
                      f" {_age_words(age)}.")
    except Exception as exc:
        _log(f"check_loop_down failed: {exc!r}")
        return False, None


def check_and_alert_loop_down(now=None):
    """Fire one High self_drift self-alert per loop-down episode; clear
    the flag when the loop is ticking again. Returns True when the loop
    is currently down. Never raises."""
    now = now if now is not None else time.time()
    try:
        down, detail = check_loop_down(now=now)
        if down:
            try:
                already = dbm.get_meta(_LOOP_DOWN_FLAG)
            except Exception:
                already = None
            if not already:
                tid = _fire_self_alert(
                    "loop", detail or "the monitor loop stopped checking in.")
                if tid:
                    try:
                        dbm.set_meta(_LOOP_DOWN_FLAG, str(now))
                    except Exception:
                        pass
        else:
            try:
                if dbm.get_meta(_LOOP_DOWN_FLAG):
                    dbm.set_meta(_LOOP_DOWN_FLAG, "")
                    _log("monitor loop ticking again; loop-down flag cleared")
            except Exception:
                pass
        return down
    except Exception as exc:
        _log(f"check_and_alert_loop_down failed: {exc!r}")
        return False


# --- self-alerts: the cases worth waking someone over --------------------------
# A stale stage, a full disk, or a dead monitor loop means the monitor
# itself is degraded -- quiet-is-a-feature yields here, once per episode.
# Everything else just logs.

_SELF_COPY = {
    "capture": (
        "The monitor stopped seeing network traffic",
        "Nothing has been recorded from your network for a while.",
        "brutedash spots threats by watching your network's traffic."
        " Right now it isn't recording any, so it can't spot anything"
        " either -- it's flying blind.",
        "Not normal -- even a quiet network has background chatter every"
        " few minutes.",
        "Make sure brutedash is still running with permission to watch"
        " the network (it needs administrator/root), then restart it.",
    ),
    "rules": (
        "Detection checks aren't running",
        "The scheduled checks that look for port scans, odd traffic, and"
        " known-bad addresses haven't completed recently.",
        "The monitor's detection rules run every minute. If they stop,"
        " new threats won't be flagged even though traffic is still"
        " being recorded.",
        "Not normal -- the checks should complete every minute.",
        "Restart brutedash. If this keeps happening, check the logs for"
        " the failing check's name.",
    ),
    "feeds": (
        "Threat-intel lists are out of date",
        "The community blocklists of known-bad sites and addresses"
        " haven't refreshed successfully in a while.",
        "brutedash keeps local copies of malware/phishing blocklists and"
        " refreshes them twice a day. Detection still works from the"
        " saved lists -- they just get staler.",
        "Happens whenever the internet is down for a stretch; the saved"
        " lists keep working meanwhile.",
        "Check your internet connection. The lists refresh on their own"
        " once the network is back.",
    ),
    "notify": (
        "Alert emails may not be going out",
        "No alert email has been sent successfully in a while.",
        "brutedash emails you about High and Critical findings. If email"
        " is broken you'll still see everything on the dashboard, but"
        " nothing will reach your inbox.",
        "Normal if nothing worth emailing happened -- this only fires"
        " when email used to work and then stopped.",
        "Check your email settings (SMTP host/user in the environment)"
        " and your internet connection.",
    ),
    "disk": (
        "This computer is nearly out of disk space",
        "brutedash paused its extra recording to protect the essentials.",
        "The packet history buffer, summaries, and scheduled scans are"
        " paused until there's room again. Threat detection keeps"
        " running -- watching matters more than recording.",
        "Not normal -- something is filling the disk.",
        "Free up disk space on this computer, then restart brutedash to"
        " resume full recording.",
    ),
    "loop": (
        "The monitor itself stopped checking",
        "The part of brutedash that runs the detection checks every"
        " minute hasn't reported in a while.",
        "brutedash watches your network in two parts: one records the"
        " traffic, the other checks it for threats every minute. The"
        " checking part went quiet, so new threats are not being flagged"
        " right now.",
        "Not normal -- the checks should report every minute.",
        "Restart brutedash. If this keeps happening, check the logs for"
        " what stopped the monitor loop.",
    ),
}


def _fire_self_alert(stage, detail_suffix=""):
    """Store one self_drift self-alert for `stage`. Returns the trace id,
    or None when the store failed. Never raises."""
    tid = new_trace_id()
    sev = _SELF_SEV.get(stage, "Medium")
    title, detail, meaning, is_normal, what_to_do = _SELF_COPY[stage]
    if detail_suffix:
        detail = f"{detail} {detail_suffix}".strip()
    _log(f"self-alert [{stage}] (trace {tid}): {title}")
    try:
        dbm.add_alert("self_drift", sev, title, detail, meaning=meaning,
                      is_normal=is_normal, what_to_do=what_to_do,
                      trace_id=tid)
        return tid
    except Exception as exc:
        # Under disk-full the INSERT itself can fail -- the stderr line
        # above is the record. Never raise out of the alert path.
        _log(f"self-alert [{stage}] could not be stored: {exc!r}")
        return None


def _fire_combined_stale_alert(new_stale):
    """One self-alert for several newly-stale stages instead of N at
    once (quiet is a feature). Severity is the highest member severity.
    Returns the trace id, or None when the store failed. Never raises."""
    rank = {"Low": 0, "Medium": 1, "High": 2, "Critical": 3}
    sev = "Low"
    for st in new_stale:
        s = _SELF_SEV.get(st["stage"], "Medium")
        if rank.get(s, 0) > rank.get(sev, 0):
            sev = s
    labels = ", ".join(st["label"] for st in new_stale)
    tid = new_trace_id()
    _log(f"self-alert [stale: "
         f"{','.join(st['stage'] for st in new_stale)}]"
         f" (trace {tid}): several monitor parts went quiet")
    try:
        dbm.add_alert(
            "self_drift", sev,
            "Several parts of the monitor went quiet",
            f"{labels} haven't reported in a while.",
            meaning=("brutedash watches itself the way it watches your"
                     " network. Several of its parts stopped reporting,"
                     " so parts of the monitoring may be degraded."),
            is_normal=("Not normal -- capture and detection should"
                       " report every few minutes, feeds and email on"
                       " their own schedules."),
            what_to_do=("Check that brutedash is still running with"
                        " permission to watch the network"
                        " (administrator/root), that the internet is up,"
                        " and that the email settings are correct. Then"
                        " restart it."),
            trace_id=tid)
        return tid
    except Exception as exc:
        _log(f"combined stale alert could not be stored: {exc!r}")
        return None


def check_and_alert_staleness(now=None, capture_expected=True):
    """Fire one self-alert per stale stage; clear flags on recovery.

    When several stages go newly stale in the same pass, one combined
    alert fires instead of N at once (severity = highest member).
    Per-stage flags still track each episode independently, so recovery
    stays per-stage. Returns the list of stages alerted this call.
    Never raises.
    """
    now = now if now is not None else time.time()
    alerted = []
    try:
        stale = stale_stages(now=now, capture_expected=capture_expected)
        stale_names = set()
        new_stale = []
        for st in stale:
            stage = st["stage"]
            stale_names.add(stage)
            flag = f"stale_alert_{stage}"
            try:
                already = dbm.get_meta(flag)
            except Exception:
                already = None
            if not already:
                new_stale.append(st)
        if len(new_stale) == 1:
            st = new_stale[0]
            stage = st["stage"]
            if stage == "rules":
                _alert_rules_down(
                    f"no completed detection pass in"
                    f" {_age_words(st['age_s'])}")
            else:
                _fire_self_alert(
                    stage,
                    f"Last healthy {_age_words(st['age_s'])}.")
            try:
                dbm.set_meta(f"stale_alert_{stage}", str(now))
            except Exception:
                pass
            alerted.append(stage)
        elif new_stale:
            _fire_combined_stale_alert(new_stale)
            for st in new_stale:
                try:
                    dbm.set_meta(f"stale_alert_{st['stage']}", str(now))
                except Exception:
                    pass
                alerted.append(st["stage"])
        # Recovery: a stage healthy again clears its flag so the next
        # episode alerts anew, and logs the recovery.
        for stage in STAGES:
            if stage in stale_names:
                continue
            flag = f"stale_alert_{stage}"
            try:
                if dbm.get_meta(flag):
                    dbm.set_meta(flag, "")
                    _log(f"stage {stage} healthy again; staleness flag"
                         f" cleared")
            except Exception:
                pass
    except Exception as exc:
        _log(f"check_and_alert_staleness failed: {exc!r}")
    return alerted


def _alert_rules_down(detail_suffix=""):
    """One Medium self-alert that detection isn't running. Shared by the
    crash-streak path and the staleness path so they can't double-alert."""
    if dbm.get_meta("stale_alert_rules"):
        return None
    tid = _fire_self_alert("rules", detail_suffix)
    if tid:
        try:
            dbm.set_meta("stale_alert_rules", str(time.time()))
        except Exception:
            pass
    return tid


def note_rules_result(ok, exc=None, alert_after=3):
    """Record one detection-pass outcome.

    ok: refresh the rules watermark, reset the failure streak, clear any
    earlier down-alert flag (recovery). Failure: log one line, count the
    streak; after `alert_after` consecutive failures, one Medium
    self-alert. Never raises.
    """
    try:
        if ok:
            try:
                dbm.set_meta("pipeline_rules_fail_streak", "0")
            except Exception:
                pass
            mark("rules")
            try:
                if dbm.get_meta("stale_alert_rules"):
                    dbm.set_meta("stale_alert_rules", "")
                    _log("detection passes healthy again")
            except Exception:
                pass
            return
        _log(f"detection pass failed: {exc!r}" if exc is not None
             else "detection pass failed")
        try:
            raw = dbm.get_meta("pipeline_rules_fail_streak") or "0"
            streak = int(raw) + 1
        except (TypeError, ValueError):
            streak = 1
        except Exception:
            streak = 1
        try:
            dbm.set_meta("pipeline_rules_fail_streak", str(streak))
        except Exception:
            pass
        if streak >= alert_after:
            _alert_rules_down(f"{streak} consecutive detection passes"
                              f" failed.")
    except Exception as exc:
        _log(f"note_rules_result failed: {exc!r}")


# --- disk guard ------------------------------------------------------------------
# A full disk used to wedge everything at once. Now: the rewind buffer
# pauses first (it has its own guard), non-essential monitor writes stop,
# one self-alert fires, detection keeps running.

DISK_MIN_FREE_MB = 512  # below this, non-essential writes stop


def disk_free_mb(path=None):
    """Free MB on the filesystem holding `path` (default: the DB dir).

    None when the stat itself fails -- an unknown disk is never treated
    as a full one (fail open, log nothing; the stat failing is not the
    disk failing).
    """
    import shutil
    try:
        target = path or os.path.dirname(
            os.path.abspath(dbm.DB_PATH))
        return shutil.disk_usage(target).free / (1024 * 1024)
    except Exception:
        return None


def disk_pressure(path=None, min_free_mb=DISK_MIN_FREE_MB):
    """True when the disk is nearly full. Never raises."""
    try:
        free = disk_free_mb(path)
        return free is not None and free < min_free_mb
    except Exception:
        return False


def disk_alert_once(path=None, min_free_mb=DISK_MIN_FREE_MB, now=None):
    """Alert once per full-disk episode; clear the flag on recovery.

    Returns True when an alert fired this call. Best-effort throughout:
    when the disk is truly full even the alert row may not store -- then
    the stderr line is the record. Never raises.
    """
    now = now if now is not None else time.time()
    try:
        flag = "disk_full_alerted_ts"
        if disk_pressure(path=path, min_free_mb=min_free_mb):
            try:
                already = dbm.get_meta(flag)
            except Exception:
                already = None
            if already:
                return False
            # Name exactly what pauses: the record of the degraded mode
            # lives in this alert (and one stderr line), not scattered.
            tid = _fire_self_alert(
                "disk",
                "Paused until there's room: summaries, scheduled scans"
                " (self scan, Nuclei, Amass, software inventory), log"
                " ingestion, digests, and reports. Still running: traffic"
                " capture, detection rules, threat-intel refreshes.")
            try:
                dbm.set_meta(flag, str(now))
            except Exception:
                pass
            return tid is not None
        try:
            if dbm.get_meta(flag):
                dbm.set_meta(flag, "")
                _log("disk pressure cleared; resuming normal writes")
        except Exception:
            pass
        return False
    except Exception as exc:
        _log(f"disk_alert_once failed: {exc!r}")
        return False


# --- capture watchdog ---------------------------------------------------------------
# The capture thread is the pipeline's front door. If it dies, restart it
# -- bounded, then stop trying and let the stale-capture watermark raise
# the self-alert. A restart storm helps nobody.

CAPTURE_MAX_RESTARTS = 3       # per window, then give up quietly
CAPTURE_RESTART_WINDOW_S = 3600


def ensure_capture(state, is_alive, start, now=None,
                   max_restarts=CAPTURE_MAX_RESTARTS,
                   window_s=CAPTURE_RESTART_WINDOW_S):
    """Keep the capture worker alive.

    state: mutable dict (keys: thread, restarts, gave_up), owned by the
      caller (run.py).
    is_alive: () -> bool. start: () -> new worker (stored in
      state["thread"]).
    Returns "ok" | "restarted" | "gave_up". Never raises.
    """
    now = now if now is not None else time.time()
    try:
        try:
            alive = bool(is_alive())
        except Exception:
            alive = False
        if alive:
            return "ok"
        restarts = [t for t in state.get("restarts", [])
                    if now - t < window_s]
        state["restarts"] = restarts
        if not restarts:
            # The window slid clear: whatever killed it last hour is
            # over, allow fresh attempts.
            state["gave_up"] = False
        if state.get("gave_up"):
            return "gave_up"
        if len(restarts) >= max_restarts:
            state["gave_up"] = True
            _log(f"capture worker dead; {max_restarts} restarts in the"
                 f" last hour already -- giving up (the stale-capture"
                 f" check will raise the self-alert)")
            return "gave_up"
        try:
            state["thread"] = start()
        except Exception as exc:
            restarts.append(now)
            state["restarts"] = restarts
            _log(f"capture restart failed: {exc!r}")
            if len(restarts) >= max_restarts:
                state["gave_up"] = True
            return "gave_up" if state.get("gave_up") else "restarted"
        restarts.append(now)
        state["restarts"] = restarts
        _log("capture worker restarted")
        return "restarted"
    except Exception as exc:
        _log(f"ensure_capture failed: {exc!r}")
        return "gave_up"


# --- safe_step -------------------------------------------------------------------------
# One pipeline step that must never kill the monitor loop. Replaces the
# bare `except: pass` blocks: the failure is logged (one line), the loop
# continues, the user is not paged.

def safe_step(name, fn, *args, **kwargs):
    """Run fn(); on failure log one stderr line and return None.
    Never raises."""
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        _log(f"step {name} failed: {exc!r}")
        return None


# --- run-mode flags ----------------------------------------------------------------------
# The monitor loop records whether capture was requested so the
# dashboard (a separate process/thread) can tell "capture intentionally
# off" from "capture died".

def set_capture_expected(expected):
    """Record whether this run requested live capture. Never raises."""
    try:
        dbm.set_meta("pipeline_capture_expected",
                     "1" if expected else "0")
    except Exception:
        pass


def get_capture_expected():
    """True when the running monitor requested live capture. Never
    raises; defaults to True (a monitor that never recorded the flag is
    assumed to want capture)."""
    try:
        return dbm.get_meta("pipeline_capture_expected") != "0"
    except Exception:
        return True
