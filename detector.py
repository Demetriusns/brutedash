"""Brute-force SSH login detector.

Port of the session #1 parser (2026-09-09) into a reusable function.

Pipeline: parse -> detect -> persist -> brief  (persist + brief live in app.py)

Findings:
  brute_force            repeated failed logins (Medium/High by count)
  login_after_bruteforce an accepted login from an IP with >= threshold
                         failures -- the break-in itself (Critical).
                         Severity-aware consumers must never drop these.

Rotation note (hardening item, 2026-10-11): a brute-force campaign spanning
a logrotate boundary used to get its failure counts split across
auth.log / auth.log.1 and could slip under the threshold. detect_brute_force
now merges counts across rotated siblings (oldest first) so the campaign
reads as one.

Two further passes (council review 2026-11-17, ARTEX batch -- see the
cadence/key section below for each rule's MITRE mapping, false-positive
profile, and threshold justification):
  detect_cadence()     windowed cadence analysis of the same logs:
                       burst rate, interval regularity, username
                       enumeration, duplicate attempts, and a success
                       within minutes of a burst (Critical).
  detect_key_events()  first-seen SSH key fingerprints, gated on per-host
                       sshd logging-level coverage: fingerprints only
                       exist in the log at LogLevel VERBOSE, and the
                       pass reports every host where it cannot see them
                       instead of silently running dark.
"""

import calendar
import gzip
import ipaddress
import json
import os
import re
import statistics
import zlib

SEVERITY_HIGH_CUTOFF = 10  # from the session #3 SPL stretch: count > 10 -> High

MAX_ROTATED_SIBLINGS = 8   # auth.log.1 .. auth.log.8 (logrotate default is 4)
MAX_TOTAL_BYTES = 64 * 1024 * 1024  # never read more than this across siblings
MAX_LINE_BYTES = 1 * 1024 * 1024  # per-line cap, enforced BEFORE parsing (M4)
_READ_CHUNK_BYTES = 64 * 1024     # bounded read block for the chunked reader


def _rotated_siblings(log_path):
    """Return rotated siblings of log_path, oldest first.

    Candidate names are constructed (never globbed): <path>.<n> and
    <path>.<n>.gz for n in 1..MAX_ROTATED_SIBLINGS. Only regular files in
    the same directory are considered; anything missing, unreadable, or
    over the byte cap is silently skipped. Returns [(path, is_gz), ...]
    oldest-first so counts merge chronologically.
    """
    directory = os.path.dirname(os.path.abspath(log_path))
    base = os.path.basename(log_path)
    found = []
    for n in range(1, MAX_ROTATED_SIBLINGS + 1):
        for ext in ("", ".gz"):
            candidate = os.path.join(directory, f"{base}.{n}{ext}")
            if os.path.isfile(candidate):
                found.append((candidate, ext == ".gz"))
    # found is ascending (1..8, .gz after plain) -> newest first; reverse.
    return found[::-1]


def _open_byte_stream(path, is_gz):
    """Open path (plain or gzipped) as a binary stream."""
    if is_gz:
        return gzip.open(path, "rb")
    return open(path, "rb")


def _iter_capped_lines(stream):
    """Yield (line_text, raw_len) from a binary stream, reading in
    bounded chunks so no single line is ever fully materialised.

    Robustness M4 (council review, 2026-11-01): the old text-mode
    `for line in f` iteration built each whole line as a str before
    the byte cap was checked, so one newline-free line (or a small
    .gz inflating to one) defeated the 64 MB cap entirely -- a 90 MB
    single line peaked ~354 MB RSS. Here the stream is read in
    _READ_CHUNK_BYTES blocks and split on b"\\n" at byte level (0x0A
    never occurs inside a UTF-8 multibyte sequence, so decoding
    complete lines with errors="replace" matches the old text mode).
    Only the first MAX_LINE_BYTES of a line are kept; the rest is
    discarded up to its newline -- a real auth line is a few hundred
    bytes, so nothing parseable is lost. raw_len counts every raw
    byte the line consumed (kept + discarded + newline), so the
    caller's MAX_TOTAL_BYTES accounting bounds total work, including
    decompressed .gz content. A final line with no trailing newline
    is still yielded.
    """
    buf = bytearray()
    raw_len = 0
    skipping = False
    while True:
        chunk = stream.read(_READ_CHUNK_BYTES)
        if not chunk:
            break
        pos, end = 0, len(chunk)
        while pos < end:
            nl = chunk.find(b"\n", pos)
            if nl < 0:
                seg, pos, term = chunk[pos:], end, False
            else:
                seg, pos, term = chunk[pos:nl], nl + 1, True
            raw_len += len(seg) + (1 if term else 0)
            if seg and not skipping:
                room = MAX_LINE_BYTES - len(buf)
                if len(seg) <= room:
                    buf += seg
                else:
                    if room > 0:
                        buf += seg[:room]
                    skipping = True
            if term:
                yield bytes(buf).decode("utf-8", "replace"), raw_len
                buf, raw_len, skipping = bytearray(), 0, False
    if buf or raw_len:
        yield bytes(buf).decode("utf-8", "replace"), raw_len


def detect_brute_force(log_path, threshold=3):
    """Flag IPs with repeated failed SSH logins -- and logins that succeeded
    after a brute-force run.

    Reads log_path plus its rotated siblings (auth.log.1 .. auth.log.N)
    so a campaign spanning a logrotate boundary is scored as one campaign,
    not several sub-threshold fragments. The primary is always scanned
    first -- the byte cap applies to rotated siblings only, so the
    freshest log is never skipped.

    Returns a list of dicts, worst first:
        [{"ip": ..., "count": ..., "severity": ..., "kind": ...}, ...]
    Severity is rule-based: count > 10 -> "High", else "Medium"; an
    accepted login after >= threshold failures -> "Critical".

    The primary path must exist and be readable (raises as before); rotated
    siblings are best-effort and silently skipped.
    """
    counts = {}
    accepted = {}

    def _count_line(line):
        # Guard -- skip lines with no IP (the bug-bait line from session #1).
        if "from " not in line:
            return
        # Move C -- the IP is the word right after "from". A truncated or
        # wrapped log line can end right after "from " with nothing after
        # it; the split then yields no words -- skip instead of letting
        # IndexError escape and kill the whole detection pass (council
        # review, robustness, 2026-10-11).
        tail = line.split("from ", 1)[1].split()
        if not tail:
            return
        ip = tail[0]
        # Security L1 (council review, 2026-10-25): the token after
        # "from " is attacker-controlled log text, not a validated IP.
        # Hostnames, truncated garbage, or markup-shaped tokens used to
        # be counted, returned as findings, and persisted into
        # detections.db. Only real IP addresses are findings.
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return
        # Move B -- keep failures...
        if "Failed password" in line:
            counts[ip] = counts.get(ip, 0) + 1
        # ...but also watch for the break-in itself.
        elif "Accepted password" in line or "Accepted publickey" in line:
            accepted[ip] = accepted.get(ip, 0) + 1

    bytes_read = 0
    # Council review (robustness, 2026-10-11): the primary is the freshest
    # log and must always be scanned. Scanning siblings first meant the
    # 64MB byte cap could be exhausted before the primary was ever read --
    # a live campaign in auth.log then scored as silent, inverting the
    # rotation fix. The primary goes first and is never pre-skipped by the
    # getsize cap (that cap now applies to rotated siblings only); the
    # streaming byte cap still bounds every source so one runaway file
    # can't stall the run. Aggregates are order-independent, so
    # primary-first changes nothing about merged counts.
    sources = [(log_path, False)] + _rotated_siblings(log_path)
    for src, is_gz in sources:
        is_primary = (src == log_path)
        if not is_primary:
            try:
                if os.path.getsize(src) > MAX_TOTAL_BYTES:
                    continue
            except OSError:
                continue
        try:
            stream = _open_byte_stream(src, is_gz)
        except OSError:
            if is_primary:
                raise
            continue
        try:
            with stream as f:
                capped = False
                for line, n_raw in _iter_capped_lines(f):
                    _count_line(line)
                    bytes_read += n_raw
                    if bytes_read > MAX_TOTAL_BYTES:
                        capped = True
                        break
                if capped:
                    break  # byte cap hit: stop merging further sources
        except (OSError, EOFError, zlib.error):
            # Robustness R5 (council review, 2026-10-18): a truncated
            # .gz sibling raises EOFError and a corrupt deflate stream
            # raises zlib.error -- neither is an OSError subclass, and
            # both used to escape here and kill the whole detection
            # pass, healthy primary log included. The primary is always
            # opened as plain text, so these can only originate from a
            # sibling; the re-raise split below is unchanged.
            if src == log_path:
                raise
            # best-effort for siblings: keep whatever was counted so far

    results = []
    for ip, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        if count >= threshold:
            severity = "High" if count > SEVERITY_HIGH_CUTOFF else "Medium"
            results.append({"ip": ip, "count": count, "severity": severity,
                            "kind": "brute_force"})

    # The critical event: they got in after hammering. This is the
    # low-and-slow nightmare -- failures alone only ever say "Medium".
    for ip in sorted(accepted):
        fails = counts.get(ip, 0)
        if fails >= threshold:
            results.append({
                "ip": ip, "count": fails, "severity": "Critical",
                "kind": "login_after_bruteforce",
                "detail": (f"{accepted[ip]} accepted login(s) after"
                           f" {fails} failed attempts"),
            })

    _order = {"Critical": 0, "High": 1, "Medium": 2}
    results.sort(key=lambda r: (_order.get(r["severity"], 9), -r["count"]))
    return results


# ---------------------------------------------------------------------------
# Windowed cadence + SSH key analysis (council review 2026-11-17, ARTEX
# batch B1/B2; FBI FLASH-20261113-001). detect_brute_force above counts
# attempts per IP over the whole log; these passes read the same capped
# sources as a TIMELINE, because the ARTEX fingerprint is cadence, not
# volume: compressed bursts, machine-regular spacing, sequential username
# enumeration, duplicate requests from parallel sub-agents, and a success
# landing minutes after a burst. Password-mutation patterns from the same
# advisory are deliberately NOT attempted: sshd logs record that an
# attempt failed, never what password was tried, so mutation is
# unobservable in this data source.
#
# Rule cards (the detection-catalog shape, kept here because the
# generated docs/DETECTION-CATALOG.md covers netmon alert kinds only):
#
# burst_cadence (High) -- >= 10 failed logins from one IP inside any
#   120-second window. MITRE T1110 (Brute Force). Threshold: sshd
#   serialises attempts per connection and adds auth delay, so even a
#   fast human mistyping a password manages only a few tries a minute
#   and gives up; 10 in 2 minutes sustained is a machine. Interval
#   regularity (coefficient of variation of the gaps < 0.35) is scored
#   and reported in the finding text -- ARTEX sub-agents fire on a
#   timer -- but never raises severity on its own: a burst alone is
#   not the break-in. FP profile: password-spraying cron jobs and
#   misconfigured monitoring that retries SSH on a fixed timer.
# username_enumeration (High) -- >= 8 distinct usernames from one IP
#   inside any 10-minute window. MITRE T1110.003 (Password Spraying) /
#   T1087.001 (Account Discovery). One person mistyping uses one or
#   two names; 8+ names in 10 minutes is a list being walked. FP
#   profile: a shared NAT address fronting many real users failing
#   logins in the same window (rare on the small networks this
#   product watches, and the names are listed in the finding).
# duplicate_attempts (Medium) -- >= 4 failed logins for the SAME
#   username from one IP inside a single second. MITRE T1110. sshd
#   handles one auth attempt per connection at a time, so 4+ in one
#   second means parallel sessions replaying the same attempt -- the
#   duplicate-request fingerprint of parallel sub-agents. FP profile:
#   essentially none at this threshold; connection-retry storms land
#   seconds apart, not inside one second.
# login_after_burst (Critical) -- an accepted login (password or key)
#   from an IP within 10 minutes after a burst window from that IP
#   ends. MITRE T1110 + T1078 (Valid Accounts). This is the timed,
#   windowed form of login_after_bruteforce: when it fires for an IP
#   it supersedes the count-based finding (app.py dedupes). FP
#   profile: an admin who finally types the right password during an
#   unrelated burst from a shared NAT address -- the timing is in the
#   finding text so a human can judge.
# first_seen_key (High; Critical when correlated) -- an SSH key
#   fingerprint used for a host/user that appears nowhere in the log
#   history (rotated siblings) or the persistent state file. MITRE
#   T1098.004 (Account Manipulation: SSH Authorized Keys). sshd does
#   not log key-file additions, so first USE of a never-seen key is
#   the observable -- exactly the persistence move the advisory
#   flags. Escalates to Critical when a password login for the same
#   user succeeded within the previous hour (log in with a stolen
#   password, plant a key, come back at leisure). FP profile: a user
#   with a genuinely new laptop/key -- a real event worth one look,
#   which is why the un-correlated form is High, not Critical.
#   ADAPTATION GATE: fingerprints are only logged at sshd LogLevel
#   VERBOSE. The pass reports per-host coverage (verbose / dark /
#   no-key-auth); on a dark host it produces NO key findings and says
#   so loudly in the coverage report rather than running dark.
# ---------------------------------------------------------------------------

BURST_WINDOW_S = 120          # sliding window for the burst-rate rule
BURST_MIN_ATTEMPTS = 10       # failures inside the window = machine speed
BURST_SUCCESS_WINDOW_S = 600  # success this long after a burst = break-in
ENUM_WINDOW_S = 600           # username-enumeration window
ENUM_MIN_USERS = 8            # distinct usernames inside the window
DUP_MIN_SAME_SECOND = 4       # identical (user, second) failures = parallel
REGULARITY_CV_MAX = 0.35      # gap CV below this = machine-regular spacing
KEY_CORRELATION_S = 3600      # password login this long before a new key
KEY_STATE_MAX = 5000          # cap on persisted first-seen key history

_MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
           "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}
_TS_SYSLOG_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2}) (\d{2}):(\d{2}):(\d{2})")
_TS_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})[T ](\d{2}):(\d{2}):(\d{2})")
_USER_RE = re.compile(r"for (?:invalid user )?(\S+) from ")
_KEY_RE = re.compile(
    r"Accepted publickey for (\S+) from (\S+) port \d+ ssh2"
    r"(?::\s*(\S+) SHA256:(\S+))?")
_YEAR_WRAP_S = 180 * 86400    # a syslog ts this far behind = new year


def _parse_timestamp(line):
    """(epoch_seconds, is_syslog, parts) from a log line's prefix.

    Syslog timestamps carry no year: they are placed in a fixed base
    year (2000) here, and the caller re-places them with a calendar
    year offset (see _collect_events), which knows the stream order --
    a fixed second-count offset would drift by the leap days. `parts`
    is the (month, day, hh, mm, ss) tuple for syslog lines, else None.
    ISO timestamps carry their own year. Unparseable -> (None, ...).
    """
    m = _TS_ISO_RE.match(line)
    if m:
        y, mo, d, hh, mm, ss = (int(g) for g in m.groups())
        try:
            return calendar.timegm((y, mo, d, hh, mm, ss, 0, 0, 0)), False, None
        except (ValueError, OverflowError):
            return None, False, None
    m = _TS_SYSLOG_RE.match(line)
    if m:
        mon = _MONTHS.get(m.group(1))
        if mon is None:
            return None, False, None
        parts = (mon, int(m.group(2)), int(m.group(3)),
                 int(m.group(4)), int(m.group(5)))
        try:
            ts = calendar.timegm((2000,) + parts + (0, 0, 0))
        except (ValueError, OverflowError):
            return None, False, None
        return ts, True, parts
    return None, False, None


def _host_token(line, is_iso):
    """The logging host's name token (the word after the timestamp)."""
    parts = line.split()
    try:
        if is_iso:
            # "2026-10-02T19:00:01 host ..." or "2026-10-02 19:00:01 host"
            return parts[1] if "T" in parts[0] else parts[2]
        return parts[3]  # "Oct  2 19:00:01 host ..."
    except IndexError:
        return ""


def _ip_after_from(line):
    """Validated IP token after "from ", or None (same rule as Move C/L1
    in detect_brute_force: the token is attacker-controlled log text)."""
    tail = line.split("from ", 1)[1].split() if "from " in line else []
    if not tail:
        return None
    try:
        ipaddress.ip_address(tail[0])
    except ValueError:
        return None
    return tail[0]


def _collect_events(log_path):
    """One capped pass over log_path + rotated siblings, OLDEST first,
    returning auth events in stream order:
        {"ts", "kind", "ip", "user", "host", "fingerprint", "primary"}
    kind is "fail" (Failed password), "accept" (Accepted password) or
    "key" (Accepted publickey; fingerprint None when the line carries
    none, i.e. sshd is not at LogLevel VERBOSE). ts is None when the
    line has no parseable timestamp.

    Chronological order is the point of this pass, so sources are read
    oldest-sibling-first and the primary last -- the reverse of
    detect_brute_force, whose aggregates are order-independent and
    which therefore protects the primary from the byte cap first. The
    same 64 MB total cap bounds this pass; in practice rotated sets
    are a few MB. Syslog year repair: timestamps have no year, so when
    a syslog event lands more than 180 days before the previous syslog
    event in the stream, the stream has crossed a New Year and a year
    is added (logrotate sets are chronological, so this is safe).
    """
    events = []
    sources = _rotated_siblings(log_path) + [(log_path, False)]
    bytes_read = 0
    wrap_years = 0
    last_syslog_ts = None

    def _handle(line, is_primary):
        nonlocal wrap_years, last_syslog_ts
        if "Failed password" not in line and "Accepted" not in line:
            return
        ts, is_syslog, parts = _parse_timestamp(line)
        if is_syslog and parts is not None:
            ts = calendar.timegm((2000 + wrap_years,) + parts + (0, 0, 0))
            if (last_syslog_ts is not None
                    and ts < last_syslog_ts - _YEAR_WRAP_S):
                wrap_years += 1
                ts = calendar.timegm((2000 + wrap_years,) + parts
                                     + (0, 0, 0))
            last_syslog_ts = ts
        host = _host_token(line, bool(_TS_ISO_RE.match(line)))
        if "Failed password" in line:
            ip = _ip_after_from(line)
            if ip is None:
                return
            m = _USER_RE.search(line)
            events.append({"ts": ts, "kind": "fail", "ip": ip,
                           "user": m.group(1) if m else "",
                           "host": host, "fingerprint": None,
                           "primary": is_primary})
        elif "Accepted publickey" in line:
            m = _KEY_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return
                fp = m.group(4)
            else:
                ip = _ip_after_from(line)
                if ip is None:
                    return
                um = _USER_RE.search(line)
                user = um.group(1) if um else ""
                fp = None
            events.append({"ts": ts, "kind": "key", "ip": ip,
                           "user": user, "host": host,
                           "fingerprint": fp, "primary": is_primary})
        elif "Accepted password" in line:
            ip = _ip_after_from(line)
            if ip is None:
                return
            m = _USER_RE.search(line)
            events.append({"ts": ts, "kind": "accept", "ip": ip,
                           "user": m.group(1) if m else "",
                           "host": host, "fingerprint": None,
                           "primary": is_primary})

    for src, is_gz in sources:
        is_primary = (src == log_path)
        if not is_primary:
            try:
                if os.path.getsize(src) > MAX_TOTAL_BYTES:
                    continue
            except OSError:
                continue
        try:
            stream = _open_byte_stream(src, is_gz)
        except OSError:
            if is_primary:
                raise
            continue
        try:
            with stream as f:
                capped = False
                for line, n_raw in _iter_capped_lines(f):
                    _handle(line, is_primary)
                    bytes_read += n_raw
                    if bytes_read > MAX_TOTAL_BYTES:
                        capped = True
                        break
                if capped:
                    break
        except (OSError, EOFError, zlib.error):
            if is_primary:
                raise
            # best-effort for siblings, as in detect_brute_force
    return events


def _burst_windows(times):
    """Sliding-window scan of sorted failure timestamps.

    Returns (best, ends): best is (count, window_times) for the densest
    window at/above BURST_MIN_ATTEMPTS, or None; ends lists the last
    timestamp of every qualifying window (for success correlation).
    """
    best = None
    ends = []
    j = 0
    n = len(times)
    for i in range(n):
        if j < i:
            j = i
        while j < n and times[j] - times[i] <= BURST_WINDOW_S:
            j += 1
        count = j - i
        if count >= BURST_MIN_ATTEMPTS:
            ends.append(times[j - 1])
            if best is None or count > best[0]:
                best = (count, times[i:j])
    return best, ends


def detect_cadence(log_path):
    """Windowed cadence findings (B1) for log_path + rotated siblings.

    Returns finding dicts in the same shape as detect_brute_force
    ({"ip", "count", "severity", "kind", "detail"}), worst first.
    A burst with no success stays High -- top severity is reserved
    for the timed break-in (login_after_burst).
    """
    events = _collect_events(log_path)
    fails = {}        # ip -> [ts]
    fail_users = {}   # ip -> [(ts, user)]
    accepts = {}      # ip -> [ts]
    for ev in events:
        if ev["ts"] is None:
            continue
        if ev["kind"] == "fail":
            fails.setdefault(ev["ip"], []).append(ev["ts"])
            fail_users.setdefault(ev["ip"], []).append((ev["ts"], ev["user"]))
        elif ev["kind"] in ("accept", "key"):
            accepts.setdefault(ev["ip"], []).append(ev["ts"])

    findings = []
    for ip, times in fails.items():
        times.sort()
        best, ends = _burst_windows(times)
        # Timed break-in first: it supersedes the plain burst finding.
        broken_in = False
        if ends:
            for a_ts in accepts.get(ip, []):
                hit = [e for e in ends
                       if 0 <= a_ts - e <= BURST_SUCCESS_WINDOW_S]
                if hit:
                    findings.append({
                        "ip": ip, "count": best[0], "severity": "Critical",
                        "kind": "login_after_burst",
                        "detail": (f"successful login {int(a_ts - hit[-1])}s"
                                   f" after a burst of {best[0]} failed"
                                   f" attempts ended -- the burst got in"),
                    })
                    broken_in = True
                    break
        if best is not None and not broken_in:
            count, window = best
            detail = (f"{count} failed logins inside"
                      f" {int(window[-1] - window[0])} seconds --"
                      f" machine-speed burst, not a person typing")
            if len(window) >= 5:
                gaps = [b - a for a, b in zip(window, window[1:])]
                mean = statistics.fmean(gaps)
                if mean > 0 and statistics.pstdev(gaps) / mean \
                        < REGULARITY_CV_MAX:
                    detail += (f"; attempts landed at machine-regular"
                               f" intervals (~{mean:.0f}s apart)")
            findings.append({"ip": ip, "count": count, "severity": "High",
                             "kind": "burst_cadence", "detail": detail})
        # Username enumeration: distinct names inside the window.
        pairs = sorted(fail_users.get(ip, []))
        seen_users = {}
        j = 0
        enum_best = 0
        for i, (t, user) in enumerate(pairs):
            if j < i:
                j = i
            while j < len(pairs) and pairs[j][0] - t <= ENUM_WINDOW_S:
                j += 1
            window_users = {u for _, u in pairs[i:j] if u}
            if len(window_users) > enum_best:
                enum_best = len(window_users)
                seen_users = window_users
        if enum_best >= ENUM_MIN_USERS:
            names = ", ".join(sorted(seen_users)[:8])
            findings.append({
                "ip": ip, "count": enum_best, "severity": "High",
                "kind": "username_enumeration",
                "detail": (f"{enum_best} different usernames tried inside"
                           f" 10 minutes ({names}) -- a list being"
                           f" walked, not one person mistyping"),
            })
        # Duplicate attempts: same user, same second, one IP.
        dup_counts = {}
        for t, user in pairs:
            key = (user, int(t))
            dup_counts[key] = dup_counts.get(key, 0) + 1
        worst_dup = max(dup_counts.items(), key=lambda kv: kv[1],
                        default=(None, 0))
        if worst_dup[1] >= DUP_MIN_SAME_SECOND:
            (user, _sec), n_dup = worst_dup
            findings.append({
                "ip": ip, "count": n_dup, "severity": "Medium",
                "kind": "duplicate_attempts",
                "detail": (f"{n_dup} identical failed logins for"
                           f" '{user}' inside a single second --"
                           f" parallel sessions replaying the same"
                           f" attempt"),
            })

    _order = {"Critical": 0, "High": 1, "Medium": 2}
    findings.sort(key=lambda r: (_order.get(r["severity"], 9), -r["count"]))
    return findings


def _key_id(ev):
    return f"{ev['host']}|{ev['user']}|{ev['fingerprint']}"


def _load_key_state(state_path):
    """Persisted first-seen key history {key_id: {"first_seen", "ip"}}.
    A missing or corrupt file reads as empty history -- the safe
    direction (a corrupt state must not turn every known key into a
    false first-seen storm on the next pass)."""
    try:
        with open(state_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        keys = data.get("keys") if isinstance(data, dict) else None
        return keys if isinstance(keys, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_key_state(state_path, keys):
    """Atomically persist key history (tmp file + replace), capped at
    KEY_STATE_MAX entries, newest first-seen kept. A failed save
    degrades the next pass to sibling history only -- it must never
    crash the analysis, so OSError is swallowed here deliberately."""
    items = sorted(keys.items(),
                   key=lambda kv: (kv[1].get("first_seen") or 0),
                   reverse=True)[:KEY_STATE_MAX]
    payload = {"version": 1, "keys": dict(items)}
    tmp = state_path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f)
        os.replace(tmp, state_path)
        try:
            os.chmod(state_path, 0o600)
        except OSError:
            pass
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def detect_key_events(log_path, state_path=None):
    """First-seen SSH key findings + per-host coverage (B2).

    Returns {"findings": [...], "coverage": [...]}. Findings use the
    detect_brute_force dict shape. Coverage entries are
    {"host", "status", "note"} with status "verbose" (fingerprints
    visible -- the rule can see new keys), "dark" (key sign-ins happen
    but no fingerprints are logged -- sshd is below LogLevel VERBOSE
    and the rule CANNOT see new keys on that host), or "no-key-auth"
    (no key sign-ins in the log at all).

    History: rotated siblings are the in-log history -- a fingerprint
    that appears in a sibling is established, one that first appears
    in the primary log is first-seen. state_path (a JSON file managed
    by _load/_save_key_state) extends that history across runs. When
    there is NO history at all (no siblings, no prior state) the pass
    is a baseline run in the amass/nuclei first-run pattern: it
    records what it sees, reports coverage, and fires nothing, rather
    than calling every existing key "new".
    """
    events = _collect_events(log_path)
    key_events = [e for e in events if e["kind"] == "key"]
    accepts = [e for e in events if e["kind"] == "accept"]

    state = _load_key_state(state_path) if state_path else {}
    has_history = bool(state) or bool(_rotated_siblings(log_path))

    known = set(state)
    for ev in key_events:
        if ev["fingerprint"] and not ev["primary"]:
            known.add(_key_id(ev))

    findings = []
    if has_history:
        seen_first = {}
        for ev in key_events:
            if not ev["fingerprint"] or not ev["primary"]:
                continue
            kid = _key_id(ev)
            if kid not in known and kid not in seen_first:
                seen_first[kid] = ev
        for kid, ev in seen_first.items():
            fp_short = ev["fingerprint"][:16] + "..."
            detail = (f"first-seen SSH key for {ev['user']} on"
                      f" {ev['host'] or 'this host'} (fingerprint"
                      f" {fp_short}), used from {ev['ip']} -- never"
                      f" seen in the log history")
            if ev["user"] == "root":
                detail += "; privileged account"
            severity = "High"
            if ev["ts"] is not None:
                for a in accepts:
                    if (a["user"] == ev["user"] and a["ts"] is not None
                            and 0 <= ev["ts"] - a["ts"]
                            <= KEY_CORRELATION_S):
                        severity = "Critical"
                        detail += (f"; a password login for {ev['user']}"
                                   f" succeeded"
                                   f" {int((ev['ts'] - a['ts']) // 60)}"
                                   f" minutes earlier -- the"
                                   f" plant-a-key pattern")
                        break
            findings.append({"ip": ev["ip"], "count": 1,
                             "severity": severity,
                             "kind": "first_seen_key", "detail": detail})

    if state_path:
        merged = dict(state)
        for ev in key_events:
            if ev["fingerprint"]:
                merged.setdefault(_key_id(ev),
                                  {"first_seen": ev["ts"], "ip": ev["ip"]})
        _save_key_state(state_path, merged)

    per_host = {}
    for ev in events:
        per_host.setdefault(ev["host"], {"fingerprinted": 0, "plain": 0})
    for ev in key_events:
        slot = per_host.setdefault(ev["host"],
                                   {"fingerprinted": 0, "plain": 0})
        slot["fingerprinted" if ev["fingerprint"] else "plain"] += 1
    coverage = []
    for host in sorted(per_host):
        counts = per_host[host]
        name = host or "this host"
        if counts["fingerprinted"]:
            status = "verbose"
            note = (f"SSH key fingerprints are visible in {name}'s log"
                    f" (LogLevel VERBOSE) -- the first-seen key rule"
                    f" can see new keys here.")
        elif counts["plain"]:
            status = "dark"
            note = (f"{name} accepts SSH keys but its log lines carry"
                    f" no key fingerprints -- sshd is not logging at"
                    f" VERBOSE, so the first-seen key rule CANNOT see"
                    f" new keys on this host. Set 'LogLevel VERBOSE'"
                    f" in sshd_config to light it up.")
        else:
            status = "no-key-auth"
            note = (f"No SSH key sign-ins appear in {name}'s log --"
                    f" the first-seen key rule has nothing to watch"
                    f" here yet.")
        if not has_history:
            note += (" First pass with no key history: baseline"
                     " recorded, first-seen alerting starts with the"
                     " next log.")
        coverage.append({"host": host, "status": status, "note": note})

    _order = {"Critical": 0, "High": 1, "Medium": 2}
    findings.sort(key=lambda r: (_order.get(r["severity"], 9), -r["count"]))
    return {"findings": findings, "coverage": coverage}


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    findings = detect_brute_force(path)
    findings += detect_cadence(path)
    key_result = detect_key_events(path)
    findings += key_result["findings"]
    if not findings:
        print("No brute-force activity detected.")
    for r in findings:
        print(f"{r['ip']}: {r['count']} failed attempts [{r['severity']}]")
    for c in key_result["coverage"]:
        print(f"coverage {c['host'] or '?'}: {c['status']} -- {c['note']}")
