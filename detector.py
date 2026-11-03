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
"""

import gzip
import ipaddress
import os
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


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    findings = detect_brute_force(path)
    if not findings:
        print("No brute-force activity detected.")
    for r in findings:
        print(f"{r['ip']}: {r['count']} failed attempts [{r['severity']}]")
