"""Brute-force SSH login detector.

Port of the session #1 parser (2026-09-09) into a reusable function.

Pipeline: parse -> detect -> persist -> brief  (persist + brief live in app.py)

Findings:
  brute_force            repeated failed logins (Medium/High by count)
  login_after_bruteforce an accepted login from an IP with >= threshold
                         failures -- the break-in itself (Critical).
                         Severity-aware consumers must never drop these.
"""

SEVERITY_HIGH_CUTOFF = 10  # from the session #3 SPL stretch: count > 10 -> High


def detect_brute_force(log_path, threshold=3):
    """Flag IPs with repeated failed SSH logins -- and logins that succeeded
    after a brute-force run.

    Returns a list of dicts, worst first:
        [{"ip": ..., "count": ..., "severity": ..., "kind": ...}, ...]
    Severity is rule-based: count > 10 -> "High", else "Medium"; an
    accepted login after >= threshold failures -> "Critical".
    """
    counts = {}
    accepted = {}

    with open(log_path) as f:
        for line in f:
            # Guard -- skip lines with no IP (the bug-bait line from session #1).
            if "from " not in line:
                continue
            # Move C -- the IP is the word right after "from".
            ip = line.split("from ", 1)[1].split()[0]
            # Move B -- keep failures...
            if "Failed password" in line:
                counts[ip] = counts.get(ip, 0) + 1
            # ...but also watch for the break-in itself.
            elif "Accepted password" in line or "Accepted publickey" in line:
                accepted[ip] = accepted.get(ip, 0) + 1

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
