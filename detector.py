"""Brute-force SSH login detector.

Port of the session #1 parser (2026-09-09) into a reusable function.

Pipeline: parse -> detect -> persist -> brief  (persist + brief live in app.py)
"""

SEVERITY_HIGH_CUTOFF = 10  # from the session #3 SPL stretch: count > 10 -> High


def detect_brute_force(log_path, threshold=3):
    """Flag IPs with repeated failed SSH logins.

    Returns a list of dicts, highest count first:
        [{"ip": ..., "count": ..., "severity": ...}, ...]
    Severity is rule-based: count > 10 -> "High", else "Medium".
    """
    counts = {}

    with open(log_path) as f:
        for line in f:
            # Move B -- keep only failures.
            if "Failed password" not in line:
                continue
            # Guard -- skip lines with no IP (the bug-bait line from session #1).
            if "from " not in line:
                continue
            # Move C -- the IP is the word right after "from".
            ip = line.split("from ", 1)[1].split()[0]
            counts[ip] = counts.get(ip, 0) + 1

    results = []
    for ip, count in sorted(counts.items(), key=lambda kv: kv[1], reverse=True):
        if count >= threshold:
            severity = "High" if count > SEVERITY_HIGH_CUTOFF else "Medium"
            results.append({"ip": ip, "count": count, "severity": severity})
    return results


if __name__ == "__main__":
    import sys

    path = sys.argv[1] if len(sys.argv) > 1 else "auth.log"
    findings = detect_brute_force(path)
    if not findings:
        print("No brute-force activity detected.")
    for r in findings:
        print(f"{r['ip']}: {r['count']} failed attempts [{r['severity']}]")
