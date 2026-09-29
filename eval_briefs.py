"""eval_briefs.py -- score brutedash brief quality.

Three checks per brief:
  1. schema      -- does it validate against the brief JSON schema?
  2. grounding   -- is every claim traceable to the evidence? The pattern
                    must name the IP and the attempt count, and any other
                    number in it must come from the evidence or the IP
                    intel (anti-hallucination heuristic).
  3. completeness -- severity set, pattern substantive, 2+ actions.

Runs against the rule-based path always, and against the LLM path too when
OPENAI_API_KEY is set. Exit code 0 = all checks pass.

Usage:  python eval_briefs.py
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from app import write_brief, _validate_brief
from ipintel import lookup_ip, describe as describe_intel

CASES = [
    ("203.0.113.44", 6, "Medium"),
    ("198.51.100.23", 14, "High"),
    ("192.0.2.11", 3, "Medium"),
]
ALLOWED_NUMBERS = {"3", "10"}  # detection threshold, severity cutoff


def check_schema(brief):
    return [] if _validate_brief(brief) else ["schema validation failed"]


def check_grounding(brief, ip, count, intel):
    """Heuristic anti-hallucination check on the observed pattern."""
    issues = []
    text = brief["observed_pattern"]
    if ip not in text:
        issues.append("IP missing from observed_pattern")
    if str(count) not in text:
        issues.append("attempt count missing from observed_pattern")
    # Strip everything the brief is allowed to know, then interrogate
    # any remaining numbers.
    scrubbed = text.replace(ip, "")
    if intel:
        scrubbed = scrubbed.replace(describe_intel(intel), "")
    allowed = ALLOWED_NUMBERS | {str(count)}
    for num in set(re.findall(r"\d+", scrubbed)):
        if num not in allowed:
            issues.append(f"unverifiable number in pattern: {num}")
    return issues


def check_completeness(brief):
    issues = []
    if len(brief["observed_pattern"]) < 20:
        issues.append("observed_pattern suspiciously short")
    if len(brief["recommended_actions"]) < 2:
        issues.append("fewer than 2 recommended actions")
    return issues


def eval_case(ip, count, severity):
    intel = lookup_ip(ip)
    brief, source = write_brief(ip, count, severity)
    issues = (check_schema(brief)
              + check_grounding(brief, ip, count, intel)
              + check_completeness(brief))
    return {"case": f"{ip} x{count} [{severity}]", "source": source,
            "issues": issues}


def main():
    results = [eval_case(*c) for c in CASES]
    total_issues = 0
    for r in results:
        status = "PASS" if not r["issues"] else "FAIL"
        total_issues += len(r["issues"])
        print(f"[{status}] {r['case']} (via {r['source']})")
        for issue in r["issues"]:
            print(f"        - {issue}")
    passed = sum(1 for r in results if not r["issues"])
    print(f"\n{passed}/{len(results)} briefs passed all checks.")
    if os.environ.get("OPENAI_API_KEY"):
        print("note: LLM path was live (OPENAI_API_KEY set).")
    else:
        print("note: evaluated rule-based path only (no OPENAI_API_KEY).")
    return 0 if total_issues == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
