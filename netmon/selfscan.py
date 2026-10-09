"""netmon/selfscan.py -- dependency-light YAML-rule static self-scan (brutedash).

Implements the `semgrep-yaml-rules-pattern` skill's harness shape
(~/workspace/skills/semgrep-rules/SKILL.md, installed 2026-10-04):

    tests/rules/<rule-dir>/rule.yaml   -- the rule under test
    tests/rules/<rule-dir>/ok.py       -- must yield ZERO findings for the rule
    tests/rules/<rule-dir>/bad.py      -- must yield the finding(s) for the rule
    tests/rules/expected.json         -- golden counts, checked by
                                         tests/test_selfscan.py

Honest scope: this is NOT semgrep. It evaluates a small documented pattern
subset with Python regexes, one line at a time:

    * `pattern: <s>`         -- semgrep-style pattern; `...` matches anything.
    * `pattern-either: [...]`-- OR of pattern entries.
    * `pattern-not-inside: "def test_*: ..."`
                             -- exclude matches inside any `def test_*`
                               function body. ONLY this one
                               `pattern-not-inside` shape is supported;
                               any other shape raises a clear ValueError.

Everything else in the semgrep rule schema is out of scope and rejected
loudly rather than silently mis-evaluated.

API:

    load_rule(path)          -- rule dict from a rule.yaml file
    scan_text(rule, text, path="<text>") -> [finding, ...]
    scan_file(rule, path)    -> [finding, ...]
    scan_all(rules_root)     -- {(rule_dir, fixture): count} snapshot used
                                by the golden tests
    scan_tree(rules, root)   -- all rules over every *.py under root
                                (future CI hook; NOT used by tests)

A finding is a dict: rule_id, message, fix, severity, path, line, text.

CLI:

    python -m netmon.selfscan --rules tests/rules
    python -m netmon.selfscan --rules tests/rules --tree netmon
"""

import argparse
import json
import os
import re
import sys

import yaml

RULES_ROOT = os.path.join(os.path.dirname(__file__), "..", "tests", "rules")

_NOT_INSIDE_SHAPES = ("def test_*: ...",)


def _translate_pattern(pat):
    """Translate a semgrep-style pattern to a Python regex (line scope).

    `...` becomes `.*?`; everything else is literal. Plain spaces match
    any run of whitespace, so hand-written fixtures don't depend on
    exact spacing.
    """
    parts = pat.split("...")
    rx = ".*?".join(re.escape(p) for p in parts)
    # re.escape() renders a space as r"\ " (backslash-space); replace that
    # sequence with a whitespace run so fixtures don't depend on exact
    # spacing. (A plain " " replace would corrupt the escaped sequence.)
    rx = rx.replace(r"\ ", r"\s+")
    return rx


def _indent_of(line):
    return len(line) - len(line.lstrip())


def _test_function_ranges(lines):
    """Line ranges (inclusive) of every `def test_*` function body."""
    ranges = []
    i = 0
    while i < len(lines):
        m = re.match(r"^(\s*)def\s+test_\w*\b", lines[i])
        if m:
            indent = len(m.group(1))
            start = i
            i += 1
            while i < len(lines):
                stripped = lines[i].strip()
                if stripped and _indent_of(lines[i]) <= indent:
                    break
                i += 1
            ranges.append((start, i - 1))
        else:
            i += 1
    return ranges


def _compile_rule(rule):
    """Compile one rule dict into matcher closures. Raises ValueError on
    anything outside the documented subset."""
    rule_id = rule.get("id", "<unnamed>")
    not_inside = rule.get("pattern-not-inside")
    if not_inside is not None and not_inside not in _NOT_INSIDE_SHAPES:
        raise ValueError(
            "rule %r: unsupported pattern-not-inside %r "
            "(only 'def test_*: ...' is supported)" % (rule_id, not_inside)
        )

    matchers = []

    def _one(pat_entry):
        if not isinstance(pat_entry, dict) or set(pat_entry) != {"pattern"}:
            raise ValueError(
                "rule %r: pattern entries must be {'pattern': <str>}, got %r"
                % (rule_id, pat_entry)
            )
        return re.compile(_translate_pattern(pat_entry["pattern"]))

    patterns = rule.get("patterns", [])
    if not isinstance(patterns, list):
        raise ValueError("rule %r: 'patterns' must be a list" % rule_id)
    for entry in patterns:
        if isinstance(entry, dict) and set(entry) == {"pattern-either"}:
            group = entry["pattern-either"]
            if not isinstance(group, list):
                raise ValueError(
                    "rule %r: 'pattern-either' must be a list" % rule_id
                )
            compiled = [_one(p) for p in group]
            matchers.append(lambda line, c=compiled: any(r.search(line) for r in c))
        else:
            rx = _one(entry)
            matchers.append(lambda line, r=rx: r.search(line) is not None)

    if not matchers:
        raise ValueError("rule %r: no usable patterns" % rule_id)
    return rule_id, matchers, not_inside is not None


def load_rule(path):
    """Load and validate a rule.yaml file."""
    with open(path, "r", encoding="utf-8") as fh:
        doc = yaml.safe_load(fh)
    if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
        raise ValueError("rule file %r must define a 'rules' list" % path)
    if len(doc["rules"]) != 1:
        raise ValueError("rule file %r must define exactly one rule" % path)
    rule = doc["rules"][0]
    for key in ("id", "message", "severity", "patterns", "fix"):
        if key not in rule:
            raise ValueError("rule file %r: rule missing %r" % (path, key))
    _compile_rule(rule)  # fail fast on unsupported shapes
    return rule


def scan_text(rule, text, path="<text>"):
    """Scan a string with one rule; return finding dicts."""
    rule_id, matchers, exclude_tests = _compile_rule(rule)
    lines = text.splitlines()
    ranges = _test_function_ranges(lines) if exclude_tests else []

    def in_test_block(lineno):
        return any(start <= lineno <= end for start, end in ranges)

    findings = []
    for lineno, line in enumerate(lines, start=1):
        if exclude_tests and in_test_block(lineno - 1):
            continue
        if any(m(line) for m in matchers):
            findings.append(
                {
                    "rule_id": rule_id,
                    "message": rule["message"],
                    "fix": rule["fix"],
                    "severity": rule["severity"],
                    "path": path,
                    "line": lineno,
                    "text": line.strip(),
                }
            )
    return findings


def scan_file(rule, path):
    """Scan one file with one rule; unreadable files yield no findings."""
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return []
    return scan_text(rule, text, path=path)


def _rule_dirs(rules_root):
    return sorted(
        d
        for d in os.listdir(rules_root)
        if os.path.isdir(os.path.join(rules_root, d))
    )


def scan_all(rules_root):
    """Snapshot: {(rule_dir, fixture_name): finding_count}.

    Each fixture is scanned with ONLY its own rule -- this is the golden
    count that tests/rules/expected.json records.
    """
    snapshot = {}
    for rule_dir in _rule_dirs(rules_root):
        rule = load_rule(os.path.join(rules_root, rule_dir, "rule.yaml"))
        for fixture in ("ok.py", "bad.py"):
            fixture_path = os.path.join(rules_root, rule_dir, fixture)
            findings = scan_file(rule, fixture_path)
            snapshot["%s/%s" % (rule_dir, fixture)] = len(findings)
    return snapshot


def scan_tree(rules, root):
    """Scan every *.py under root with every rule (CI hook, unused by tests)."""
    findings = []
    for dirpath, _dirnames, filenames in os.walk(root):
        for name in sorted(filenames):
            if not name.endswith(".py"):
                continue
            path = os.path.join(dirpath, name)
            for rule in rules:
                findings.extend(scan_file(rule, path))
    return findings


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="YAML-rule static self-scan for brutedash (subset evaluator)"
    )
    parser.add_argument("--rules", default=RULES_ROOT)
    parser.add_argument(
        "--tree",
        default=None,
        help="also scan every *.py under this dir with all rules",
    )
    args = parser.parse_args(argv)

    rules = []
    for rule_dir in _rule_dirs(args.rules):
        rules.append(load_rule(os.path.join(args.rules, rule_dir, "rule.yaml")))

    snapshot = scan_all(args.rules)
    bad = sum(v for k, v in snapshot.items() if k.endswith("/bad.py"))
    print("fixture snapshot: %d rule dirs, %d bad.py findings" % (len(rules), bad))
    print(json.dumps(snapshot, indent=2, sort_keys=True))

    if args.tree:
        findings = scan_tree(rules, args.tree)
        print("tree scan: %d findings under %s" % (len(findings), args.tree))
        for f in findings:
            print("%s:%d [%s] %s" % (f["path"], f["line"], f["rule_id"], f["text"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
