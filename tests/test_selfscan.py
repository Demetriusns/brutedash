"""Golden-file tests for the YAML-rule self-scan harness (netmon/selfscan.py).

Shape per ~/workspace/skills/semgrep-rules/SKILL.md:

    tests/rules/<rule>/rule.yaml  -- rule under test
    tests/rules/<rule>/ok.py      -- zero findings for that rule
    tests/rules/<rule>/bad.py     -- expected finding count for that rule
    tests/rules/expected.json     -- golden counts for the full snapshot

The snapshot test is the discipline: a rule change that alters findings on
*other* rules' fixtures fails the build. Cross-rule isolation is asserted
explicitly too.
"""

import json
import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import selfscan

RULES = os.path.join(os.path.dirname(__file__), "rules")

REQUIRED_RULE_KEYS = ("id", "message", "severity", "patterns", "fix")


def _expected():
    with open(os.path.join(RULES, "expected.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


class SelfScanRuleShapeTests(unittest.TestCase):
    def test_each_rule_dir_has_required_files(self):
        for rule_dir in sorted(os.listdir(RULES)):
            full = os.path.join(RULES, rule_dir)
            if not os.path.isdir(full):
                continue
            for name in ("rule.yaml", "ok.py", "bad.py"):
                self.assertTrue(
                    os.path.isfile(os.path.join(full, name)),
                    "%s/%s missing" % (rule_dir, name),
                )

    def test_rule_yaml_has_required_keys(self):
        for rule_dir in sorted(os.listdir(RULES)):
            full = os.path.join(RULES, rule_dir)
            if not os.path.isdir(full):
                continue
            rule = selfscan.load_rule(os.path.join(full, "rule.yaml"))
            for key in REQUIRED_RULE_KEYS:
                self.assertIn(key, rule, "%s rule missing %r" % (rule_dir, key))
            self.assertEqual(rule["severity"], "ERROR")

    def test_unsupported_pattern_shape_raises(self):
        bad = {
            "id": "x.y",
            "patterns": [{"pattern-not": "foo(...)"}],
        }
        with self.assertRaises(ValueError):
            selfscan._compile_rule(bad)


class SelfScanGoldenTests(unittest.TestCase):
    def test_ok_fixtures_clean_bad_fixtures_hit(self):
        expected = _expected()
        for rule_dir in sorted(os.listdir(RULES)):
            full = os.path.join(RULES, rule_dir)
            if not os.path.isdir(full):
                continue
            rule = selfscan.load_rule(os.path.join(full, "rule.yaml"))
            ok_findings = selfscan.scan_file(rule, os.path.join(full, "ok.py"))
            self.assertEqual(
                ok_findings, [], "%s/ok.py must be clean" % rule_dir
            )
            bad_findings = selfscan.scan_file(rule, os.path.join(full, "bad.py"))
            want = expected["%s/bad.py" % rule_dir]
            self.assertGreater(want, 0, "%s must expect >=1 bad.py finding" % rule_dir)
            self.assertEqual(
                len(bad_findings), want,
                "%s/bad.py: got %d, want %d" % (rule_dir, len(bad_findings), want),
            )
            for f in bad_findings:
                self.assertEqual(f["rule_id"], rule["id"])

    def test_full_snapshot_matches_expected_json(self):
        self.assertEqual(selfscan.scan_all(RULES), _expected())

    def test_cross_rule_isolation(self):
        """A bad fixture for one rule must be clean for every other rule."""
        dirs = sorted(
            d for d in os.listdir(RULES)
            if os.path.isdir(os.path.join(RULES, d))
        )
        rules = {
            d: selfscan.load_rule(os.path.join(RULES, d, "rule.yaml"))
            for d in dirs
        }
        for own_dir in dirs:
            bad_path = os.path.join(RULES, own_dir, "bad.py")
            for other_dir, other_rule in rules.items():
                if other_dir == own_dir:
                    continue
                findings = selfscan.scan_file(other_rule, bad_path)
                self.assertEqual(
                    findings, [],
                    "%s/bad.py leaked %d finding(s) into rule %s"
                    % (own_dir, len(findings), other_rule["id"]),
                )


class SelfScanPatternNotInsideTests(unittest.TestCase):
    def test_excludes_def_test_blocks(self):
        rule = {
            "id": "x.y",
            "message": "m",
            "severity": "ERROR",
            "fix": "f",
            "patterns": [{"pattern": "pickle.loads(...)"}],
            "pattern-not-inside": "def test_*: ...",
        }
        text = (
            "def test_serialize():\n"
            "    return pickle.loads(blob)\n"
            "\n"
            "\n"
            "def load(blob):\n"
            "    return pickle.loads(blob)\n"
        )
        findings = selfscan.scan_text(rule, text, path="t.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["line"], 6)

    def test_unsupported_not_inside_shape_raises(self):
        rule = {
            "id": "x.y",
            "message": "m",
            "severity": "ERROR",
            "fix": "f",
            "patterns": [{"pattern": "pickle.loads(...)"}],
            "pattern-not-inside": "class Foo: ...",
        }
        with self.assertRaises(ValueError):
            selfscan.scan_text(rule, "x = pickle.loads(y)", path="t.py")


if __name__ == "__main__":
    unittest.main()
