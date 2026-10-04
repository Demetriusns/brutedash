"""Tests for the Phase 3.5 batch 11 template DSL (2026-10-04):
detection-as-code -- new self-scan checks as YAML files in templates/.

- Minimal YAML-subset parser: valid templates parse; anything outside
  the subset (anchors, tags, flow syntax, tabs) is rejected.
- Schema validation: id/info/severity/matcher rules enforced.
- Loader: valid files load, invalid files are skipped with a warning
  (never break the scan); matcher ports overlapping the built-in
  SCAN_PORTS are skipped (findings key on (ip, port)).
- Matcher engine: port_open / ports_open evaluated against scan
  results (pure function, no I/O).
- The four shipped templates: all valid, none overlap SCAN_PORTS.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import templates as tmplm
from netmon import scan as scanm


_VALID = """\
id: test-check
info:
  name: "Test check"
  service: "Test"
  severity: medium
  description: "A test check for unit tests."
  tags: [network, test]
match:
  port_open: 2375
"""


class ParserTests(unittest.TestCase):
    def test_valid_template_parses(self):
        t = tmplm.parse_template_text(_VALID)
        self.assertEqual(t["id"], "test-check")
        self.assertEqual(t["info"]["severity"], "medium")
        self.assertEqual(t["info"]["service"], "Test")
        self.assertEqual(t["info"]["tags"], ["network", "test"])
        self.assertEqual(t["match"], {"port_open": 2375})

    def test_ports_open_matcher(self):
        # block list form
        text = _VALID.replace("  port_open: 2375",
                              "  ports_open:\n    - 9200\n    - 9300")
        t = tmplm.parse_template_text(text)
        self.assertEqual(t["match"], {"ports_open": [9200, 9300]})
        # inline flow list of scalars is also fine
        text2 = _VALID.replace("  port_open: 2375",
                              "  ports_open: [9200, 9300]")
        t2 = tmplm.parse_template_text(text2)
        self.assertEqual(t2["match"], {"ports_open": [9200, 9300]})

    def test_single_quotes_and_plain_scalars(self):
        text = _VALID.replace('"Test check"', "'Test check'")
        t = tmplm.parse_template_text(text)
        self.assertEqual(t["info"]["name"], "Test check")

    def test_comments_and_blank_lines_ignored(self):
        text = "# a comment\n\n" + _VALID + "\n# trailing\n"
        t = tmplm.parse_template_text(text)
        self.assertEqual(t["id"], "test-check")

    def test_anchors_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(_VALID + "anchor: &x 1\n")

    def test_python_tag_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(
                _VALID.replace('severity: medium',
                               'severity: !!python/str medium'))

    def test_flow_syntax_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(
                _VALID.replace("tags: [network, test]",
                               "tags: {a: b}"))

    def test_tabs_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(_VALID.replace(
                "  port_open: 2375", "\tport_open: 2375"))

    def test_unknown_top_level_key_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(_VALID + "bogus: 1\n")

    def test_duplicate_keys_rejected(self):
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(_VALID + "id: another-id\n")
        dup_nested = _VALID.replace(
            '  severity: medium',
            '  severity: medium\n  severity: low')
        with self.assertRaises(ValueError):
            tmplm.parse_template_text(dup_nested)

    def test_template_content_never_executes(self):
        # Even hostile-looking content is inert data or a rejection.
        evil = _VALID.replace(
            'description: "A test check for unit tests."',
            'description: "__import__(\'os\').system(\'id\')"')
        t = tmplm.parse_template_text(evil)
        self.assertIn("__import__", t["info"]["description"])


class ValidationTests(unittest.TestCase):
    def _base(self):
        return {
            "id": "x-check",
            "info": {"name": "X", "service": "X", "severity": "low",
                     "description": "d"},
            "match": {"port_open": 2376},
        }

    def test_bad_ids_rejected(self):
        for bad in ["", "UPPER", "with space", "a" * 65, "semi;colon",
                    "../escape"]:
            d = self._base()
            d["id"] = bad
            with self.assertRaises(ValueError, msg=bad):
                tmplm.validate_template(d)

    def test_bad_severities_rejected(self):
        for bad in ["high", "critical", "info", "", None]:
            d = self._base()
            d["info"]["severity"] = bad
            with self.assertRaises(ValueError, msg=str(bad)):
                tmplm.validate_template(d)

    def test_bad_ports_rejected(self):
        for bad in [0, 65536, -1, "2375", 12.5, True, None]:
            d = self._base()
            d["match"] = {"port_open": bad}
            with self.assertRaises(ValueError, msg=str(bad)):
                tmplm.validate_template(d)

    def test_matcher_needs_exactly_one_key(self):
        d = self._base()
        d["match"] = {"port_open": 2375, "ports_open": [9200]}
        with self.assertRaises(ValueError):
            tmplm.validate_template(d)
        d["match"] = {}
        with self.assertRaises(ValueError):
            tmplm.validate_template(d)
        d["match"] = {"banner_contains": "foo"}
        with self.assertRaises(ValueError):
            tmplm.validate_template(d)

    def test_empty_ports_open_rejected(self):
        d = self._base()
        d["match"] = {"ports_open": []}
        with self.assertRaises(ValueError):
            tmplm.validate_template(d)

    def test_description_required(self):
        d = self._base()
        d["info"]["description"] = "   "
        with self.assertRaises(ValueError):
            tmplm.validate_template(d)

    def test_severity_normalized(self):
        d = self._base()
        d["info"]["severity"] = "Medium"
        t = tmplm.validate_template(d)
        self.assertEqual(t["info"]["severity"], "medium")


class LoaderTests(unittest.TestCase):
    def _write(self, directory, name, text):
        with open(os.path.join(directory, name), "w") as fh:
            fh.write(text)

    def test_valid_and_invalid_files(self):
        d = tempfile.mkdtemp(prefix="tmpl-test-")
        try:
            self._write(d, "good.yaml", _VALID)
            self._write(d, "bad.yaml", "id: [not a mapping\n")
            self._write(d, "wrong-sev.yaml", _VALID.replace(
                "severity: medium", "severity: critical"))
            self._write(d, "notes.txt", "ignored")
            loaded = tmplm.load_templates(d)
            self.assertEqual([t["id"] for t in loaded], ["test-check"])
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_overlap_with_builtin_ports_skipped(self):
        d = tempfile.mkdtemp(prefix="tmpl-test-")
        try:
            overlap = _VALID.replace("port_open: 2375", "port_open: 23")
            self._write(d, "overlap.yaml", overlap)
            self.assertEqual(tmplm.load_templates(d), [])
        finally:
            for f in os.listdir(d):
                os.unlink(os.path.join(d, f))
            os.rmdir(d)

    def test_missing_directory_returns_empty(self):
        self.assertEqual(tmplm.load_templates("/nonexistent/dir"), [])

    def test_shipped_templates_all_valid(self):
        loaded = tmplm.load_templates()
        ids = {t["id"] for t in loaded}
        self.assertEqual(ids, {"docker-api-open", "elasticsearch-open",
                               "memcached-open", "mqtt-open"})
        builtin = {p for p, _ in scanm.SCAN_PORTS}
        for t in loaded:
            ports = tmplm.matcher_ports(t)
            self.assertFalse(ports & builtin,
                             f"{t['id']} overlaps SCAN_PORTS")
            self.assertIn(t["info"]["severity"], {"low", "medium"})
            self.assertTrue(t["info"]["description"])

    def test_required_ports_bounded(self):
        loaded = tmplm.load_templates()
        ports = tmplm.required_ports(loaded)
        self.assertTrue(ports)
        self.assertLessEqual(len(ports), 32)
        self.assertIn(2375, ports)
        self.assertIn(9200, ports)
        self.assertIn(9300, ports)  # elasticsearch needs both


class EvaluateTests(unittest.TestCase):
    def _tmpl(self, tid, match):
        return {"id": tid,
                "info": {"name": tid, "service": tid,
                         "severity": "medium", "description": "d",
                         "tags": []},
                "match": match}

    def test_port_open_fires(self):
        t = self._tmpl("t", {"port_open": 2375})
        got = tmplm.evaluate([t], {"192.168.1.10": {2375, 80},
                                   "192.168.1.11": {80}})
        self.assertEqual(got, [("192.168.1.10", 2375, t)])

    def test_ports_open_needs_all(self):
        t = self._tmpl("t", {"ports_open": [9200, 9300]})
        got = tmplm.evaluate([t], {"192.168.1.10": {9200},
                                   "192.168.1.11": {9200, 9300}})
        self.assertEqual(
            got, [("192.168.1.11", 9200, t),
                  ("192.168.1.11", 9300, t)])

    def test_no_templates_no_findings(self):
        self.assertEqual(tmplm.evaluate([], {"192.168.1.10": {2375}}),
                         [])
        self.assertEqual(tmplm.evaluate(None, None), [])

    def test_risk_ports_only_medium(self):
        ports = tmplm.risk_ports()
        self.assertIn(2375, ports)
        self.assertEqual(ports[2375][0], "Medium")


if __name__ == "__main__":
    unittest.main()
