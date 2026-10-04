"""Consistency tests for the detection catalog (netmon/detection_catalog.py).

The catalog is the single source of truth for every rule that can fire an
alert. These tests make sure nothing lands without its paperwork:

- every alert kind the monitor emits (add_alert call sites) has a catalog
  entry, and every catalog entry names a kind the monitor emits
- every catalog entry's MITRE mapping matches netmon/mitre.py, and every
  mitre.py kind has a catalog entry
- every catalog entry has a fix-it guide in netmon/playbooks.py, and every
  playbook kind has a catalog entry
- every validation-test pointer in the catalog resolves to a real
  test file / class / method
- docs/DETECTION-CATALOG.md is in sync with the rendered registry
  (re-render with: python -m netmon.detection_catalog --render)

Run: python -m unittest discover -s tests -v
"""
import importlib
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from netmon import detection_catalog as cat
from netmon import mitre as mitrem
from netmon import playbooks as pbm

_REPO = os.path.join(os.path.dirname(__file__), "..")
_NETMON = os.path.join(_REPO, "netmon")
_DOC = os.path.join(_REPO, "docs", "DETECTION-CATALOG.md")


def _emitted_kinds():
    """Alert kinds emitted anywhere in netmon/ (add_alert call sites)."""
    kinds = set()
    pat = re.compile(r"add_alert\(\s*\"([a-z_0-9]+)\"")
    for fn in os.listdir(_NETMON):
        if not fn.endswith(".py"):
            continue
        with open(os.path.join(_NETMON, fn), encoding="utf-8") as fh:
            kinds.update(pat.findall(fh.read()))
    return kinds


class CatalogCoverageTests(unittest.TestCase):
    def test_every_emitted_kind_has_catalog_entry(self):
        missing = [k for k in sorted(_emitted_kinds())
                   if cat.by_id(k) is None]
        self.assertEqual(missing, [],
                         f"alert kinds without catalog entries: {missing}")

    def test_every_catalog_entry_is_actually_emitted(self):
        emitted = _emitted_kinds()
        orphan = [r["id"] for r in cat.RULES if r["id"] not in emitted]
        self.assertEqual(orphan, [],
                         f"catalog entries no rule emits: {orphan}")

    def test_catalog_ids_unique(self):
        ids = [r["id"] for r in cat.RULES]
        self.assertEqual(len(ids), len(set(ids)),
                         "duplicate catalog ids")


class MitreConsistencyTests(unittest.TestCase):
    def test_every_catalog_entry_matches_mitre_py(self):
        problems = []
        for r in cat.RULES:
            tag = mitrem.tag_for(r["id"])
            if tag is None:
                problems.append(f"{r['id']}: no mitre.py entry")
                continue
            for field in ("mitre_id", "mitre_name", "mitre_tactic"):
                key = {"mitre_id": "id", "mitre_name": "name",
                       "mitre_tactic": "tactic"}[field]
                if r[field] != tag[key]:
                    problems.append(
                        f"{r['id']}: catalog {field}={r[field]!r} != "
                        f"mitre.py {tag[key]!r}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_mitre_kind_has_catalog_entry(self):
        missing = [k for k in mitrem.all_kinds() if cat.by_id(k) is None]
        self.assertEqual(missing, [],
                         f"mitre.py kinds without catalog entries: {missing}")


class PlaybookConsistencyTests(unittest.TestCase):
    def test_every_catalog_entry_has_a_guide(self):
        missing = [r["id"] for r in cat.RULES
                   if pbm.playbook_slug_for_kind(r["id"]) is None]
        self.assertEqual(missing, [],
                         f"kinds without playbook guides: {missing}")

    def test_every_playbook_kind_has_catalog_entry(self):
        missing = [k for k in pbm.KIND_TO_SLUG if cat.by_id(k) is None]
        self.assertEqual(missing, [],
                         f"playbook kinds without catalog entries: {missing}")


class TestPointerTests(unittest.TestCase):
    def _resolve(self, pointer):
        """'tests/test_x.py::ClassName.test_method' -> the bound method."""
        path_part, _, member = pointer.partition("::")
        cls_name, _, meth_name = member.partition(".")
        mod_name = path_part[:-3].replace("/", ".")  # tests/test_x.py
        path = os.path.join(_REPO, path_part)
        if not os.path.isfile(path):
            return None, f"missing file {path_part}"
        mod = importlib.import_module(mod_name)
        cls = getattr(mod, cls_name, None)
        if cls is None:
            return None, f"{path_part}: no class {cls_name}"
        meth = getattr(cls, meth_name, None)
        if meth is None:
            return None, f"{path_part}::{cls_name}: no method {meth_name}"
        return meth, None

    def test_every_validation_pointer_resolves(self):
        problems = []
        for r in cat.RULES:
            if not r.get("tests"):
                problems.append(f"{r['id']}: no validation test listed")
                continue
            for pointer in r["tests"]:
                _, err = self._resolve(pointer)
                if err:
                    problems.append(f"{r['id']}: {err}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_every_validation_pointer_names_its_kind(self):
        """The referenced test file must mention the rule's kind -- a
        pointer to an unrelated test that never touches the rule is a
        dangling reference with a fresh coat of paint."""
        problems = []
        seen_files = {}
        for r in cat.RULES:
            for pointer in r.get("tests", []):
                path_part = pointer.split("::")[0]
                if path_part not in seen_files:
                    with open(os.path.join(_REPO, path_part),
                              encoding="utf-8") as fh:
                        seen_files[path_part] = fh.read()
                if r["id"] not in seen_files[path_part]:
                    problems.append(
                        f"{r['id']}: {pointer} never mentions"
                        f" {r['id']!r}")
        self.assertEqual(problems, [], "\n".join(problems))

    def test_catalog_entries_are_complete(self):
        required = ("id", "title", "module", "rule", "description",
                    "trigger", "severities", "mitre_id", "mitre_name",
                    "mitre_tactic", "fp_profile", "recognize_fp",
                    "tuning", "tests")
        problems = []
        for r in cat.RULES:
            for field in required:
                if not r.get(field):
                    problems.append(f"{r.get('id')}: empty {field}")
        self.assertEqual(problems, [], "\n".join(problems))


class DocSyncTests(unittest.TestCase):
    def test_rendered_doc_is_in_sync(self):
        with open(_DOC, encoding="utf-8") as fh:
            current = fh.read()
        rendered = cat.render_markdown()
        self.assertEqual(current, rendered,
                         "docs/DETECTION-CATALOG.md is out of sync with "
                         "netmon/detection_catalog.py -- re-render with: "
                         "python -m netmon.detection_catalog --render")

    def test_doc_covers_every_rule(self):
        with open(_DOC, encoding="utf-8") as fh:
            doc = fh.read()
        missing = [r["id"] for r in cat.RULES
                   if f"### `{r['id']}`" not in doc]
        self.assertEqual(missing, [],
                         f"rules missing from the rendered doc: {missing}")


if __name__ == "__main__":
    unittest.main()
