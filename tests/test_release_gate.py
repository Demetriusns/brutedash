"""Tests for scripts/audit_llm_sinks.py (release gate, repo-learning item 2).

The audit scans diffs, so fixtures are synthetic unified diffs fed straight
to audit_diff(). Clean fixtures must stay silent; dirty fixtures must fire
with the right tier. The committed test file itself must not self-flag when
the gate audits its own diff -- fixtures live inside string literals, which
the auditor masks before scanning.
"""
import importlib.util
import os
import unittest

_AUDIT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..",
                                      "scripts", "audit_llm_sinks.py"))
_REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _load_audit():
    spec = importlib.util.spec_from_file_location("audit_llm_sinks", _AUDIT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


audit = _load_audit()


def _diff(path, lines, is_new=False):
    head = ["diff --git a/%s b/%s" % (path, path),
            "index 0000000..1111111 100644",
            "--- /dev/null" if is_new else "--- a/%s" % path,
            "+++ b/%s" % path,
            "@@ -0,0 +1,%d @@" % len(lines)]
    return "\n".join(head + ["+" + ln for ln in lines]) + "\n"


def _find(diff_text, **kw):
    return audit.audit_diff(diff_text, _REPO, **kw)


def _tiers(findings):
    return {f.tier for f in findings}


def _rules(findings):
    return {f.rule for f in findings}


class TestAuditClean(unittest.TestCase):
    def test_clean_parameterized_sql(self):
        d = _diff("netmon/db.py", [
            "def recent(dbm, since):",
            '    return dbm.query("SELECT * FROM alerts WHERE ts > ?",',
            "                      (since,))",
        ])
        self.assertEqual(_find(d), [])

    def test_clean_constant_fstring_sql(self):
        # ALL_CAPS interpolation = module constant, not injection
        d = _diff("netmon/dashboard.py", [
            '    q = f"SELECT {_ALERT_COLS} FROM alerts WHERE ts > ?"',
            "    return dbm.query(q, (since,))",
        ])
        self.assertEqual(_find(d), [])

    def test_clean_docstring_mentioning_sink(self):
        d = _diff("netmon/detect.py", [
            '"""Detect port scans.',
            "",
            "Never do dbm.query(f\"SELECT {x}\") -- always parameterize.",
            '"""',
            "def rule():",
            "    pass",
        ])
        self.assertEqual(_find(d), [])

    def test_clean_env_key(self):
        d = _diff("netmon/ai_assist.py", [
            "def _client():",
            '    api_key = os.environ.get("OPENAI_API_KEY")',
            "    return api_key",
        ])
        self.assertEqual(_find(d), [])

    def test_clean_commented_sink(self):
        d = _diff("netmon/detect.py", [
            "# old code did dbm.query(f\"SELECT {x}\") -- removed",
            "def rule():",
            "    pass",
        ])
        self.assertEqual(_find(d), [])

    def test_clean_argv_subprocess(self):
        d = _diff("netmon/amass.py", [
            "def run_scan():",
            '    subprocess.run(["amass", "enum", "-d", dom],',
            "                     capture_output=True)",
        ])
        self.assertEqual(_find(d), [])


class TestAuditBlockers(unittest.TestCase):
    def test_b_sql_fstring(self):
        d = _diff("netmon/detect.py", [
            "def check(dbm, val):",
            '    return dbm.query(f"SELECT * FROM t WHERE a = {val}")',
        ])
        f = _find(d)
        self.assertIn("BLOCKER", _tiers(f))
        self.assertIn("B-SQL", _rules(f))

    def test_b_sql_concat(self):
        d = _diff("netmon/detect.py", [
            "def check(dbm, where):",
            '    return dbm.query("SELECT * FROM t " + where)',
        ])
        f = _find(d)
        self.assertIn("B-SQL", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))

    def test_b_sql_percent_format(self):
        d = _diff("netmon/detect.py", [
            "def check(dbm, val):",
            '    return dbm.query("SELECT * FROM t WHERE a = %s" % val)',
        ])
        self.assertIn("B-SQL", _rules(_find(d)))

    def test_b_shell_true(self):
        d = _diff("netmon/scan.py", [
            "def probe(host):",
            '    subprocess.run("nmap " + host, shell=True)',
        ])
        f = _find(d)
        self.assertIn("B-SHELL", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))

    def test_b_shell_true_multiline_with_parens(self):
        d = _diff("netmon/scan.py", [
            "def probe(host):",
            "    subprocess.run(",
            '        shlex.split("nmap " + host),',
            "        shell=True,",
            "    )",
        ])
        self.assertIn("B-SHELL", _rules(_find(d)))

    def test_b_os_system(self):
        d = _diff("netmon/scan.py", [
            "def probe(host):",
            '    os.system("ping " + host)',
        ])
        self.assertIn("B-SHELL", _rules(_find(d)))

    def test_b_eval(self):
        d = _diff("netmon/detect.py", [
            "def check(alert):",
            "    return eval(alert_detail)",
        ])
        f = _find(d)
        self.assertIn("B-EVAL", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))

    def test_b_sysinj(self):
        d = _diff("netmon/ai_assist.py", [
            "def triage(alert):",
            '    SYSTEM_PROMPT = f"You are an analyst. Alert: {alert}"',
            "    return ask(SYSTEM_PROMPT)",
        ])
        f = _find(d)
        self.assertIn("B-SYSINJ", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))

    def test_b_hardkey(self):
        d = _diff("netmon/ai_assist.py", [
            "def _client():",
            '    api_key = "sk-proj-abcdef1234567890"',
            "    return api_key",
        ])
        f = _find(d)
        self.assertIn("B-HARDKEY", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))

    def test_path_trick_outside_netmon(self):
        # A sink in an unexpected directory must still be caught.
        d = _diff("tools/helper.py", [
            "def check(alert):",
            "    return eval(alert_detail)",
        ])
        f = _find(d)
        self.assertIn("B-EVAL", _rules(f))
        self.assertIn("BLOCKER", _tiers(f))


class TestAuditSuggestions(unittest.TestCase):
    def test_s_promptfmt_untrusted_kwarg(self):
        d = _diff("netmon/ai_assist.py", [
            "def triage(alert):",
            "    block = alert['title'] + alert['detail']",
            "    return NEW_PROMPT.format(alert_block=block)",
        ])
        f = _find(d)
        self.assertIn("S-PROMPTFMT", _rules(f))
        self.assertNotIn("BLOCKER", _tiers(f))

    def test_s_promptfmt_safe_kwarg_silent(self):
        d = _diff("netmon/ai_assist.py", [
            "def triage():",
            '    return NEW_PROMPT.format(version="3.5")',
        ])
        self.assertEqual(_find(d), [])

    def test_s_llmcall_new_file_no_validator(self):
        d = _diff("netmon/brain.py", [
            "def ask(client, prompt):",
            "    return client.chat.completions.create(",
            '        model="x", messages=[{"role": "user",',
            '                            "content": prompt}])',
        ], is_new=True)
        f = _find(d)
        self.assertIn("S-LLMCALL", _rules(f))
        self.assertNotIn("BLOCKER", _tiers(f))

    def test_s_llmcall_existing_file_silent(self):
        # Existing files are assumed to already carry their validators;
        # the auditor only nags on brand-new call paths.
        d = _diff("netmon/ai_assist.py", [
            "def ask2(client, prompt):",
            "    return client.chat.completions.create(",
            '        model="x", messages=[{"role": "user",',
            '                            "content": prompt}])',
        ])
        self.assertNotIn("S-LLMCALL", _rules(_find(d)))

    def test_s_newtemplate(self):
        d = _diff("netmon/ai_assist.py", [
            'BRIEF_PROMPT = """Summarize this:"""',
            "def brief():",
            "    pass",
        ])
        f = _find(d)
        self.assertIn("S-NEWTEMPLATE", _rules(f))
        self.assertNotIn("BLOCKER", _tiers(f))

    def test_s_constant_interpolated(self):
        d = _diff("netmon/detect.py", [
            'SQL_TMPL = f"SELECT * FROM t WHERE a = {val}"',
        ])
        f = _find(d)
        self.assertIn("S-CONSTANT", _rules(f))
        self.assertNotIn("BLOCKER", _tiers(f))

    def test_s_constant_literal_silent(self):
        d = _diff("netmon/detect.py", [
            'SQL_TMPL = "SELECT * FROM t WHERE a = ?"',
            'MSG = f"v{VERSION}"',
        ])
        self.assertNotIn("S-CONSTANT", _rules(_find(d)))

    def test_n_binary(self):
        d = ("diff --git a/x.png b/x.png\n"
             "index 0000000..1111111 100644\n"
             "Binary files a/x.png and b/x.png differ\n")
        f = _find(d)
        self.assertEqual([x.rule for x in f], ["N-BINARY"])
        self.assertEqual([x.tier for x in f], ["NIT"])

    def test_b_binary_py(self):
        # A binary blob wearing a .py extension must not sail through.
        d = ("diff --git a/netmon/evil.py b/netmon/evil.py\n"
             "index 0000000..1111111 100644\n"
             "Binary files a/netmon/evil.py and b/netmon/evil.py differ\n")
        f = _find(d)
        self.assertEqual([x.rule for x in f], ["B-BINARY"])
        self.assertEqual([x.tier for x in f], ["BLOCKER"])


class TestAuditSelfExclusion(unittest.TestCase):
    def test_auditor_skips_itself(self):
        rel = os.path.relpath(_AUDIT, _REPO)
        d = _diff(rel, [
            "def check(alert):",
            "    return eval(alert_detail)",
        ])
        f = _find(d, self_path=os.path.realpath(_AUDIT))
        self.assertEqual(f, [])

    def test_non_python_ignored(self):
        d = _diff("docs/notes.md", [
            "Never do dbm.query(f\"SELECT {x}\") in code.",
        ])
        self.assertEqual(_find(d), [])


class TestAuditCLI(unittest.TestCase):
    def _run_main(self, diff_text):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".diff",
                                         delete=False) as fh:
            fh.write(diff_text)
            path = fh.name
        try:
            return audit.main(["--diff-file", path, "--quiet"])
        finally:
            os.unlink(path)

    def test_exit_0_clean(self):
        d = _diff("netmon/db.py", ["x = 1"])
        self.assertEqual(self._run_main(d), 0)

    def test_exit_1_blocker(self):
        d = _diff("netmon/detect.py", ["x = eval(y)"])
        self.assertEqual(self._run_main(d), 1)

    def test_exit_0_suggestion_only(self):
        d = _diff("netmon/ai_assist.py",
                  ["x = NEW_PROMPT.format(alert_block=b)"])
        self.assertEqual(self._run_main(d), 0)

    def test_exit_0_empty_diff(self):
        self.assertEqual(self._run_main(""), 0)

    def test_exit_2_bad_diff_file(self):
        self.assertEqual(
            audit.main(["--diff-file", "/nonexistent/xyz.diff", "--quiet"]),
            2)


if __name__ == "__main__":
    unittest.main()
