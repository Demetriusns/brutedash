#!/usr/bin/env python3
"""Pre-commit audit for LLM-generated detection rules + brief-prompt templates.

Repo-learning item 2 (the ai-generated-code-auditor pattern): scan a unified
diff -- staged by default -- for prompt-injection sinks, i.e. places where
alert text / network-derived strings reach the model, plus a few hard
blockers (f-string SQL, shell=True, eval/exec, hardcoded secrets) that the
release gate enforces locally even where semgrep is not installed.

Design principle (from the ai-code-audit checklist): prompt-injection
detection stays HEURISTIC -- medium confidence, flagged for human verify,
never claimed as proof of exploit.

Known limitations (documented, not silently absent):
  * The audit does not follow variable assignments or string propagation
    (''.join, intermediate variables). Indirect construction of SQL or
    prompts is a REVIEWER check -- see docs/CODE-REVIEW-CHECKLIST.md.
  * B-SQL trusts ALL_CAPS names at the use site; interpolated constant
    DEFINITIONS get S-CONSTANT so a reviewer confirms the value is safe.

Tiers:
  BLOCKER     almost certainly wrong; the gate fails. Exit 1.
  SUGGESTION  should fix / confirm; reported, gate still passes.
  NIT         nice to have; reported only.

Exit codes: 0 = no blockers, 1 = >=1 blocker, 2 = the audit itself failed
(fail closed: the release gate treats 2 as FAIL).

Anti-bypass notes (reviewed):
  * Scans EVERY staged .py file, not just netmon/ -- a sink hidden in an
    unexpected directory is still a sink.
  * Skips only its own file (by resolved realpath, not by name match).
  * String-literal contents are masked before scanning so docstrings and
    test fixtures cannot cause false positives -- but f-string {holes}
    are preserved, because that is exactly where injection lives.
  * If git is unavailable or the diff cannot be produced, exits 2 rather
    than silently passing.
"""
import argparse
import bisect
import os
import re
import shlex
import subprocess
import sys

TIERS = ("BLOCKER", "SUGGESTION", "NIT")

# Kwarg/field names that smell like untrusted, network- or alert-derived
# content being fed into a prompt template.
UNTRUSTED_KWARGS = frozenset({
    "alert_block", "recent_block", "context", "evidence", "report",
    "question", "alert", "title", "detail", "meaning", "brief",
    "hostname", "domain", "ip", "alert_text", "summary",
})

DIFF_SIZE_WARN = 2 * 1024 * 1024  # warn (not fail) on very large diffs


class AuditError(Exception):
    """The audit itself could not run -- fail closed."""


# --------------------------------------------------------------------------
# Diff parsing
# --------------------------------------------------------------------------

def _b_path(token):
    """Strip a/ b/ prefix and surrounding quotes from a diff path token."""
    if len(token) >= 2 and token[1] == "/":
        token = token[2:]
    if token == "dev/null":
        return None
    return token


def parse_diff(diff_text):
    """Parse a unified diff into a list of dicts:

    {"path": str, "is_new": bool, "added": [(lineno, text), ...],
     "binary": bool}
    Only .py files are returned. Deleted files are skipped.
    """
    files = []
    cur = None
    new_lineno = 0
    in_hunk = False
    for raw in diff_text.splitlines():
        line = raw
        if line.startswith("diff --git "):
            try:
                parts = shlex.split(line)
            except ValueError:
                parts = line.split()
            b_raw = parts[2] if len(parts) > 2 else ""
            if b_raw.startswith('"') and b_raw.endswith('"'):
                try:
                    b_raw = shlex.split(b_raw)[0]
                except ValueError:
                    pass
            path = _b_path(b_raw)
            cur = {"path": path, "is_new": False, "added": [],
                   "binary": False}
            files.append(cur)
            in_hunk = False
            continue
        if cur is None:
            continue
        if line.startswith("Binary files ") and " differ" in line:
            cur["binary"] = True
            continue
        if line.startswith("--- "):
            if line[4:].strip() in ("/dev/null", "a/dev/null"):
                cur["is_new"] = True
            continue
        if line.startswith("+++ "):
            if line[4:].strip() in ("/dev/null", "b/dev/null"):
                cur["path"] = None  # deleted file
            continue
        m = re.match(r"@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@", line)
        if m:
            new_lineno = int(m.group(1))
            in_hunk = True
            continue
        if not in_hunk:
            continue
        if line.startswith("+") and not line.startswith("+++"):
            cur["added"].append((new_lineno, line[1:]))
            new_lineno += 1
        elif line.startswith("-") and not line.startswith("---"):
            pass  # removed line: new-file lineno does not advance
        elif line == "\\ No newline at end of file":
            pass
        else:
            new_lineno += 1  # context line
    return [f for f in files
            if f["path"] and (f["binary"] or f["path"].endswith(".py"))]


# --------------------------------------------------------------------------
# String masking: hide literal contents, keep f-string {holes} visible
# --------------------------------------------------------------------------

def _mask_strings(text):
    """Replace string-literal contents and comments with spaces.

    Offsets are preserved. f-string interpolation holes {expr} are KEPT
    visible -- that is where injection sinks live. Everything else inside
    quotes, plus # comments, becomes spaces, so docstrings, comments and
    test fixtures cannot false-positive.
    """
    out = list(text)
    i, n = 0, len(text)
    while i < n:
        # comment start (outside strings)?
        if text[i] == "#":
            j = text.find("\n", i)
            j = n if j == -1 else j
            for k in range(i, j):
                out[k] = " "
            i = j
            continue
        # find the next quote, checking for an f-string prefix
        m = re.search(r"[\"']", text[i:])
        if not m:
            break
        q = i + m.start()
        # string prefix: letters immediately before the quote
        p = q - 1
        while p >= 0 and text[p] in "rRbBuUfF":
            p -= 1
        prefix = text[p + 1:q]
        is_f = "f" in prefix or "F" in prefix
        triple = text.startswith(text[q] * 3, q)
        qlen = 3 if triple else 1
        j = q + qlen
        if is_f:
            depth = 0
            while j < n:
                c = text[j]
                if c == "\\":
                    if depth == 0:
                        out[j] = " "
                        if j + 1 < n and text[j + 1] != "\n":
                            out[j + 1] = " "
                    j += 2
                    continue
                if c == "{":
                    depth += 1
                    j += 1
                    continue
                if c == "}":
                    if depth > 0:
                        depth -= 1
                        j += 1
                        continue
                    # closing brace at depth 0 ends... no: only quote ends
                if depth == 0 and text.startswith(text[q] * qlen, j):
                    # check this isn't an escaped quote inside the string
                    j += qlen
                    break
                if depth == 0:
                    if c != "\n":
                        out[j] = " "
                j += 1
                if not triple and c == "\n":
                    break
        else:
            while j < n:
                c = text[j]
                if c == "\\":
                    if j + 1 < n and text[j + 1] != "\n":
                        out[j + 1] = " "
                    out[j] = " "
                    j += 2
                    continue
                if text.startswith(text[q] * qlen, j):
                    j += qlen
                    break
                if c != "\n":
                    out[j] = " "
                j += 1
                if not triple and c == "\n":
                    break
        # mask the quote characters themselves? No -- keep them so the
        # f-prefix patterns (f"...) still match; mask only contents.
        i = j
    return "".join(out)


# --------------------------------------------------------------------------
# Findings
# --------------------------------------------------------------------------

class Finding:
    def __init__(self, tier, rule, path, lineno, message, snippet=""):
        assert tier in TIERS
        self.tier = tier
        self.rule = rule
        self.path = path
        self.lineno = lineno
        self.message = message
        self.snippet = snippet[:160]

    def __str__(self):
        loc = "%s:%s" % (self.path, self.lineno or "?")
        s = "%s [%s] %s: %s" % (self.tier, self.rule, loc, self.message)
        if self.snippet:
            s += "\n    | %s" % self.snippet.strip()
        return s


def _line_of(offset, line_starts):
    return bisect.bisect_right(line_starts, offset)


def _line_starts(text):
    starts = [0]
    for m in re.finditer(r"\n", text):
        starts.append(m.end())
    return starts


# --------------------------------------------------------------------------
# Rules -- each takes (path, masked_text, raw_text, line_starts, is_new)
# --------------------------------------------------------------------------

def _rule_b_sql(path, masked, raw, starts, is_new):
    """f-string / concatenated / %-formatted SQL in db query calls."""
    out = []
    for m in re.finditer(
            r"\b(?:dbm|cursor|conn|self\.conn|self\.db)\s*\.\s*"
            r"(query|execute|executemany)\s*\(", masked):
        end = _paren_span(masked, m.end() - 1)
        call = masked[m.start():end if end else m.start() + 600]
        ln = _line_of(m.start(), starts)
        # f-string with a non-constant interpolation hole: f"...{x}..."
        fm = re.search(r"\(\s*f[\"']", call)
        if fm and re.search(
                r"\{(?![A-Z_][A-Z0-9_]*\})[a-zA-Z_][a-zA-Z0-9_.]*",
                call[fm.end():]):
            hole = re.search(
                r"\{(?![A-Z_][A-Z0-9_]*\})[a-zA-Z_][a-zA-Z0-9_.]*",
                call[fm.end():]).group(0).split("}")[0]
            out.append(Finding(
                "BLOCKER", "B-SQL", path, ln,
                "f-string interpolation %s into a SQL query call -- "
                "use a parameterized ? placeholder instead" % hole,
                snippet=raw[m.start():m.start() + 120]))
            continue
        # string literal concatenated with / %-formatted by an identifier
        if (re.search(r"[\"']\s*\+\s*[a-z][a-zA-Z0-9_]*", call)
                or re.search(r"[\"']\s*%\s*\(?[a-z_(]", call)):
            out.append(Finding(
                "BLOCKER", "B-SQL", path, ln,
                "string concatenation / %-formatting into a SQL query "
                "call -- use a parameterized ? placeholder instead",
                snippet=raw[m.start():m.start() + 120]))
    return out


def _paren_span(text, open_idx):
    """Return the index just past the paren matching text[open_idx]=='('.

    Walks on masked text, so parens inside string literals cannot confuse
    the depth count. Returns None if unbalanced.
    """
    depth = 0
    for j in range(open_idx, len(text)):
        c = text[j]
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return j + 1
    return None


def _rule_b_shell(path, masked, raw, starts, is_new):
    out = []
    for m in re.finditer(
            r"subprocess\s*\.\s*(?:Popen|call|run|check_output|check_call)"
            r"\s*\(", masked):
        end = _paren_span(masked, m.end() - 1)
        call = masked[m.start():end if end else m.start() + 600]
        if re.search(r"\bshell\s*=\s*True", call):
            out.append(Finding(
                "BLOCKER", "B-SHELL", path,
                _line_of(m.start(), starts),
                "subprocess with shell=True -- pass an argv list instead "
                "(see netmon/amass.py build_argv)",
                snippet=raw[m.start():m.start() + 120]))
    for m in re.finditer(r"\bos\.system\s*\(", masked):
        out.append(Finding(
            "BLOCKER", "B-SHELL", path,
            _line_of(m.start(), starts),
            "os.system() -- use subprocess with an argv list instead",
            snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_b_eval(path, masked, raw, starts, is_new):
    out = []
    for m in re.finditer(r"\b(?:eval|exec)\s*\(", masked):
        out.append(Finding(
            "BLOCKER", "B-EVAL", path, _line_of(m.start(), starts),
            "eval()/exec() in production code -- no dynamic code "
            "execution on alert/network data",
            snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_b_sysinj(path, masked, raw, starts, is_new):
    """Untrusted data interpolated into the INSTRUCTION (system) side."""
    out = []
    for m in re.finditer(
            r"(?i)(?:\bsystem[_\s-]*prompt\s*=\s*f[\"']"
            r"|[\"']system[\"']\s*:\s*f[\"'])", masked):
        out.append(Finding(
            "BLOCKER", "B-SYSINJ", path, _line_of(m.start(), starts),
            "f-string interpolation into a SYSTEM/instruction prompt -- "
            "untrusted alert/network text must only ever reach the model "
            "as delimited user-role content, never as instructions",
            snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_b_hardkey(path, masked, raw, starts, is_new):
    """Hardcoded secret-looking literal (defense in depth; gitleaks leads).

    Runs on MASKED text: the secret value itself is never visible to this
    rule (and never echoed in findings -- per the ai-code-audit checklist,
    findings carry type + location only). A key-shaped literal inside a
    test's string fixture is test data, not a leak, so it stays silent;
    real code assignments still fire. gitleaks remains the primary
    enforcer, with a narrow allowlist for the test fixture value in
    .gitleaks.toml.
    """
    out = []
    for m in re.finditer(
            r"(?i)\b(api[_-]?key|secret|passwd|password|token)\b"
            r"\s*=\s*[fF]?[\"'][^\"']{2,}[\"']", masked):
        out.append(Finding(
            "BLOCKER", "B-HARDKEY", path, _line_of(m.start(), starts),
            "hardcoded secret-looking literal -- keys live in "
            "environment variables only, never in code",
            snippet="[redacted assignment]"))
    return out


def _rule_s_promptfmt(path, masked, raw, starts, is_new):
    """New .format() on a prompt template fed with untrusted kwargs."""
    out = []
    for m in re.finditer(r"\b\w*PROMPT\s*\.\s*format\s*\(", masked):
        window = masked[m.end():m.end() + 800]
        kwargs = set(re.findall(r"(\w+)\s*=", window))
        hit = kwargs & UNTRUSTED_KWARGS
        if hit:
            out.append(Finding(
                "SUGGESTION", "S-PROMPTFMT", path,
                _line_of(m.start(), starts),
                "prompt template .format() fed with untrusted kwarg(s) %s "
                "-- confirm an output-contract/schema validator covers "
                "this sink (see ai_assist._validate_verdict)" % sorted(hit),
                snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_s_llmcall(path, masked, raw, starts, is_new):
    """A brand-new file opening an LLM call path without a validator."""
    if not is_new:
        return []
    if not re.search(r"chat\.completions\.create|_json_chat\s*\(", masked):
        return []
    if re.search(r"def\s+\w*valid\w*\s*\(|_valid\w*\s*\(", masked):
        return []
    m = re.search(r"chat\.completions\.create|_json_chat\s*\(", masked)
    return [Finding(
        "SUGGESTION", "S-LLMCALL", path, _line_of(m.start(), starts),
        "new file opens an LLM call path with no output-contract "
        "validator visible -- validate the model's JSON before use "
        "(see ai_assist._validate_verdict)",
        snippet=raw[m.start():m.start() + 120])]


def _rule_s_newtemplate(path, masked, raw, starts, is_new):
    """A new prompt template constant was added."""
    out = []
    for m in re.finditer(r"\b[A-Z][A-Z0-9_]*PROMPT\s*=", masked):
        out.append(Finding(
            "SUGGESTION", "S-NEWTEMPLATE", path,
            _line_of(m.start(), starts),
            "new prompt template -- confirm untrusted sections are "
            "clearly delimited from instructions and the model output "
            "has an explicit contract (see ai_assist.TRIAGE_PROMPT)",
            snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_s_constant(path, masked, raw, starts, is_new):
    """Module constant built with f-string interpolation.

    B-SQL exempts ALL_CAPS constants at the USE site (e.g.
    f"SELECT {_ALERT_COLS} ..."), which is only safe if the constant
    itself is a literal. Flag interpolated constant DEFINITIONS so a
    reviewer confirms the value is safe -- the audit does not follow
    variable assignments (documented limitation; the reviewer does).
    """
    out = []
    for m in re.finditer(r"(?m)^[ \t]*[A-Z][A-Z0-9_]{2,}\s*=\s*f[\"']", masked):
        window = masked[m.end():m.end() + 400]
        if re.search(r"\{(?![A-Z_][A-Z0-9_]*\})[a-zA-Z_]", window):
            out.append(Finding(
                "SUGGESTION", "S-CONSTANT", path,
                _line_of(m.start(), starts),
                "module constant built with f-string interpolation -- "
                "keep SQL/query constants literal; B-SQL trusts ALL_CAPS "
                "names at the use site",
                snippet=raw[m.start():m.start() + 120]))
    return out


def _rule_n_todo(path, masked, raw, starts, is_new):
    out = []
    for m in re.finditer(r"(?i)\bTODO\b|\bFIXME\b", masked):
        window = masked[max(0, m.start() - 200):m.start() + 200]
        if re.search(r"PROMPT|completions|_json_chat|valid", window,
                     re.IGNORECASE):
            out.append(Finding(
                "NIT", "N-TODO", path, _line_of(m.start(), starts),
                "TODO/FIXME near prompt/LLM code -- resolve before release",
                snippet=raw[m.start():m.start() + 120]))
    return out


RULES = (_rule_b_sql, _rule_b_shell, _rule_b_eval, _rule_b_sysinj,
         _rule_b_hardkey, _rule_s_promptfmt, _rule_s_llmcall,
         _rule_s_newtemplate, _rule_s_constant, _rule_n_todo)


def audit_file(path, added_lines, is_new):
    """Audit one file's added lines. Returns [Finding]."""
    raw = "\n".join(t for _, t in added_lines)
    masked = _mask_strings(raw)
    starts = _line_starts(raw)
    # map joined-text line index -> real diff lineno
    lineno_of = [ln for ln, _ in added_lines]

    def real_lineno(idx):
        i = min(idx, len(lineno_of) - 1)
        return lineno_of[max(i, 0)]

    findings = []
    for rule in RULES:
        for f in rule(path, masked, raw, starts, is_new):
            f.lineno = real_lineno(f.lineno)
            findings.append(f)
    return findings


def audit_diff(diff_text, repo_root, self_path=None):
    """Audit a unified diff. Returns [Finding], sorted by tier then path."""
    if len(diff_text) > DIFF_SIZE_WARN:
        sys.stderr.write(
            "audit_llm_sinks: warning: diff is %d bytes; scan may be slow\n"
            % len(diff_text))
    findings = []
    for f in parse_diff(diff_text):
        if f["binary"]:
            if f["path"].endswith(".py"):
                # Fail closed: a binary blob with a .py extension is not
                # reviewable -- it must never pass the gate silently.
                findings.append(Finding(
                    "BLOCKER", "B-BINARY", f["path"], 0,
                    "binary content in a .py file -- not reviewable; "
                    "commit text source, not a blob"))
            else:
                findings.append(Finding(
                    "NIT", "N-BINARY", f["path"], 0,
                    "binary file added/changed -- not scannable by this "
                    "text audit; gitleaks still scans it"))
            continue
        if self_path:
            try:
                if os.path.realpath(os.path.join(repo_root, f["path"])) \
                        == self_path:
                    continue  # never audit the auditor
            except OSError:
                pass
        findings.extend(audit_file(f["path"], f["added"], f["is_new"]))
    findings.sort(key=lambda x: (TIERS.index(x.tier), x.path,
                                 x.lineno or 0))
    return findings


# --------------------------------------------------------------------------
# Diff acquisition
# --------------------------------------------------------------------------

def _git(args, repo_root):
    try:
        p = subprocess.run(
            ["git"] + args, cwd=repo_root, capture_output=True, text=True,
            timeout=60)
    except (OSError, subprocess.TimeoutExpired) as e:
        raise AuditError("git failed: %s" % e)
    if p.returncode != 0:
        raise AuditError("git %s failed: %s" % (args[0], p.stderr.strip()))
    return p.stdout


def get_diff(args, repo_root):
    if args.diff_file:
        try:
            with open(args.diff_file, "r", encoding="utf-8",
                      errors="replace") as fh:
                return fh.read()
        except OSError as e:
            raise AuditError("cannot read --diff-file: %s" % e)
    if args.worktree:
        return _git(["diff", "HEAD", "--no-ext-diff", "--no-color", "--",
                     "."], repo_root)
    return _git(["diff", "--cached", "--no-ext-diff", "--no-color", "--",
                 "."], repo_root)


def find_repo_root(start):
    try:
        p = subprocess.run(["git", "rev-parse", "--show-toplevel"],
                           cwd=start, capture_output=True, text=True,
                           timeout=15)
    except (OSError, subprocess.TimeoutExpired):
        return os.path.abspath(start)
    if p.returncode != 0:
        return os.path.abspath(start)
    return p.stdout.strip()


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Audit a diff for LLM prompt-injection sinks and "
                    "hard blockers (f-string SQL, shell=True, eval, "
                    "hardcoded secrets).")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--staged", action="store_true",
                     help="audit the staged diff (default)")
    src.add_argument("--worktree", action="store_true",
                     help="audit staged+unstaged changes vs HEAD")
    src.add_argument("--diff-file", metavar="PATH",
                     help="audit a pre-generated unified diff file")
    ap.add_argument("--quiet", action="store_true",
                    help="print only findings, no summary")
    args = ap.parse_args(argv)

    repo_root = find_repo_root(os.getcwd())
    self_path = os.path.realpath(__file__)
    try:
        diff_text = get_diff(args, repo_root)
    except AuditError as e:
        sys.stderr.write("audit_llm_sinks: ERROR: %s\n" % e)
        return 2
    if not diff_text.strip():
        if not args.quiet:
            print("audit_llm_sinks: no changes to audit -- PASS")
        return 0
    findings = audit_diff(diff_text, repo_root, self_path=self_path)
    for f in findings:
        print(f)
    blockers = sum(1 for f in findings if f.tier == "BLOCKER")
    suggs = sum(1 for f in findings if f.tier == "SUGGESTION")
    nits = sum(1 for f in findings if f.tier == "NIT")
    if not args.quiet:
        print("audit_llm_sinks: %d blocker(s), %d suggestion(s), %d nit(s) "
              "-- %s" % (blockers, suggs, nits,
                         "FAIL" if blockers else "PASS"))
    return 1 if blockers else 0


if __name__ == "__main__":
    sys.exit(main())
