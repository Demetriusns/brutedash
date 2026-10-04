#!/usr/bin/env bash
# scripts/release-gate.sh -- the brutedash release gate.
#
# One entry point that enforces quality before anything ships. Runs, in order:
#   (a) full unittest suite (venv python AND plain python3)
#   (b) py_compile on every changed .py file (staged + unstaged + untracked)
#   (c) gitleaks secret scan            (repo-learning item 9 -- BLOCKING)
#   (d) semgrep detection-audit rules    (repo-learning item 10 -- if installed)
#   (e) LLM prompt-injection sink audit  (repo-learning item 2 -- BLOCKING)
#
# Exit 0 + "RELEASE GATE: PASS" only when every blocking step passes.
# Any blocker => "RELEASE GATE: FAIL", exit 1. Fail closed throughout: a
# step that cannot run its check (missing binary, unreadable diff, git
# failure) FAILS LOUDLY instead of silently passing.
#
# Diff source: $RELEASE_GATE_DIFF (a pre-generated unified diff file -- set
# by the pre-push hook, which gates the pushed commits) wins; otherwise the
# gate builds the diff from staged + unstaged + untracked changes, and
# gitleaks falls back to a full working-tree scan.
#
# Manual invocation:  ./scripts/release-gate.sh        (from the repo root)
# Installed as the git pre-push hook by scripts/install-hooks.sh.
#
# Target: comfortably under 2 minutes (the suite is ~4s, gitleaks ~1s).
set -u

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "release-gate: FAIL: not inside a git repo" >&2; exit 1; }
cd "$ROOT" || exit 1

FAILS=0
step_start=0
step_begin() { step_start=$SECONDS; printf '%-58s' "--- $1 ..."; }
step_end() { # $1 = PASS|FAIL|SKIP, $2 = optional note
    local dur=$((SECONDS - step_start)) note="${2:-}"
    printf '%s (%ss)%s\n' "$1" "$dur" "${note:+ -- $note}"
    [ "$1" = "FAIL" ] && FAILS=$((FAILS + 1))
    return 0
}

# --- pick pythons ---------------------------------------------------------
PY_VENV="$ROOT/venv/bin/python"
PY_SYS="python3"
HAVE_VENV=0
[ -x "$PY_VENV" ] && HAVE_VENV=1

# --- (a) full unittest suite ----------------------------------------------
step_begin "(a) unittest suite (venv python)"
if [ "$HAVE_VENV" = 1 ]; then
    if out="$("$PY_VENV" -m unittest discover -s tests 2>&1)"; then
        step_end PASS "$(echo "$out" | grep -E '^(OK|FAILED)' | tail -1)"
    else
        echo; echo "$out" | tail -15
        step_end FAIL "venv suite failed"
    fi
else
    step_end SKIP "no venv/bin/python"
fi

step_begin "(a) unittest suite (plain python3)"
if out="$("$PY_SYS" -m unittest discover -s tests 2>&1)"; then
    step_end PASS "$(echo "$out" | grep -E '^(OK|FAILED)' | tail -1)"
else
    echo; echo "$out" | tail -15
    step_end FAIL "system-python suite failed"
fi

# --- changed .py files (staged + unstaged + untracked) --------------------
CHANGED="$( { git diff --cached --name-only -z; \
              git diff --name-only -z; \
              git ls-files --others --exclude-standard -z -- '*.py'; } \
            2>/dev/null | tr '\0' '\n' | grep '\.py$' | sort -u )"
PY_FILES=""
SKIPPED_BIG=""
for f in $CHANGED; do
    [ -f "$ROOT/$f" ] || continue
    # size guard: never let a huge generated file stall the gate
    if [ "$(wc -c < "$ROOT/$f")" -gt 2097152 ]; then
        SKIPPED_BIG="$SKIPPED_BIG $f"
    else
        PY_FILES="$PY_FILES $f"
    fi
done
[ -n "$SKIPPED_BIG" ] && \
    echo "note: py_compile skipped >2MB files:$SKIPPED_BIG" >&2

# --- (b) py_compile on changed files --------------------------------------
step_begin "(b) py_compile changed files"
if [ -z "$PY_FILES" ]; then
    step_end SKIP "no changed .py files"
elif "$PY_SYS" -m py_compile $PY_FILES 2>/tmp/gate_pycompile.err; then
    step_end PASS "$(echo "$PY_FILES" | wc -w) files"
else
    echo; cat /tmp/gate_pycompile.err
    step_end FAIL "compile errors"
fi
rm -f /tmp/gate_pycompile.err

# --- locate gitleaks (fail closed if missing) ------------------------------
GITLEAKS=""
for cand in "$(command -v gitleaks 2>/dev/null)" \
            "$HOME/workspace/bin/gitleaks" "$HOME/bin/gitleaks"; do
    if [ -n "$cand" ] && [ -x "$cand" ]; then GITLEAKS="$cand"; break; fi
done

# --- diff file for the diff-based checks ----------------------------------
DIFF_FILE=""
if [ -n "${RELEASE_GATE_DIFF:-}" ]; then
    if [ -f "$RELEASE_GATE_DIFF" ]; then
        DIFF_FILE="$RELEASE_GATE_DIFF"
    else
        echo "release-gate: FAIL: RELEASE_GATE_DIFF points at a missing file" >&2
        exit 1
    fi
else
    DIFF_FILE="$(mktemp)"
    trap 'rm -f "$DIFF_FILE"' EXIT
    git diff --cached --no-ext-diff --no-color >> "$DIFF_FILE" 2>/dev/null
    git diff --no-ext-diff --no-color >> "$DIFF_FILE" 2>/dev/null
    while IFS= read -r -d '' f; do
        git diff --no-index --no-ext-diff --no-color -- /dev/null "$f" \
            >> "$DIFF_FILE" 2>/dev/null
    done < <(git ls-files --others --exclude-standard -z -- '*.py' 2>/dev/null)
fi

# --- (c) gitleaks ------------------------------------------------------------
# Explicit --config so the repo's allowlist applies no matter the cwd.
GL_CFG=()
[ -f "$ROOT/.gitleaks.toml" ] && GL_CFG=(--config "$ROOT/.gitleaks.toml")
step_begin "(c) gitleaks secret scan"
if [ -z "$GITLEAKS" ]; then
    echo
    echo "release-gate: FAIL: gitleaks binary not found."
    echo "  Why this blocks: a silently-skipped secret scan defeats the"
    echo "  whole point of the gate. Install it, then re-run:"
    echo "    - this machine: binary lives at ~/workspace/bin/gitleaks"
    echo "    - elsewhere: https://github.com/gitleaks/gitleaks/releases"
    echo "      (or: go install github.com/gitleaks/gitleaks/v8@latest)"
    echo "      then ensure 'gitleaks' is on PATH."
    step_end FAIL "binary missing (fail closed)"
elif [ -n "${RELEASE_GATE_DIFF:-}" ] && [ -s "$DIFF_FILE" ]; then
    if "$GITLEAKS" detect --pipe "${GL_CFG[@]}" --redact --no-color < "$DIFF_FILE" \
            >/tmp/gate_gitleaks.log 2>&1; then
        step_end PASS "push diff clean"
    else
        echo; tail -20 /tmp/gate_gitleaks.log
        step_end FAIL "secrets detected in the pushed diff"
    fi
else
    if "$GITLEAKS" detect --no-git "${GL_CFG[@]}" --source "$ROOT" --redact --no-color \
            >/tmp/gate_gitleaks.log 2>&1; then
        step_end PASS "working tree clean"
    else
        echo; tail -20 /tmp/gate_gitleaks.log
        step_end FAIL "secrets detected"
    fi
fi
rm -f /tmp/gate_gitleaks.log

# --- (d) semgrep (only if installed) -----------------------------------------
step_begin "(d) semgrep detection-audit rules"
if command -v semgrep >/dev/null 2>&1 && [ -f "$ROOT/.semgrep/detection-audit.yml" ]; then
    if semgrep --config "$ROOT/.semgrep/detection-audit.yml" \
               --error --quiet --exclude='venv' "$ROOT" 2>/tmp/gate_semgrep.err; then
        step_end PASS "no ERROR findings"
    else
        echo; tail -25 /tmp/gate_semgrep.err
        step_end FAIL "semgrep findings"
    fi
else
    step_end SKIP "semgrep not installed -- scripts/audit_llm_sinks.py covers local enforcement; rules ship in .semgrep/ for CI"
fi
rm -f /tmp/gate_semgrep.err

# --- (e) LLM prompt-injection sink audit -------------------------------------
step_begin "(e) LLM sink audit (audit_llm_sinks.py)"
audit_out="$("$PY_SYS" "$ROOT/scripts/audit_llm_sinks.py" \
    --diff-file "$DIFF_FILE" 2>&1)"
rc=$?
echo "$audit_out"
if [ "$rc" = 0 ]; then
    step_end PASS "$(echo "$audit_out" | tail -1 | tr -d '\n')"
elif [ "$rc" = "2" ]; then
    step_end FAIL "audit tool error (fail closed)"
else
    step_end FAIL "blocker findings above"
fi

# --- verdict -----------------------------------------------------------------
echo
if [ "$FAILS" = 0 ]; then
    echo "RELEASE GATE: PASS"
    exit 0
else
    echo "RELEASE GATE: FAIL ($FAILS blocking step(s) failed)"
    exit 1
fi
