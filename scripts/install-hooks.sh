#!/usr/bin/env bash
# scripts/install-hooks.sh -- install the release gate as the git pre-push hook.
#
# Usage: ./scripts/install-hooks.sh        (from the repo root)
#
# Copies scripts/pre-push-hook to .git/hooks/pre-push and makes it executable.
# Hooks live in .git/ and are NOT committed -- every clone that should be
# gated needs this run once. The gate itself (scripts/release-gate.sh) IS
# committed, so manual runs work everywhere: ./scripts/release-gate.sh
set -u

ROOT="$(git rev-parse --show-toplevel 2>/dev/null)" || {
    echo "install-hooks: not inside a git repo" >&2; exit 1; }
cd "$ROOT" || exit 1

HOOK="$ROOT/.git/hooks/pre-push"
cp "$ROOT/scripts/pre-push-hook" "$HOOK" && chmod +x "$HOOK" || {
    echo "install-hooks: copy failed" >&2; exit 1; }

# sanity: the hook must be executable and the gate must exist
[ -x "$HOOK" ] || { echo "install-hooks: hook not executable" >&2; exit 1; }
[ -x "$ROOT/scripts/release-gate.sh" ] || {
    echo "install-hooks: scripts/release-gate.sh missing/not executable" >&2
    exit 1; }

echo "installed: .git/hooks/pre-push -> scripts/release-gate.sh"
echo "verify with: git push --dry-run   (runs the gate, pushes nothing)"
