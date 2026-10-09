# Security Policy

## Reporting a vulnerability

brutedash is a defensive security tool built by an independent developer. If you find
a security issue, **do not open a public issue**. Instead:

- Email the maintainer via the address on the GitHub profile
  ([Demetriusns](https://github.com/Demetriusns)), with "SECURITY" in the subject.
- Include: what you found, where (file + line), and how to reproduce it.
- Allow reasonable time for a fix before any public disclosure.

## Scope

In scope: the detection pipeline, dashboard, quarantine mechanism, tool registry
(`netmon/tools.py`), and the release gate (`scripts/release-gate.sh`).

Out of scope: the intentionally-vulnerable fixture files under `tests/rules/`
(they exist to prove the self-scanner catches bad patterns — see
`scripts/audit_llm_sinks.py` and the `FIXTURE_TREE_PREFIXES` exclusion).

## Automated checks

Every push runs the release gate (`scripts/release-gate.sh`): full test suite,
LLM prompt-injection sink audit, and secret scan. The self-scanner
(`netmon/selfscan.py`) enforces project-specific static-analysis rules with a
golden-file test harness under `tests/rules/`.
