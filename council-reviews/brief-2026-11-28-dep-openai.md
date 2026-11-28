# Council review brief — 2026-11-28 — Dependency bump openai 3.58.0 → 3.60.0

For: council seats (research, repair, innovation; security seat vacant).
Verdict wanted: exactly one of APPLY / ADAPT / REJECT as the first word,
then reasons. Word cap: 120 words. No flattery, no hedging.

## Verified facts (head-checked against source at HEAD 67ce125)

- PyPI live check 2026-11-28 (`pip index versions`): openai latest is
  3.60.0; pin is 3.58.0. Every other pin is already at its latest:
  Flask 3.1.3, Werkzeug 3.1.9, scapy 2.8.0, PyYAML 6.0.4. gunicorn
  latest is 27.0.1 — a major (23 → 27), stays Tier 2 proposal-only,
  not in this batch.
- Changelog review against the official 3.60.0 sdist CHANGELOG.md
  (openai/openai-python, read 2026-11-28): 3.59.0 (2026-11-24) one
  feature (healthcare model IDs for Responses) + bug fixes, including
  redacting credential headers on API error requests; 3.60.0
  (2026-11-26) two features (spend alerts and response compaction
  fields; updating session vaults) + chores/docs only. No BREAKING
  CHANGES section in either release.
- brutedash usage surface (grep-verified today): OpenAI(key=...,
  timeout=30)` + `client.chat.completions.create(...)` in
  netmon/ai_assist.py, netmon/explainer.py; optional dependency with
  rule-based fallback. Nothing in 3.59.0/3.60.0 touches
  chat-completions handling.

## Proposal

One-line change: `requirements.txt` pin `openai==3.58.0` →
`openai==3.60.0`; install the new pin in the repo venv and
import-verify (`openai.__version__` = 3.60.0). Standing process runs
the full test suite with the new version installed BEFORE commit.

## Question

APPLY this bump as written, ADAPT (say how), or REJECT?
