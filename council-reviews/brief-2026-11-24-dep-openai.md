# Council review — brutedash daily build 2026-11-24, dep openai 3.58.0 (Tier 1)

You are a judge seat for the brutedash daily build (Warden phase 4).
Deliver an exact verdict: APPLY, ADAPT (name the concrete change), or
REJECT (name the concrete breaking change or risk). One verdict for the
WHOLE batch. No flattery, no hedging. Word cap: 120 words.

## Objective
Apply pick-order step (3): dependency patch/minor update — bump the
openai pin in requirements.txt from 3.57.0 to 3.58.0. Nothing else in
production code changes.

## Verified facts (head-checked today, 2026-11-24, at HEAD faefbd4)

1. Pick order: (1) 3 open Warden findings are tier-0 environmental
   probes from 2026-10-04; no code fix. (2) Staged proposals are Tier 2
   only (gunicorn 23->27.0.1 major, ipintel HTTPS) — untouched.
   (3) Dependencies: live PyPI check today — Flask 3.1.3, Werkzeug
   3.1.9, scapy 2.8.0, PyYAML 6.0.4 all at latest; openai latest is
   3.58.0 (pin is 3.57.0); only gunicorn has a newer (major) version,
   already staged Tier 2. So the dep step is taken, ahead of the
   staged step-(4) work (security S2 minimum warning stays queued).
2. Changelog verified from the official 3.58.0 sdist CHANGELOG.md:
   one feature (api: set and read agent session spending limits,
   #4315) and one bug fix (api: clarify when to omit completion
   choice count, #4298). No breaking changes, no deprecations.
3. brutedash uses only the OpenAI client (timeout=30) +
   chat.completions.create, behind try/except rule-based fallbacks
   (app.py brief writer, netmon AI summaries). The changed areas
   (agent session spending limits, completion-choice-count docs)
   are never used.
4. Standing gate for dep bumps (precedent 2026-10-31 through
   2026-11-21): official changelog check + full suite + dashboard
   smoke boot + staged-diff scan + release gate, all before commit.
   Suite at HEAD: 1,107 tests, green at the 2026-11-23 run.

## Files that would be touched
requirements.txt (one pin line only), plus DEVLOG/ledger bookkeeping
after push.

## Question
APPLY the openai 3.57.0 -> 3.58.0 pin bump as today's Tier 1 batch,
ADAPT it, or REJECT it?
