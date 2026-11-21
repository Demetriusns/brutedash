# Council review — brutedash daily build 2026-11-21, dependency batch (Tier 1)

You are a judge seat for the brutedash daily build (Warden phase 4).
Deliver an exact verdict: APPLY, ADAPT (name the concrete change), or
REJECT (name the concrete breaking change or risk). One verdict for the
WHOLE batch. No flattery, no hedging. Word cap: 120 words.

## Objective
Apply dependency step (3) of the daily pick order: PyYAML patch bump.
No other changes.

## Proposed change (Tier 1: dependency patch bump)

`requirements.txt`: `PyYAML==6.0.3` -> `PyYAML==6.0.4`. No code changes.

## Verified facts (head-checked today, 2026-11-21, at HEAD 58331fc)

1. Live PyPI check today: PyYAML latest is 6.0.4, pinned 6.0.3.
   All other pins are already latest: Flask 3.1.3, Werkzeug 3.1.9,
   scapy 2.8.0, openai 3.57.0. gunicorn 23.0.0 -> 27.0.1 is a major
   and stays a staged Tier 2 proposal — NOT in this batch.
2. Changelog read by the head today from the official GitHub release
   yaml/pyyaml 6.0.4 (published 2026-11-20):
   - Added support for Python 3.15.
   - Dropped support for EoL Python 3.8, 3.9.
   - Fixed exponential merge key expansion (#937).
   - Exposed libyaml 0.2.6 recursion control API (#1010) - no-op when missing.
   - Bumped wheel builds to libyaml 0.2.6.
   No BREAKING CHANGES for supported Pythons.
3. brutedash runtime is Python 3.12.3 (venv and system, verified today),
   so dropping 3.8/3.9 does not affect it.
4. brutedash's entire PyYAML surface (grep-verified today):
   `yaml.safe_load(...)` only, in netmon/config.py (config.yaml parsing),
   netmon/selfscan.py and netmon/templates.py (rule/template loading).
   No UnsafeLoader, no yaml.load without Loader, no merge-key-heavy
   custom usage that changes API.
5. The 3 open Warden findings are tier-0 environmental probes from
   2026-10-04 (service inactive / dashboard unreachable / heartbeat
   down on this dev VM); no code fix. Staged proposals are Tier 2 only
   (gunicorn major, ipintel HTTPS) — untouched.
6. Standing process: full unit suite (1,088 tests at HEAD) must pass
   with the new version installed in the venv before commit;
   dashboard smoke boot + release gate also required; one focused
   batch per run. Prior identical dep bumps shipped under this same
   process with council APPLY quorum and green suite.

## Files that would be touched
requirements.txt only (plus DEVLOG/ledger bookkeeping after push).

## Test plan
Install 6.0.4 in venv, import-verify version and safe_load, full
unittest suite green, dashboard smoke boot /api/stats 200,
staged-diff scan clean, release gate PASS.

## Question

APPLY the PyYAML 6.0.3 -> 6.0.4 pin bump as today's Tier 1 batch,
ADAPT it, or REJECT it?
