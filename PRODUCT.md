# Project Orion — Product Vision

> Orion is an AI-powered network security monitor for people who can't hire a
> security analyst. It watches the network, detects threats, and explains them
> in plain English — the analyst is built in.

## Who it's for

**Phase 1 — Home users.** "See every device on your network, get told in plain
English when something's wrong." Low price, simple pitch, easy install.

**Phase 2 — Small businesses.** Shops, offices, and small-town operations that
can't afford (or find) a network/security analyst. This is the real market:
a business can't pay a $90k SOC analyst, but it can pay a monthly subscription
for software that does the watching and explains what it finds.

## What makes it different

Splunk and friends show a wall of logs that takes a trained analyst to read.
Orion tells the owner: *"Your card reader started talking to an unknown server
at 2am — here's what that means and what to do."* Detection + plain-English
triage in one box. That is the product.

## Pricing sketch (to validate later)

- Home: low monthly or one-time license, self-installed.
- Small business: ~$50–200/mo per site, depending on device count.

## Ship checklist — what it still needs before anyone pays

- [x] Secrets via environment variables (no hardcoded keys) — done
- [x] **Unified config file** — one human-readable `config.yaml`, first-run
      bootstrap, env overrides. Wired through run.py, dashboard, capture,
      explainer, ai_assist, app.py. (shipped 2026-10-02, commit 864f93d)
- [x] **Detection demo tests** — `tests/demo_detection.py` proves the rules
      flag real attack shapes on synthetic home + small-business networks
      while quiet devices stay silent. (shipped 2026-10-02)
- [x] **One-command install script** — `python install.py` (Windows: `py
      install.py`): checks Python, creates venv, installs deps, bootstraps
      config, idempotent re-runs. (shipped 2026-10-02)
- [ ] **Polished installer** — native-feel package (exe/msi or equivalent)
      for non-technical buyers. Comes after the product is sale-ready.
- [ ] **First-run onboarding** — guided setup inside the dashboard: name the
      network, confirm devices, set quiet hours. Zero terminal required.
- [ ] **False-positive tuning** — per-device baselines exist; need confidence
      scoring and auto-suppression so non-technical owners trust every alert.
- [ ] **Self-update** — safe auto-update that can't brick a running monitor.
- [ ] **Diagnostics bundle** — one-click "send diagnostics" for support.
- [ ] **Licensing** — key validation for paid tiers.
- [ ] **Hardening pass** — the monitor runs with elevated network privileges;
      needs a proper security review before it touches customer networks.

## Rules

- Add → Test → Release. Every change is tested locally against real endpoints
  before it ships. No exceptions — this will run on customer networks.
- Never ship secrets, tokens, local usernames, or PII. Ever.
