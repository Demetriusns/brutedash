# Project Orion — Product Checklist

> Orion is a network security monitor that watches the network, detects
> threats, and explains them in plain English — the analyst is built in.

## What it does (technical)

- Local packet capture + deterministic detection rules (no cloud needed).
- Plain-English alert explanations (meaning / is this normal / what to do).
- Phone-friendly dashboard.
- Quiet-first: per-device behavior baselines, probation watch, quiet hours.
- Self-diagnostics: heartbeat monitoring, crash bundles, secret-scrubbed
  diagnostics.

## Ship checklist — now (Phase 3.5)

- [ ] **False-positive tuning** — per-device baselines exist; need confidence
      scoring and auto-suppression so every alert is trustworthy.
- [ ] **First-run onboarding** — guided setup inside the dashboard: name the
      network, confirm devices, set quiet hours. Zero terminal required.
- [ ] **Self-update** — safe auto-update that can't brick a running monitor.
- [ ] **Remote access (personal)** — Tailscale private tunnel so the owner
      views the dashboard from anywhere; stepping stone to the Phase 5
      cloud console. Parked per his call 2026-10-02; mobile CSS shipped.

## Later phases (technical)

- [ ] **Polished installer** — native-feel package (exe/msi or equivalent).
- [ ] **Diagnostics upload** — one-click send from the dashboard.
- [ ] **Hardening pass** — the monitor runs with elevated network privileges;
      needs a proper security review before it touches other networks.

### Shipped
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

## Rules

- Add → Test → Release. Every change is tested locally against real endpoints
  before it ships. No exceptions.
- Never ship secrets, tokens, local usernames, or PII. Ever.
- Business-side material (vision, pricing, pitch, licensing, legal) lives
  outside this repo, personally with the owner. Never commit it here.
