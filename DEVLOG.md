# Project Orion — dev log

## 2026-10-01
- Demetrius named the project **Project Orion**. (brutedash remains the repo/codename on GitHub.)
- **Phase 3.5 batch 2 — new-device probation (the bouncer watching the new guy).** First-seen devices are now on a 24-hour probation watch: a new `probation_watch` rule (Medium) flags any probationary device that moves >500 MB in an hour, contacts 100+ outside addresses, or uses unusual ports — quiet devices produce no alert at all. Devices page shows a 🟡 Probation badge with "trusted in Nh" countdown plus first-seen timestamps; trusted devices get ✅ Trusted. Also fixed a `NameError` in `rule_based_summary` (referenced undefined `whats_happening` instead of `happening`) found during git reconciliation.
- **Live traffic graph (his call, 2026-10-01).** Replaced the static "data packets (last min)" card with a live traffic graph: /api/stats now ships cumulative `bytes_total`/`packets_total`, the dashboard diffs them every 5s poll and plots MB per tick as an area chart (last ~6 min, peak annotated), with the current MB/tick and packets/tick readouts. Pure canvas JS, no new dependencies. Python compile + node --check clean.
