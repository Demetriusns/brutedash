# Robustness verdict 2026-11-22 (seat summary, full text in run log)

HEAD 37f9339. NEEDS WORK. No Critical. 2 High, 4 Medium, 5 Low. All High/Medium reproduced except M4 (source-verified). Prior cycle items N1/N2/R9/R10/L3 verified FIXED.
- High H1: detect_cadence username-enumeration O(n^2) — 20k failures/one IP took 11.75s; ~2-3 min at the 10MB app.py cap. Fix: sliding window with incremental counts.
- High H2: _collect_events reads oldest-first; 64MB cap can starve the primary (freshest) log — reproduced 61 sibling events, 0 primary, burst missed. Fix: read primary first into separate list, siblings under remaining cap, concatenate.
- Medium M1: type-wrong key-state JSON crashes detect_key_events (only syntax corruption handled). Fix: validate on load + safe sort in save.
- Medium M2: empty/skipped sibling counts as "history", defeating baseline — reproduced first-seen storm with a 0-byte auth.log.1. Fix: history = sibling actually contributed a fingerprinted key event, or non-empty state.
- Medium M3: llm_egress baseline is a single sighting aged 7 days, exemption permanent.
- Medium M4: _save_key_state fixed tmp path, no lock — concurrent threaded scans race/tear/lose updates. Fix: lock + unique tmp name.
- Low L1 syslog timestamps not range-validated; L2 same-ts ceiling escape; L3 scanner single-line materialisation; L4 llm_egress correlation scope/time; L5 triple log re-read per POST.
- Seat recommended batch: H1+H2, then M1+M2.
