# UX verdict 2026-11-22 (seat summary, full text in run log)

HEAD 37f9339. NEEDS WORK. No Critical. 3 High.
- U9 FIXED (c6fa73c).
- High U1 STILL: "edit config.yaml" dead-ends (15 rendered strings).
- High U2 STILL: app.py demo front door technician-only.
- High U11 NEW (ARTEX): "SSH key visibility" section orders user to edit sshd_config (app.py:363 / detector.py coverage notes).
- Medium U12 NEW: results table header "Failed attempts" mislabels counts for enumeration/duplicate/first_seen_key kinds.
- Medium U3-U8 carried. Low U10 retention labels; U13 NEW ports in llm_egress detail.
- Seat recommended batch: U11+U12 (+U10).
