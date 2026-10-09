# ADR 001 — Approval-only quarantine

Date: 2026-09-30
Status: Accepted

## Context
brutedash can isolate a device from the LAN by ARP-spoofing (see `netmon/quarantine.py`).
An automated response that cuts a device's internet on its own could take a small business
offline by mistake — a false positive becomes an outage.

## Decision
Nothing in this repo may ever quarantine a device on its own. A human clicks "Isolate"
on the dashboard; that is the ONLY code path that calls `request_quarantine()`.
Enforced in code (`safety_check`) and in tests (`tests/test_response.py` inspects the
source tree — add another caller and the suite goes red).

## Consequences
- A missed attack is possible if nobody is watching the dashboard; accepted trade-off.
- The product stays trustworthy for non-technical owners: the tool never acts alone.
- Related: ADR 002 (the relay mechanism this builds on).
