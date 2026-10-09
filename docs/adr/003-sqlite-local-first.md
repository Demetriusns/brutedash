# ADR 003 — SQLite, local-first storage

Date: 2026-10-02
Status: Accepted

## Context
brutedash stores alerts, incidents, audit log, and learned baselines. Options were
SQLite (file), Postgres (server), or a cloud DB.

## Decision
SQLite, local-first. One file (`netmon/netmon.db`, git-ignored), no server to install,
no credentials to manage, survives reboots. The sensor box owns its data; nothing
leaves it unless the owner exports it.

## Consequences
- Single-writer design: the pipeline owns writes; the dashboard reads.
- Backup = copy the file. Retention policy in `netmon/retention.py` keeps it bounded.
- If a multi-sensor product line ever emerges, revisit (likely Postgres or SQLite
  per sensor with manager sync — see Wazuh agent→manager pattern in findings).
