# Troubleshooting — brutedash / netmon

If something breaks, fill out the form below and send it to Orion. The more
of it you fill in, the faster the fix. Raw command output pasted verbatim
is the single most useful thing — don't summarize it, paste it.

---

## Bug report form (copy, fill, send)

```
### What broke (one line)

### What were you doing when it broke

### Command you ran (exact)

### Full output (paste everything, don't trim)

### What you expected to happen

### Environment
- Machine: (home PC / other)
- OS: (Windows 11 / Linux)
- Python version: (python --version)
- How you launched it: (python -m netmon.run / dashboard-only / --pcap ...)
- Whole-network mode on? (yes / no)
- NETMON_PASSWORD set? (yes / no — never paste the password itself)

### When did it last work
- (e.g. "yesterday after the pull" / "never worked" / "broke right after I changed X")

### Anything you already tried
```

---

## Quick checks before filing

1. **Dashboard shows "No fresh data" / STALE** — the monitor probably
   stopped. Check the terminal where you launched it; if it's closed,
   restart with `python -m netmon.run`. On the home PC, sleep kills
   capture — that's also what silences the heartbeat.
2. **Heartbeat down (the nurse alerted)** — PC asleep, offline, netmon
   crashed, or the heartbeat URL got removed from config. Wake the PC
   and check the terminal first.
3. **Login page loops / can't sign in** — you're hitting the dashboard
   without `NETMON_PASSWORD` set in that terminal's environment.
   Set it, restart the dashboard.
4. **Whole-network mode: LAN loses internet** — the PC must stay awake;
   if the PC sleeps while ARP-spoofing, the relay dies with it. Kill
   the spoof (`arp.spoof off` in bettercap) to restore the LAN fast.
5. **Orbi-subnet devices show as one IP** — expected until the Orbi goes
   into AP mode. Not a bug.
6. **Permission errors on capture** — live sniffing needs root/admin.
   `sudo python -m netmon.run` on Linux; admin terminal on Windows.

---

## Where logs live

- Terminal output of the launch window (first place to look).
- Crash bundles and persistent logs: see `netmon/health.py`
  (`healthm.setup_logging()` — the nurse's toolkit).
- Config: `~/.config/brutedash/config.yaml`.
