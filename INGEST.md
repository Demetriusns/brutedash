# Windows log ingestion — INGEST.md

brutedash watches the network. This page covers the other half: reading
your Windows PC's own logs so host events (failed logins, new services,
USB drives, Defender detections) can be correlated with what the network
saw. Point brutedash at a folder of **exported** logs and it reads them
every few minutes.

What this is NOT: brutedash never replaces your antivirus. It does not
scan files, quarantine anything, or kill processes — Windows Defender
(and tools like CrowdStrike) own real-time file/process prevention.
brutedash detects, correlates, and proposes.

---

## Setup (one time)

1. Create a folder for the exported logs, e.g.
   `C:\Users\dmanc\brutedash-logs` (any folder works).
2. Tell brutedash about it in `~/.config/brutedash/config.yaml`:

   ```yaml
   ingest:
     watch_dir: "C:/Users/dmanc/brutedash-logs"
   ```

   (Or set the `BRUTEDASH_INGEST_WATCH_DIR` environment variable.)
   Restart brutedash. The dashboard's Settings → **Windows logs** panel
   shows whether the folder is being watched.
3. Drop exported logs into the folder (steps below). New files and
   updated files are picked up automatically; firewall logs are read
   incrementally, XML exports are re-read when they change.

No folder configured = ingestion quietly disabled. Nothing breaks; the
panel just says it's not configured.

## Exporting Windows Firewall logs

Windows Firewall can log every dropped packet to `pfirewall.log`:

1. Press Win+R, type `wf.msc`, Enter (Windows Defender Firewall with
   Advanced Security).
2. Right-click **Windows Defender Firewall with Advanced Security** →
   **Properties**.
3. On each profile tab (Domain / Private / Public), under **Logging**:
   - Log dropped packets: **Yes**
   - Log successful connections: **No** (too noisy)
   - Name: note the path, default is
     `%systemroot%\system32\logfiles\firewall\pfirewall.log`
4. Copy `pfirewall.log` into your watch folder (or point the logging
   path at the watch folder directly). brutedash reads new lines as the
   file grows; only **DROP** events are stored (ALLOW rows are counted,
   not kept — they're too noisy).

## Exporting Event Viewer logs (Security, System, Defender)

1. Press Win+R, type `eventvwr.msc`, Enter.
2. In the left tree:
   - **Windows Logs → Security** — failed logons (4625), new external
     devices (6416), new services (7045 lives in System, actually — see
     below).
   - **Windows Logs → System** — new service installed (7045), device
     install events.
   - **Applications and Services Logs → Microsoft → Windows →
     Windows Defender → Operational** — Defender detections (1116),
     actions taken/quarantines (1117), configuration changes (5007,
     including real-time protection being turned off).
   - **Applications and Services Logs → Microsoft → Windows →
     DriverFrameworks-UserMode → Operational** — USB device arrival
     (2003/2102).
3. Right-click the log → **Save All Events As…** → choose **XML**,
   save it into your watch folder (e.g. `security.xml`).
4. Re-export whenever you want fresh data (weekly is fine, or after
   something suspicious). If the file's modification time changed,
   brutedash re-reads it and imports only events newer than the last
   import — re-exporting the same log twice is harmless.

USB note: the high-signal USB event is Security **6416** ("a new
external device was recognized"), which needs device-installation
auditing enabled. The DriverFrameworks 2003/2102 events work without
extra configuration and are the easier path.

## What brutedash does with the events

| Event | Rule | Alert |
|---|---|---|
| 4625 failed logon | 5+ from one IP in 10 min | Medium "Repeated failed logins" |
| 4625 (any) | source IP also seen in port_scan/beaconing alerts in the last 24h | linked to that network alert |
| 7045 new service | first time this service name seen | Low "New Windows service installed" |
| 6416 / 2003 / 2102 USB insert | first time this device ID seen, and it looks like mass storage | Medium "Unknown USB device plugged in" |
| Defender 1116/1117 | threat detected / action taken | Medium/High "Defender caught something" |
| Defender 1116/1117 **+** C2-style traffic from the same host in 24h | correlated | **Critical** "Host under attack" (one incident) |
| Defender 5007 | real-time protection turned off | High |

Repeat sightings stay quiet: a USB drive you own alerts once, then it's
known. A weekly re-export with nothing new produces zero alerts.

## Troubleshooting

- **Panel says "Not configured"** — `ingest.watch_dir` is empty or the
  folder doesn't exist. Check the path in config.yaml and restart.
- **Events not appearing** — the XML must be a real Event Viewer XML
  export (right-click → Save All Events As → XML), not `.evtx`.
  brutedash cannot read `.evtx` directly; export to XML first.
- **pfirewall.log is empty** — logging is off by default; follow the
  firewall steps above and generate some traffic (or wait for the next
  blocked inbound probe).
- **Duplicate alerts after re-export** — shouldn't happen: XML imports
  are incremental by event timestamp, and every rule has a cooldown.
  If it does, file a bug report (see TROUBLESHOOTING.md).
- **Nothing about USB** — 6416 needs extra auditing; use the
  DriverFrameworks-UserMode Operational log instead (2003/2102).

## Privacy

These logs stay on your machine, in your SQLite database, like
everything else brutedash records. Nothing is uploaded anywhere.
