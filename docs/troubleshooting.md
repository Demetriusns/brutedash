# Troubleshooting

Every error hit during real deployments, with the fix that worked.
If you hit something new, add it here.

## bettercap: "not recognized as the name of a cmdlet"

The exe path in your command doesn't match where bettercap actually lives.
Find it first, then use the real path:

```powershell
where.exe bettercap
# or
Get-ChildItem C:\Tools -Recurse -Filter "*bettercap*" | Select-Object FullName
```

## Dashboard still shows the old page after `git pull` + restart

The browser is showing a cached copy. The dashboard now sends
`Cache-Control: no-store` on every HTML page, so this should stop
happening — but if you see it: hard-refresh (`Ctrl+Shift+R`), or open the
dashboard in a private window (you'll need to log in again).

To prove which code the server is running, open `/api/stats` in the
browser and look for the newest field the latest commit added
(e.g. `"whole_network": true`). If the field is there, the server is new
and the problem is 100% browser cache.

## A dashboard section is stuck on "Loading..."

The page now surfaces refresh failures as a red banner instead of hanging
silently. Common causes:

- **"Your devices" never loads:** `/api/devices` was returning HTTP 500
  (`KeyError: 'on_probation'`) because the endpoint expected probation
  fields the device store never provided. Fixed — new devices now get a
  real 24-hour probation watch computed from first-seen time.
- **Everything loads but shows nothing:** check `/api/health` — if
  `"stale": true`, the capture thread isn't recording. The monitor process
  may have died; restart the scheduled task.

## `setx /M` didn't take effect

- `setx /M` requires an **elevated** PowerShell, or it fails silently-ish
  with an access-denied error.
- Machine-level variables are only picked up by **new** processes. After
  setting one, you must stop and start the scheduled task:
  `Stop-ScheduledTask` then `Start-ScheduledTask`
  (`Restart-ScheduledTask` doesn't exist on all systems).
- Verify: `[Environment]::GetEnvironmentVariable("VAR","Machine")`

## `git pull` says "already up to date" but nothing changed

Confirm the checkout really has the commit:
`git log --oneline -1`. Then confirm the *running* process picked it up:
check `/api/stats` for the newest field, or check the Python process start
time (`Get-Process python | Select StartTime`) — if it predates your
restart, the old process is still holding the port and the new one died on
a bind conflict.

## Task Scheduler result codes

- `267009` — **not an error.** It means the task is currently running.
- `2147942402` — the action's executable path is wrong. The SYSTEM account
  can't resolve the per-user `py` launcher; point the action at the full
  `python.exe` path instead.
- Exit code `1` right after install — usually a missing dependency
  (Flask, scapy, openai). Install `requirements.txt` with the **same**
  Python executable the task uses, then restart the task.

## AI verdict / summary does nothing

- AI verdict needs the `openai` package installed for the task's Python
  (it was once commented out of `requirements.txt` — check yours).
- Pressing **Explain now** now reports where the summary came from
  (`(llm)` vs `(rule-based)`) or shows the actual error instead of failing
  silently.

## Stopping an ARP-spoof relay safely

Type `quit` **inside** the bettercap window. That sends corrective ARP
packets and every device gets its real gateway back immediately. Closing
the window or killing the process leaves poisoned ARP entries behind and
the LAN loses internet until they time out (several minutes).

## Relay running but other devices never appear

- Keep the relaying PC **awake**. Sleep, reboot, or a bettercap crash ends
  the relay — and until ARP state recovers, the LAN has no internet.
- Devices behind a downstream router in NAT mode (e.g. a mesh node doing
  its own routing) appear collectively as that router's IP. That's
  expected; put the downstream unit in AP/bridge mode to see them
  individually.
- bettercap may default to a dead adapter (self-assigned 169.254.x.x).
  List adapters with `Get-NetAdapter`, take the right InterfaceGuid, and
  launch with `-iface "\Device\NPF_{GUID}"`.

## Noisy alerts

- Windows NetBIOS ports 137–139 to LAN destinations are treated as normal
  chatter; the same ports leaving the LAN are still flagged.
- Repeat alerts are grouped into one card with a ×N count; use
  Ack/Dismiss on the group.
