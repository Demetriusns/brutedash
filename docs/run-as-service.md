# Running netmon as an always-on service

Right now netmon runs when you start it by hand and stops when you close
the terminal. This page explains how to make it start by itself when the
computer turns on and keep running in the background — on Windows (Task
Scheduler) and on Linux (systemd).

Once it's set up, the dashboard is just always there at
`http://127.0.0.1:8080`, and the monitor keeps watching without you
thinking about it.

> The examples below use port **8080** because port 5001 is the default
> (`python -m netmon.run` uses 5001) — if something else already sits on
> 8080 on your machine, pick any free port and use it consistently.

## Windows — Task Scheduler

1. Open **Task Scheduler** (press the Windows key, type "Task Scheduler",
   open it).
2. In the right-hand pane click **Create Task** (not "Create Basic Task" —
   we need the extra settings).
3. On the **General** tab:
   - Name it `netmon`.
   - Tick **"Run whether user is logged on or not"** — this is what lets it
     run in the background without a visible window.
   - Tick **"Run with highest privileges"** — live capture needs raw
     network access, which is an administrator-level ability.
4. On the **Triggers** tab, click **New**:
   - "Begin the task" → **At startup**. This starts the monitor every time
     Windows boots, before you even log in.
5. On the **Actions** tab, click **New**:
   - Action: **Start a program**.
   - "Program/script": `py` (the Python launcher; on some machines this
     is `python` or the full path to `python.exe` — use whichever works
     when you type it in a terminal).
   - "Add arguments": `-m netmon.run --port 8080`
   - **"Start in"**: the full path to your project folder, e.g.
     `C:\Users\dmanc\projects\brutedash` — this is important: Python needs
     to run *from* the folder that contains the `netmon` package and the
     database file, otherwise it won't find the code or will create the
     database in the wrong place.
6. On the **Conditions** tab:
   - If this is a laptop, un-tick **"Start the task only if the computer
     is on AC power"** if you want the monitor running on battery too.
   - Tick **"Wake the computer to run this task"** so the monitor can
     restart capture if the machine slept.
7. Click **OK**. Windows will ask for your user password so the task can
   run while you're logged out — that's normal.

To check it's running: open a browser and go to
`http://127.0.0.1:8080/api/health`. You should see a small block of text
starting with `"ok": true`. In Task Scheduler you can also right-click
the `netmon` task and choose **Run** to start it immediately, or check the
**History** tab if something looks wrong.

To stop the background monitor: open Task Scheduler, right-click
`netmon`, choose **End** (and **Disable** if you don't want it starting on
every boot anymore).

> Live capture needs the Npcap driver installed and administrator rights.
> If you don't want to run as admin, the dashboard-only mode still works:
> change the action arguments to `-m netmon.run --dashboard-only --port 8080`.

## Linux — systemd unit

Create the file `/etc/systemd/system/netmon.service` with these contents
(replace the paths and user with your own):

```ini
[Unit]
Description=netmon home network monitor
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
WorkingDirectory=/home/YOURNAME/brutedash
ExecStart=/usr/bin/python3 -m netmon.run --port 8080
Restart=always
RestartSec=10
# Environment variables for email alerts / password / AI features:
# Environment="NETMON_SMTP_HOST=smtp.example.com"
# Environment="NETMON_ALERT_TO=you@example.com"
# Environment="NETMON_PASSWORD=your-dashboard-password"

[Install]
WantedBy=multi-user.target
```

Notes:

- `WorkingDirectory` must be the folder containing the `netmon` package
  and `netmon.db` — the monitor stores its database next to the code.
- `User=root` because live capture needs raw sockets. If you only want the
  dashboard, drop the capture need: change `ExecStart` to
  `/usr/bin/python3 -m netmon.run --dashboard-only --port 8080` and set
  `User=` to a normal user.
- `Restart=always` means systemd brings it back if it crashes.

Install and start it:

```bash
sudo cp netmon.service /etc/systemd/system/netmon.service
sudo systemctl daemon-reload
sudo systemctl enable --now netmon
```

Check it's alive:

```bash
sudo systemctl status netmon
curl http://127.0.0.1:8080/api/health
```

To stop: `sudo systemctl disable --now netmon`.

## The /api/health endpoint

Both setups above expose a tiny health-check page at:

```
http://127.0.0.1:8080/api/health
```

It answers with JSON like this:

```json
{
  "ok": true,
  "now": "2026-09-30 18:05:12",
  "last_flow_ts": "2026-09-30 18:04:58",
  "stale": false
}
```

What each field means:

- **ok** — the web part of the monitor is up.
- **now** — the current time on the machine running netmon.
- **last_flow_ts** — when network traffic was last seen. The capture
  thread writes this "heartbeat" every time it flushes packets.
- **stale** — `true` when no traffic has been seen for more than
  **5 minutes**. That usually means the capture thread stopped (a crash,
  the machine went to sleep, or the interface changed) even though the
  web dashboard is still up.

### The stale-data banner

When the dashboard itself notices the data is stale (same 5-minute rule),
it shows a red banner at the top of the page:

> No fresh data — the monitor may have stopped. Check that netmon is still
> running.

That banner does **not** mean your internet is down — it means the
*monitor* hasn't recorded traffic in a while. Things to check, in order:

1. Is the machine running netmon awake and on the network?
2. Is the service/task still running (Task Scheduler status, or
   `systemctl status netmon`)?
3. If you restarted it recently, give it a minute — capture needs a few
   seconds to warm up, and an idle machine with nothing open produces very
   little traffic.
4. If the banner stays up for 10+ minutes on an active machine, restart
   the service/task and check the logs (Task Scheduler **History** tab, or
   `journalctl -u netmon`).

## Older databases upgrade themselves

If you've been running netmon for a while, your `netmon.db` file just
gets upgraded in place — new tables (`dns_queries`, `arp_observations`,
`first_seen`, `meta`) are created automatically, and new columns (the
plain-English alert fields, the alert triage `status`/`note`) are added to
the old `alerts` table on startup. Nothing is deleted, and you don't need
to do anything. The `first_seen` history starts building from the first
run after the upgrade, so new baselining alerts become accurate over the
first day or so.
