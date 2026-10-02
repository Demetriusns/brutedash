# Installing Project Orion

Works on **Windows 10/11, macOS, and Linux**. You need Python 3.10 or newer —
the installer checks and tells you if yours is too old.

## 1. Get the code

```bash
git clone https://github.com/Demetriusns/brutedash.git
cd brutedash
```

No git? Download the ZIP from
[github.com/Demetriusns/brutedash](https://github.com/Demetriusns/brutedash)
and unzip it instead.

## 2. Install Python (if you don't have it)

| OS | How |
|---|---|
| Windows | [python.org/downloads](https://www.python.org/downloads/) — during setup, check **"Add python.exe to PATH"** |
| macOS | [python.org/downloads](https://www.python.org/downloads/) or `brew install python3` |
| Linux | `sudo apt install python3 python3-venv python3-pip` (Debian/Ubuntu) or `sudo dnf install python3` (Fedora) |

Check yours: `python --version` (Windows) or `python3 --version` (Mac/Linux).

## 3. Run the installer

```bash
python install.py      # Windows  (or: py install.py)
python3 install.py     # macOS / Linux
```

It creates an isolated environment, installs everything, and writes your
settings file. Safe to re-run any time — it never overwrites your settings.

It also checks the *optional* extras and tells you what's missing:

- **Live traffic capture** needs a packet-capture driver:
  - Windows → [Npcap](https://npcap.com/) (free)
  - Linux → `sudo apt install libpcap0.8` (or `sudo dnf install libpcap`)
  - macOS → already built in
- **Whole-network mode** (see every device, not just this PC) needs
  [bettercap](https://www.bettercap.org/). Skip it unless you want that.

## 4. Run it

Dashboard only — no admin rights needed, works everywhere:

```bash
venv\Scripts\python -m netmon.run --dashboard-only     # Windows
venv/bin/python -m netmon.run --dashboard-only         # macOS / Linux
```

Then open **http://127.0.0.1:5001** in your browser.

Full live monitoring — needs admin/root for packet capture:

```bash
# Windows: open PowerShell AS ADMINISTRATOR first
venv\Scripts\python -m netmon.run
# macOS / Linux:
sudo venv/bin/python -m netmon.run
```

## 5. Make it yours (optional)

- **AI summaries:** set `OPENAI_API_KEY` as an environment variable.
  Without it, Orion writes rule-based summaries instead — still readable.
- **Dashboard password:** set `NETMON_PASSWORD` as an environment variable.
- **Everything else** lives in one settings file the installer created:
  - Windows → `%APPDATA%\brutedash\config.yaml`
  - macOS/Linux → `~/.config/brutedash/config.yaml`

## Whole-network mode (optional, advanced)

This makes your PC relay the LAN so Orion sees *every* device. Only do
this on a network you own.

```bash
python -m netmon.relay --write     # generates YOUR machine's caplet
```

It prints the exact command to run (as Administrator/root). Type `quit`
in the bettercap console to stop — it restores the network on exit.
Your PC becomes the LAN relay while it runs: if the PC sleeps or
reboots, other devices briefly lose internet.

## Troubleshooting

- `Python 3.10+ required` → install a newer Python (step 2).
- `requirements.txt not found` → run `install.py` from the `brutedash`
  folder you cloned.
- Dashboard won't open → something else may own port 5001; run with
  `--port 8080` instead.
- No live traffic on Windows → install Npcap (step 3) and run PowerShell
  as Administrator.
- Still stuck → see `docs/troubleshooting.md`.
