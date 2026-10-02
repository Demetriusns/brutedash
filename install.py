#!/usr/bin/env python3
"""Project Orion one-command installer.

Usage:
    python install.py            # full setup in this folder
    python install.py --no-venv  # use the current Python instead of a venv

What it does:
  1. Checks Python >= 3.10 and that pip is available.
  2. Creates a virtual environment (./venv) unless --no-venv.
  3. Installs requirements.txt into it.
  4. Creates the first-run config file (~/.config/brutedash/config.yaml
     on Linux/macOS, %APPDATA%\\brutedash\\config.yaml on Windows).
  5. Prints what to do next (API key, dashboard password, how to run).

Safe to re-run: existing venvs are reused, dependencies are upgraded
in place, and an existing config file is never overwritten.

After installing:
    # dashboard only (no admin rights needed)
    venv/bin/python -m netmon.run --dashboard-only      # Linux/macOS
    venv\\Scripts\\python -m netmon.run --dashboard-only  # Windows

    # full monitor (needs admin/root for packet capture)
    sudo venv/bin/python -m netmon.run                  # Linux/macOS
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MIN_PYTHON = (3, 10)


def die(msg):
    print(f"install: ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def run(cmd, **kwargs):
    print(f"install: {' '.join(str(c) for c in cmd)}")
    subprocess.run(cmd, check=True, **kwargs)


def main():
    ap = argparse.ArgumentParser(description="Install Project Orion.")
    ap.add_argument("--no-venv", action="store_true",
                    help="install into the current Python, no venv")
    args = ap.parse_args()

    if sys.version_info < MIN_PYTHON:
        die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required"
            f" (found {sys.version.split()[0]}).")

    req = HERE / "requirements.txt"
    if not req.exists():
        die("requirements.txt not found -- run this from the repo folder.")

    if args.no_venv:
        pythons = [sys.executable]
        print("install: using current Python (no venv).")
    else:
        venv_dir = HERE / "venv"
        venv_py = (venv_dir / ("Scripts" if os.name == "nt" else "bin")
                   / ("python.exe" if os.name == "nt" else "python"))
        if not venv_py.exists():
            print("install: creating virtual environment...")
            run([sys.executable, "-m", "venv", str(venv_dir)])
        else:
            print("install: virtual environment already exists, reusing it.")
        pythons = [str(venv_py)]

    for py in pythons:
        print("install: upgrading pip...")
        run([py, "-m", "pip", "install", "--quiet", "--upgrade", "pip"])
        print("install: installing dependencies (this can take a minute)...")
        run([py, "-m", "pip", "install", "--quiet", "-r", str(req)])

    # Bootstrap the config file. Import from the repo directly so this
    # works before anything is installed system-wide.
    sys.path.insert(0, str(HERE))
    try:
        from netmon import config as cfgm
        cfg_path = cfgm.ensure_bootstrap()
        print(f"install: config file ready at {cfg_path}")
    except Exception as exc:
        die(f"could not create the config file: {exc}")

    # Optional pieces the user may want later -- report, don't require.
    print()
    if shutil.which("bettercap") or Path(r"C:\Tools\bettercap.exe").exists():
        print("install: bettercap found -- whole-network mode available.")
    else:
        print("install: bettercap not found (optional; only needed for"
              " whole-network relay mode).")

    print()
    print("Done! Next steps:")
    print("  1. Set your OpenAI key for AI summaries (optional):")
    if os.name == "nt":
        print(r"       setx OPENAI_API_KEY " + '"<your key>"')
        print("  2. Set a dashboard password (recommended):")
        print(r"       setx NETMON_PASSWORD " + '"<pick a password>"')
        print("  3. Run it:")
        print(r"       venv\Scripts\python -m netmon.run --dashboard-only")
        print("     Then open http://127.0.0.1:5001")
    else:
        print('       export OPENAI_API_KEY="<your key>"')
        print("  2. Set a dashboard password (recommended):")
        print('       export NETMON_PASSWORD="<pick a password>"')
        print("  3. Run it:")
        print("       venv/bin/python -m netmon.run --dashboard-only")
        print("     Then open http://127.0.0.1:5001")
    print()
    print("  Tune everything later in the config file shown above.")


if __name__ == "__main__":
    main()
