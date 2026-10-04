"""Unified product configuration for Project Orion.

One human-readable ``config.yaml`` instead of scattered environment variables.
On first run the file is created with commented defaults; the operator edits
it, and Orion picks it up on restart.

Resolution order (later wins): defaults < config.yaml < BRUTEDASH_* env vars.

Env mapping: ``BRUTEDASH_DASHBOARD_PORT=9090`` sets ``dashboard.port``.
Values are coerced to the type of the default (int/float/bool/str).

Env-var rule (B3): BRUTEDASH_* is the canonical prefix for every
config-file-backed setting. The legacy NETMON_* names still work as
deprecated aliases, but they print a loud warning -- nothing is silently
ignored anymore. Standalone secrets (NETMON_PASSWORD, NETMON_SECRET_KEY,
NETMON_SMTP_*) keep their existing names; see INSTALL.md.

This module has no import-time side effects: call ``load()`` explicitly.
Secrets (API keys, dashboard password) stay in environment variables and are
never written to the config file.
"""

import os
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

DEFAULTS = {
    "general": {
        "site_name": "Home network",
    },
    "capture": {
        # Network interface to sniff. Empty = auto-detect.
        "interface": "",
        # Whole-network relay mode (ARP-spoof via bettercap). Requires the
        # operator to run the relay separately; see wifimon.cap.
        "whole_network": False,
    },
    "dashboard": {
        "host": "127.0.0.1",
        "port": 5001,
    },
    "ai": {
        # "openai" or "off". The API key always comes from OPENAI_API_KEY.
        "provider": "openai",
        "model": "gpt-4o-mini",
        # Rate limits guard the AI budget: every /api/ask and /api/triage
        # call with the LLM on is a paid API call. Per-IP sliding windows.
        # The cheap fallback paths (no API key configured) are never
        # limited -- only the spendy calls count.
        "ask_per_min": 10,
        "ask_per_hour": 100,
    },
    "alerts": {
        # Future: minimum confidence (0-100) before an alert pages the owner.
        "min_confidence": 0,
        # Hours between email digest sends; 0 disables.
        "digest_hours": 24,
    },
    "quiet": {
        # Alert-fatigue circuit breaker (see netmon/db.py add_alert): one
        # rule firing this many times within the window below gets
        # auto-muted for the mute window. The mute is never silent -- a
        # visible "muted" alert is recorded and the dashboard shows it.
        "circuit_fires": 10,
        "circuit_window_min": 10,
        "circuit_mute_min": 60,
    },
    "canary": {
        # Fake open port + fake credentials file: a tripwire nothing
        # legitimate should ever touch (see netmon/canary.py). A touch
        # is a High alert. The listener never reads or writes -- it
        # accepts and closes immediately.
        "enabled": True,
        # Unusual high port for the fake listener.
        "port": 23231,
        # Bind address; empty = auto-detect this box's LAN address.
        "bind": "",
    },
    "response": {
        # Where "Escalate to admin" sends the incident bundle.
        # EMPTY BY DEFAULT -- never commit a real address here. The person
        # running brutedash types their admin's address in after install.
        # Can also come from the BRUTEDASH_RESPONSE_ADMIN_EMAIL env var.
        "admin_email": "",
    },
    "auth": {
        # Dashboard sign-in roles: owner (full control) vs viewer
        # (read-only -- sees everything, changes nothing). Two shared
        # secrets, no user database: right-sized for a home/small-biz box
        # where the owner hands the viewer password to one trusted person.
        # Prefer the BRUTEDASH_AUTH_OWNER_PASSWORD /
        # BRUTEDASH_AUTH_VIEWER_PASSWORD env vars -- values here are
        # readable by anyone who can read this file. If only ONE password
        # is set (either field), it is the owner password and viewer
        # sign-in stays disabled. No passwords at all = open dashboard
        # (localhost dev), exactly like before.
        "owner_password": "",
        "viewer_password": "",
    },
    "retention": {
        # Data retention: how long each kind of data is kept, in days.
        # A scheduled prune job (daily, from the monitor loop) deletes
        # expired rows in bounded batches. Alerts attached to OPEN or
        # ESCALATED cases are NEVER pruned -- only history that's no
        # longer actionable goes. The forensic rewind buffer has its own
        # bounds (rewind_minutes / rewind_max_mb) and is not pruned here.
        "flows_days": 30,          # raw flow records (the bulk of the DB)
        "observations_days": 30,   # dns_queries + arp_observations
        "alerts_days": 365,        # alert history (open/escalated cases exempt)
        "summaries_days": 90,      # AI/plain-English summaries
        "outages_days": 365,       # internet uptime log
        "score_snapshots_days": 365,  # security-score trend
        "prune_enabled": True,     # the daily prune job
        "prune_batch": 5000,       # rows per DELETE -- bounded, never locks for minutes
        "prune_interval_hours": 24,
    },
    "monitor": {
        # healthchecks.io ping URL for the heartbeat. Empty = disabled.
        # Prefer the BRUTEDASH_MONITOR_HEARTBEAT_URL env var for this --
        # anyone with the URL can fake heartbeats.
        "heartbeat_url": "",
        # Minutes between heartbeats. Match the check's Period on
        # healthchecks.io (set the check's Grace to ~2x this).
        "heartbeat_minutes": 5,
    },
    "scan": {
        # Weekly self vulnerability scan of the OWN LAN (see netmon/scan.py).
        # On-demand scans are always available from the dashboard.
        "weekly": True,
    },
    "ingest": {
        # Folder of exported Windows logs to watch (see INGEST.md).
        # Empty = log ingestion disabled (graceful no-op).
        "watch_dir": "",
    },
    "amass": {
        # External attack-surface mapping via OWASP Amass (optional tool
        # you install; see netmon/amass.py). Opt-in: scans run only when
        # enabled AND domains are listed.
        "enabled": False,
        # YOUR OWN domains only, e.g. ["example.com"]. These are the ONLY
        # scan targets, ever -- the dashboard cannot add targets.
        "domains": [],
        # Passive sources only (no direct contact with target
        # infrastructure). true is the safe default.
        "passive": True,
        # Weekly scheduled run of the external scan.
        "weekly": True,
        # Per-run cap, minutes.
        "timeout_min": 20,
    },
    "nuclei": {
        # Deeper vulnerability scanning via Nuclei (optional tool you
        # install; see netmon/nuclei.py). Opt-in: scheduled scans run only
        # when enabled AND the binary is installed. Targets are ALWAYS
        # your own LAN devices from the asset inventory -- the dashboard
        # can never add targets. Nuclei is never a network service: it
        # runs as a short-lived subprocess with -dut (signed templates
        # only) always on.
        "enabled": False,
        # Weekly scheduled run of the deeper scan.
        "weekly": True,
        # Only this severity and above alerts (low|medium|high|critical).
        # medium keeps the noise down; low/info findings are still stored.
        "min_severity": "medium",
        # Per-run cap, minutes.
        "timeout_min": 30,
    },
    "swaudit": {
        # Software inventory of THIS box matched against CISA's
        # known-exploited-vulnerabilities list (see netmon/swaudit.py).
        # Local reads only -- the software list never leaves the box.
        "enabled": True,
        # Daily run of the inventory + correlation check.
        "daily": True,
    },
    "reporting": {
        # Daily morning briefing email: the last 24h in plain English
        # (alerts, cases, score, quiet wins, exposed doors). ONE email
        # per day, never per alert (see netmon/reporting.py).
        "briefing_enabled": True,
        # The briefing goes out at/after this hour (local time). If the
        # hour falls inside quiet hours, the send waits until they end.
        "briefing_hour": 7,
        # Daily security score snapshot, for the trend on the dashboard.
        "score_enabled": True,
        # Forensic rewind: rolling RAW-packet buffer of your own network
        # for post-incident review (see netmon/rewind.py). Opt-in: raw
        # packets are only kept when you turn this on.
        "rewind_enabled": False,
        # Keep at most this many minutes of packets...
        "rewind_minutes": 60,
        # ...or this much disk, whichever fills first. Oldest packets
        # are deleted automatically; the buffer can never grow past this.
        "rewind_max_mb": 256,
        # Empty = <config>/rewind.
        "rewind_dir": "",
    },
}

ENV_PREFIX = "BRUTEDASH_"


def env_compat(new_name, old_name, default=""):
    """Read an env var by its canonical BRUTEDASH_* name, falling back to
    the legacy NETMON_* name with a loud deprecation warning.

    B3: run.py used to read NETMON_* directly while the docs promised
    BRUTEDASH_*, so BRUTEDASH_PORT was silently ignored. Nothing here is
    silent: the new name wins, the old name warns, and a missing var
    returns the default.
    """
    import sys
    if old_name in os.environ and new_name not in os.environ:
        print(f"WARNING: {old_name} is deprecated; use {new_name} instead.",
              file=sys.stderr)
        return os.environ[old_name]
    return os.environ.get(new_name, default)

_TEMPLATE = """\
# Project Orion configuration.
# Edit values below, then restart Orion. Secrets (API keys, passwords) are
# NEVER stored here -- set them as environment variables instead.

general:
  site_name: "Home network"   # friendly name shown in the dashboard

capture:
  interface: ""        # network interface to sniff; empty = auto-detect
  whole_network: false # true = ARP-spoof relay mode (see netmon/wifimon.cap)

dashboard:
  host: "127.0.0.1"    # bind address; use 0.0.0.0 for LAN access
  port: 5001

ai:
  provider: "openai"   # "openai" or "off" (rule-based summaries when off)
  model: "gpt-4o-mini" # model used for alert briefs
  # OPENAI_API_KEY must be set in the environment -- never put it here.

alerts:
  min_confidence: 0    # 0-100; alerts below this stay logged but don't notify
  digest_hours: 24     # hours between email digests; 0 disables

response:
  admin_email: ""  # who "Escalate to admin" emails the incident bundle to -- set this to your admin's address

auth:
  owner_password: ""   # full control. Prefer the BRUTEDASH_AUTH_OWNER_PASSWORD env var -- values here are readable by anyone who can read this file
  viewer_password: ""  # read-only dashboard. Prefer BRUTEDASH_AUTH_VIEWER_PASSWORD. If only one password is set, it is the owner and viewer sign-in stays off

retention:
  flows_days: 30            # raw flow records (the bulk of the database)
  observations_days: 30     # dns_queries + arp_observations
  alerts_days: 365          # alert history -- alerts on OPEN or ESCALATED cases are never pruned
  summaries_days: 90        # AI/plain-English summaries
  outages_days: 365         # internet uptime log
  score_snapshots_days: 365 # security-score trend
  prune_enabled: true       # daily prune job from the monitor loop
  prune_batch: 5000         # rows per DELETE -- bounded so the database never locks for minutes
  prune_interval_hours: 24

monitor:
  heartbeat_url: ""  # healthchecks.io ping URL; empty = heartbeat disabled
  heartbeat_minutes: 5  # match the check's Period on healthchecks.io

scan:
  weekly: true  # weekly self vulnerability scan of your OWN LAN (dashboard can also run one on demand)

ingest:
  watch_dir: ""  # folder of exported Windows logs to watch (see INGEST.md); empty = disabled

amass:
  enabled: false  # external attack-surface mapping via OWASP Amass (optional; install the amass binary first)
  domains: []     # YOUR OWN domains only, e.g. ["example.com"] -- these are the ONLY scan targets, ever
  passive: true   # passive sources only; no direct contact with target infrastructure
  weekly: true    # weekly scheduled run
  timeout_min: 20 # per-run cap, minutes

nuclei:
  enabled: false   # deeper vulnerability scanning via Nuclei (optional; install the nuclei binary first)
  weekly: true     # weekly scheduled run; targets are always your own LAN devices from the asset inventory
  min_severity: medium  # only this severity and above alerts (low|medium|high|critical)
  timeout_min: 30  # per-run cap, minutes

swaudit:
  enabled: true  # software inventory of THIS box vs CISA's known-exploited list (local reads only)
  daily: true    # daily inventory + correlation check

reporting:
  briefing_enabled: true  # daily morning briefing email: the last 24h in plain English (one email per day, never per alert)
  briefing_hour: 7        # the briefing goes out at/after this hour (local time); waits out quiet hours
  score_enabled: true     # daily security score snapshot, for the trend on the dashboard
  rewind_enabled: false   # forensic rewind: rolling RAW-packet buffer of your own network (opt-in)
  rewind_minutes: 60      # keep at most this many minutes of packets...
  rewind_max_mb: 256      # ...or this much disk, whichever fills first (oldest deleted automatically)
  rewind_dir: ""          # empty = <config>/rewind
"""


def config_dir() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "brutedash"


def config_path() -> Path:
    return config_dir() / "config.yaml"


def ensure_bootstrap(path: Path | None = None) -> Path:
    """Create config.yaml with commented defaults if it doesn't exist."""
    path = path or config_path()
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(_TEMPLATE)
        try:
            # L6: the file may hold monitor.heartbeat_url -- not world-readable.
            os.chmod(path, 0o600)
        except OSError:
            pass
    return path


def _deep_merge(base: dict, override: dict) -> dict:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def _coerce(value: str, default):
    if isinstance(default, bool):
        return value.strip().lower() in ("1", "true", "yes", "on")
    if isinstance(default, int):
        return int(value)
    if isinstance(default, float):
        return float(value)
    return value


def _apply_env(cfg: dict) -> dict:
    for section, keys in list(cfg.items()):
        if not isinstance(keys, dict):
            continue
        for key, default in list(keys.items()):
            env_name = f"{ENV_PREFIX}{section.upper()}_{key.upper()}"
            if env_name in os.environ:
                try:
                    cfg[section][key] = _coerce(os.environ[env_name], default)
                except (ValueError, TypeError):
                    pass  # bad env value: keep the file/default value
    return cfg


def load(path: Path | None = None) -> dict:
    """Load effective config: defaults < config.yaml < BRUTEDASH_* env."""
    path = path or config_path()
    cfg = {section: dict(keys) for section, keys in DEFAULTS.items()}
    if path.exists():
        if yaml is None:
            _warn_no_yaml(path)
        else:
            try:
                data = yaml.safe_load(path.read_text()) or {}
                if isinstance(data, dict):
                    cfg = _deep_merge(cfg, data)
            except Exception:
                pass  # corrupt file: fall back to defaults rather than crash
    return _apply_env(cfg)


_WARNED_NO_YAML = False


def _warn_no_yaml(path):
    """A config file the user bothered to write should never be silently
    ignored: say so once, loudly, instead of running on defaults."""
    global _WARNED_NO_YAML
    if _WARNED_NO_YAML:
        return
    _WARNED_NO_YAML = True
    import sys
    print(f"WARNING: {path} exists but PyYAML is not installed --"
          " config file ignored. Run: pip install pyyaml",
          file=sys.stderr)


def get(cfg: dict, dotted: str, default=None):
    """Fetch e.g. get(cfg, "dashboard.port")."""
    node = cfg
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return default
        node = node[part]
    return node


_CACHE: dict = {}


def load_cached(path: Path | None = None) -> dict:
    """load() with a stat-based cache so hot paths don't re-read the file."""
    path = path or config_path()
    key = str(path)
    try:
        mtime = path.stat().st_mtime
    except OSError:
        mtime = None
    cached = _CACHE.get(key)
    if cached is not None and cached[1] == mtime:
        return cached[0]
    cfg = load(path)
    _CACHE[key] = (cfg, mtime)
    return cfg


def whole_network_enabled() -> bool:
    """True when this machine relays the LAN.

    Environment wins (backwards compatible with NETMON_WHOLE_NETWORK=1),
    then the config file's ``capture.whole_network``.
    """
    env = os.environ.get("NETMON_WHOLE_NETWORK", "").strip().lower()
    if env:
        return env in ("1", "true", "yes", "on")
    return bool(get(load_cached(), "capture.whole_network", False))


def ai_enabled() -> bool:
    """LLM features on? Needs an API key AND provider != "off"."""
    if not os.environ.get("OPENAI_API_KEY"):
        return False
    return get(load_cached(), "ai.provider", "openai") != "off"


def ai_model() -> str:
    """Configured LLM model for briefs and Q&A."""
    return get(load_cached(), "ai.model", "gpt-4o-mini")


_WARNED_LEGACY_PASSWORD = False


def auth_passwords():
    """(owner_password, viewer_password) for the dashboard roles.

    Resolution: BRUTEDASH_AUTH_OWNER_PASSWORD / BRUTEDASH_AUTH_VIEWER_PASSWORD
    env vars win (read fresh from the environment, never cache-stale), then
    the config file's auth.* values, then the legacy NETMON_PASSWORD env var
    as the owner password (deprecated alias -- warns once).

    If only ONE password is set (either field), it is the owner password
    and viewer sign-in stays disabled. No passwords at all means the
    dashboard runs open (localhost dev), exactly like before roles existed.
    """
    global _WARNED_LEGACY_PASSWORD
    cfg = load_cached()
    owner = str(get(cfg, "auth.owner_password", "") or "")
    viewer = str(get(cfg, "auth.viewer_password", "") or "")
    # Env overrides are read directly so a changed variable takes effect
    # without waiting for the config file's mtime to move.
    owner = os.environ.get("BRUTEDASH_AUTH_OWNER_PASSWORD", "") or owner
    viewer = os.environ.get("BRUTEDASH_AUTH_VIEWER_PASSWORD", "") or viewer
    legacy = os.environ.get("NETMON_PASSWORD", "")
    if legacy and not owner:
        if not _WARNED_LEGACY_PASSWORD:
            _WARNED_LEGACY_PASSWORD = True
            import sys
            print("WARNING: NETMON_PASSWORD is deprecated as the dashboard"
                  " password; use BRUTEDASH_AUTH_OWNER_PASSWORD instead.",
                  file=sys.stderr)
        owner = legacy
    if not owner and viewer:
        # A lone password is the owner; viewer sign-in stays disabled.
        owner, viewer = viewer, ""
    return owner, viewer
