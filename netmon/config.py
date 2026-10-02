"""Unified product configuration for Project Orion.

One human-readable ``config.yaml`` instead of scattered environment variables.
On first run the file is created with commented defaults; the operator edits
it, and Orion picks it up on restart.

Resolution order (later wins): defaults < config.yaml < BRUTEDASH_* env vars.

Env mapping: ``BRUTEDASH_DASHBOARD_PORT=9090`` sets ``dashboard.port``.
Values are coerced to the type of the default (int/float/bool/str).

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
    },
    "alerts": {
        # Future: minimum confidence (0-100) before an alert pages the owner.
        "min_confidence": 0,
        # Hours between email digest sends; 0 disables.
        "digest_hours": 24,
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
}

ENV_PREFIX = "BRUTEDASH_"

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

monitor:
  heartbeat_url: ""  # healthchecks.io ping URL; empty = heartbeat disabled
  heartbeat_minutes: 5  # match the check's Period on healthchecks.io
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
