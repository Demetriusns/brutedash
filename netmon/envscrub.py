"""Scrubbed subprocess environment for third-party scanner binaries.

Council review 2026-11-08 (security S4): the nuclei and amass binaries
are downloaded from the internet, and their subprocesses used to
inherit the monitor's full environment -- OPENAI_API_KEY,
ABUSEIPDB_API_KEY, NETMON_SMTP_PASS, the BRUTEDASH_AUTH_* dashboard
passwords. Neither tool needs any of those (amass reads its own
data-source keys from its own config file), so every scanner
invocation now runs with scrubbed_env(): a copy of os.environ minus
any name that looks like a secret. Everything else (PATH, HOME,
SystemRoot, proxies, ...) passes through untouched so the binaries
still run exactly as before.

One shared helper on purpose: the marker list is the security
property, and two copies in two modules would drift.
"""

import os

# Uppercase substrings that mark an env var name as secret-bearing.
# 2026-11-16 (security S4-residual): HEARTBEAT/WEBHOOK/AUTH/CREDENTIAL/
# PRIVATE added -- BRUTEDASH_MONITOR_HEARTBEAT_URL is a capability URL
# (health.py's scrub list already treats heartbeat_url/webhook_url as
# secrets) and it used to pass untouched to the scanner subprocesses;
# the same gap covered any *_AUTH / *_CREDENTIAL / *_WEBHOOK_* name.
# Over-scrubbing is safe here: neither scanner needs any of these.
_SECRET_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "PASS",
                   "HEARTBEAT", "WEBHOOK", "AUTH", "CREDENTIAL",
                   "PRIVATE")


def is_secret_name(name):
    """True when an env var name looks like it carries a secret."""
    upper = name.upper()
    return any(marker in upper for marker in _SECRET_MARKERS)


def scrubbed_env():
    """os.environ with every secret-named variable removed."""
    return {name: value for name, value in os.environ.items()
            if not is_secret_name(name)}
