"""MITRE ATT&CK tagging for brutedash detections.

Every alert kind maps to the attacker's most likely technique. These are
*analyst labels*, not verdicts -- they answer "if this were hostile, what
would the attacker be doing?" in the language professional SOCs use.
The detection itself stays deterministic (rules fire, models explain);
this table just names the technique.

Technique IDs/names follow the MITRE ATT&CK enterprise matrix. When a
kind is genuinely ambiguous we pick the closest fit and say so in the
note -- a wrong-but-close label a human can correct beats no label.
"""

# kind -> (technique_id, technique_name, tactic, note)
_TECHNIQUES = {
    "port_scan": (
        "T1046", "Network Service Discovery", "Discovery",
        "Knocking on many ports is how attackers find a way in.",
    ),
    "arp_spoof": (
        "T1557.002", "Adversary-in-the-Middle: ARP Cache Poisoning",
        "Credential Access",
        "Poisoned ARP lets an attacker sit between a device and the network.",
    ),
    "beaconing": (
        "T1071.001", "Application Layer Protocol: Web Protocols",
        "Command and Control",
        "Regular check-ins to one address look like malware phoning home.",
    ),
    "dns_tunneling": (
        "T1071.004", "Application Layer Protocol: DNS",
        "Command and Control",
        "Data hidden inside DNS lookups bypasses normal monitoring.",
    ),
    "dns_lookup_burst": (
        "T1071.004", "Application Layer Protocol: DNS",
        "Command and Control",
        "A burst of lookups can be malware resolving its next instructions.",
    ),
    "unusual_port": (
        "T1571", "Non-Standard Port",
        "Command and Control",
        "Talking on an odd channel is a classic way to dodge firewalls.",
    ),
    "traffic_spike": (
        "T1041", "Exfiltration Over C2 Channel",
        "Exfiltration",
        "A sudden surge of outbound data can be files leaving the network.",
    ),
    "volume_anomaly": (
        "T1041", "Exfiltration Over C2 Channel",
        "Exfiltration",
        "Unusual data volume leaving the network can be files leaving it.",
    ),
    "behavior_deviation": (
        "T1041", "Exfiltration Over C2 Channel",
        "Exfiltration",
        "A device moving far more than its own normal can be data theft.",
    ),
    "new_device": (
        "T1200", "Hardware Additions",
        "Initial Access",
        "A rogue device on the LAN is a foothold an attacker can use.",
    ),
    "new_external_ip": (
        "T1071.001", "Application Layer Protocol: Web Protocols",
        "Command and Control",
        "First contact with a new outside address can be C2 being set up.",
    ),
    "new_busy_domain": (
        "T1568.002", "Domain Generation Algorithms",
        "Defense Evasion",
        "A suddenly-busy new domain can be malware cycling through names.",
    ),
    "vuln_finding": (
        "T1046", "Network Service Discovery",
        "Discovery",
        "Open doors on your own LAN are what an attacker's scan would find.",
    ),
    "host_event": (
        "T1078", "Valid Accounts",
        "Persistence",
        "Odd host events (logons, services) can be an attacker settling in.",
    ),
    "usb_insert": (
        "T1091", "Replication Through Removable Media",
        "Initial Access",
        "USB drives carry malware into networks and files out of them.",
    ),
    "defender_detection": (
        "T1204.002", "User Execution: Malicious File",
        "Execution",
        "Defender caught something the attacker got executed on the host.",
    ),
    "host_compromise": (
        "T1071.001", "Application Layer Protocol: Web Protocols",
        "Command and Control",
        "Endpoint detection plus C2 traffic means the host is owned.",
    ),
    "self_drift": (
        "T1547.001", "Boot or Logon Autostart Execution: Registry Run Keys",
        "Persistence",
        "New listeners, services, or autoruns on the monitor box itself.",
    ),
    "phishing_domain": (
        "T1566.002", "Phishing: Spearphishing Link",
        "Initial Access",
        "A site on a phishing/malware blocklist was looked up or visited.",
    ),
    "malicious_ip": (
        "T1071.001", "Application Layer Protocol: Web Protocols",
        "Command and Control",
        "Traffic with an address the blocklists flag as malicious.",
    ),
    "amass_new_asset": (
        "T1590.002", "Gather Victim Network Information: DNS",
        "Reconnaissance",
        "A new public-facing subdomain or address is what an attacker's"
        " recon would find first.",
    ),
    "nuclei_finding": (
        "T1046", "Network Service Discovery",
        "Discovery",
        "A vulnerability scanner found a weakness on your own network --"
        " the same thing an attacker's scan would turn up.",
    ),
    "cve_match": (
        "T1190", "Exploit Public-Facing Application",
        "Initial Access",
        "Software on the monitor box has a flaw attackers are actively"
        " exploiting in the wild (CISA's known-exploited list). Closest"
        " fit: the box runs code with a known weaponized bug.",
    ),
    "rule_muted": (
        "T1562.001", "Impair Defenses: Disable or Modify Tools",
        "Defense Evasion",
        "Operational notice, not attacker behavior: one rule fired so"
        " often it was quieted down for a while. Closest fit: flooding a"
        " detector to blind it is itself a known attacker trick, which is"
        " why the mute is always visible, never silent.",
    ),
    "canary_touch": (
        "T1595.002", "Active Scanning: Vulnerability Scanning",
        "Reconnaissance",
        "Something on the LAN touched a fake target nothing legitimate"
        " should ever contact -- the way a scanner finds its way in.",
    ),
    "doh_usage": (
        "T1071.004", "Application Layer Protocol: DNS",
        "Command and Control",
        "A device is resolving names over encrypted HTTPS (DoH) instead"
        " of plain DNS. Legitimate privacy feature -- but it also blinds"
        " DNS-based detection, which is why it's worth knowing about.",
    ),
}


def tag_for(kind):
    """Return the MITRE tag dict for an alert kind, or None if unmapped.

    The dict has keys: id, name, tactic, note. New detection kinds must
    be added here -- tests enforce that every kind brutedash emits has
    a tag.
    """
    if not kind:
        return None
    entry = _TECHNIQUES.get(str(kind).strip())
    if not entry:
        return None
    tech_id, name, tactic, note = entry
    return {"id": tech_id, "name": name, "tactic": tactic, "note": note}


def all_kinds():
    """Every alert kind with a MITRE tag."""
    return sorted(_TECHNIQUES)
