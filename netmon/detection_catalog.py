"""netmon/detection_catalog.py -- the single source of truth for brutedash's detection rules.

Repo-learning item 1 (threat-detection-engineer pattern): every rule gets a
description, a MITRE ATT&CK mapping, a false-positive profile, and a
validation test that proves it fires (item 11, the Strix "validate with
PoC" pattern -- his eval discipline).

docs/DETECTION-CATALOG.md is RENDERED from this module::

    python -m netmon.detection_catalog --render

Never edit the .md by hand -- tests/test_detection_catalog.py fails if the
rendered doc drifts out of sync, and fails if any alert kind the monitor
emits (add_alert call sites), any netmon/mitre.py entry, or any
playbooks.py KIND_TO_SLUG entry lacks a matching catalog entry (and vice
versa). A new rule lands with: rule -> MITRE tag -> FP profile -> PoC
test -> catalog entry. No silent gaps.

Voice rule: the false-positive profiles are read by the owner, so they are
written in plain, casual language. No medical language anywhere.
"""

RULES = [
    {
        "id": "port_scan",
        "title": "Port scan",
        "module": "netmon/capture.py",
        "rule": "ScanTracker.observe (live, inline in capture)",
        "description": ("Catches a device rapidly knocking on many of your"
                        " ports -- the way an attacker looks for a way in."
                        " Think of it as someone walking down a hallway"
                        " trying every doorknob."),
        "trigger": ("20 or more DIFFERENT destination ports touched by TCP"
                    " SYN packets from one source address within 120 seconds."),
        "severities": ["High"],
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "fp_profile": ("Your router or a security tool doing a health check"
                       " can knock on several ports at once. A smart TV or"
                       " game console phoning lots of servers usually hits a"
                       " handful of ports, not twenty in two minutes."),
        "recognize_fp": ("Check which device the source address is. If it is"
                         " your router, your own PC, or a security tool you"
                         " run, it is benign. If it is a device you do not"
                         " recognize -- especially on the guest Wi-Fi --"
                         " treat it as real."),
        "tuning": ("1-hour cooldown per source address. Note: this rule only"
                   " runs during LIVE capture (per-packet timing) -- it does"
                   " not fire from pcap replays or the scheduled run_all"
                   " loop."),
        "tests": ["tests/test_detection_poc.py::PortScanPocTests"
                  ".test_scan_fires_high"],
    },
    {
        "id": "traffic_spike",
        "title": "Traffic spike",
        "module": "netmon/detect.py",
        "rule": "check_traffic_spike (runs every minute)",
        "description": ("Catches the whole network (or this box) suddenly"
                        " moving far more data than usual -- like a water"
                        " bill jumping 5x in one month."),
        "trigger": ("Bytes moved in the last 5 minutes are 5x or more than"
                    " the average 5 minutes of the previous hour."),
        "severities": ["Medium"],
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "mitre_tactic": "Exfiltration",
        "fp_profile": ("Large downloads, game updates, cloud photo backups,"
                       " video calls, and OS updates all look exactly like"
                       " this. This is the single most benign-looking rule"
                       " in the catalog."),
        "recognize_fp": ("Match the time to what someone was doing. If a"
                         " download, update, or backup was running, it is"
                         " fine. It is suspicious only when nobody was doing"
                         " anything data-heavy."),
        "tuning": ("30-minute cooldown. Dismissals teach the allowlist"
                   " (netmon/learn.py); quiet-hours windows can cover"
                   " scheduled backups."),
        "tests": ["tests/test_detection_poc.py::TrafficSpikePocTests"
                  ".test_spike_fires_medium"],
    },
    {
        "id": "unusual_port",
        "title": "Unusual port",
        "module": "netmon/detect.py",
        "rule": "check_unusual_ports (runs every minute)",
        "description": ("Catches a device talking to the outside world on a"
                        " channel (a 'port') everyday apps do not use. Ports"
                        " are like TV channels -- most apps use the popular"
                        " ones, and this one used an obscure channel."),
        "trigger": ("Outbound TCP/UDP traffic in the last 15 minutes to a"
                    " port outside the COMMON_PORTS list (web, DNS, mail,"
                    " chat, video-call ports, and friends). Windows"
                    " NetBIOS chatter (137-139) inside the LAN never counts."),
        "severities": ["Medium"],
        "mitre_id": "T1571",
        "mitre_name": "Non-Standard Port",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("Games, work VPNs, video-chat apps, developer tools,"
                       " and VoIP apps all use unusual ports every day."
                       " Port 4444 on a gamer PC is probably a game; port"
                       " 4444 on the smart TV is worth a look."),
        "recognize_fp": ("Match the device and the time to what was running."
                         " Search the web for the port number. If a legit"
                         " app explains it, dismiss it -- the dismissal"
                         " learner will suggest silencing that exact"
                         " device+port+destination pattern."),
        "tuning": ("1-hour cooldown per device+address+port. Allowlist-aware"
                   " ('Never alert me about' on the dashboard)."),
        "tests": ["tests/test_detection_poc.py::UnusualPortPocTests"
                  ".test_odd_port_fires"],
    },
    {
        "id": "beaconing",
        "title": "Beaconing (phoning home)",
        "module": "netmon/detect.py",
        "rule": "check_beaconing (runs every minute)",
        "description": ("Catches a device checking in with the same outside"
                        " address on a steady schedule -- like clockwork."
                        " Some of that is routine (apps checking for"
                        " updates); malware also 'phones home' this way."),
        "trigger": ("One device contacts one outside address in at least 8"
                    " of the twelve 5-minute buckets of the last hour."),
        "severities": ["Medium"],
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("Email, chat, cloud backup, antivirus, and push"
                       " notifications all check in on a schedule. This rule"
                       " fires on legit software most of the time."),
        "recognize_fp": ("Search the web for the address. If it belongs to a"
                         " service used on that device, it is fine."
                         " Suspicious when you do not recognize the address"
                         " and each check-in moves only a tiny amount of"
                         " data."),
        "tuning": ("1-hour cooldown per device+address pair."),
        "tests": ["tests/test_detection_poc.py::BeaconingPocTests"
                  ".test_clockwork_fires"],
    },
    {
        "id": "new_external_ip",
        "title": "First contact with a new outside address",
        "module": "netmon/detect.py",
        "rule": "check_baseline_anomalies (runs every minute)",
        "description": ("Catches a device talking to an internet address it"
                        " has never talked to before -- like getting a"
                        " letter from a pen pal you have never heard of."),
        "trigger": ("More than 1 MB exchanged in the last hour with an"
                    " outside address the device has no first-seen record"
                    " for."),
        "severities": ["Low"],
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("New apps, games, updates, and work tools phone new"
                       " servers constantly. This fires a lot on networks"
                       " with a new device or a fresh OS install."),
        "recognize_fp": ("Think about what started running on that device"
                         " in the last day or two. Something new matching"
                         " the time = benign. Nothing new = worth a search"
                         " of the address."),
        "tuning": ("24-hour cooldown per device+address. Fires once per"
                   " address -- after that the address is 'known'."),
        "tests": ["tests/test_detection_poc.py::NewExternalIpPocTests"
                  ".test_first_contact_fires"],
    },
    {
        "id": "volume_anomaly",
        "title": "Volume anomaly (heavy upload)",
        "module": "netmon/detect.py",
        "rule": "check_baseline_anomalies (runs every minute)",
        "description": ("Catches a KNOWN internet contact suddenly receiving"
                        " far more data than ever before -- like a faucet"
                        " that was dripping and is now running full blast."
                        " Could be a big upload, could be data quietly"
                        " leaving the device."),
        "trigger": ("A device sends more than 50 MB in the last hour to an"
                    " outside address it has talked to before, AND that is"
                    " more than 10x its own 7-day hourly average for that"
                    " address."),
        "severities": ["Medium"],
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "mitre_tactic": "Exfiltration",
        "fp_profile": ("Big uploads, photo/video syncs, cloud backups, and"
                       " game-stream uploads all look like this. Needs the"
                       " double condition (50 MB floor AND 10x), so small"
                       " blips never fire it."),
        "recognize_fp": ("Match the time to what the device was doing. An"
                         " upload or sync running then = expected. Nobody"
                         " doing anything data-heavy = check which app sent"
                         " the data."),
        "tuning": ("24-hour cooldown per device+address."),
        "tests": ["tests/test_detection_poc.py::VolumeAnomalyPocTests"
                  ".test_surge_fires"],
    },
    {
        "id": "dns_lookup_burst",
        "title": "DNS lookup burst",
        "module": "netmon/detect.py",
        "rule": "check_dns_anomalies (runs every minute)",
        "description": ("Catches a device asking 'where is this address?'"
                        " for the same domain hundreds of times in a few"
                        " minutes -- like calling directory assistance over"
                        " and over for the same number."),
        "trigger": ("More than 200 lookups of one domain by one device in"
                    " the last 10 minutes."),
        "severities": ["Medium"],
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("Glitchy or chatty apps retrying too fast do this"
                       " constantly -- retry loops, captive-portal checks,"
                       " and ad SDKs are the usual culprits."),
        "recognize_fp": ("Note which program was running on the device at"
                         " the time. A chatty app you recognize = fine. A"
                         " random-looking domain = search it."),
        "tuning": ("1-hour cooldown per device+domain."),
        "tests": ["tests/test_detection_poc.py::DnsLookupBurstPocTests"
                  ".test_burst_fires"],
    },
    {
        "id": "dns_tunneling",
        "title": "DNS tunneling",
        "module": "netmon/detect.py",
        "rule": "check_dns_anomalies (runs every minute)",
        "description": ("Catches lots of strange, one-time-looking addresses"
                        " under the same domain being asked about in a"
                        " hurry -- the classic shape of sneaking data out"
                        " disguised as ordinary address lookups, like"
                        " passing notes written on the back of postcards."),
        "trigger": ("More than 25 DISTINCT subdomains of one parent domain"
                    " looked up by one device in the last 10 minutes."),
        "severities": ["High"],
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("Rarely benign on a home network. Some antivirus and"
                       " corporate security tools do rapid lookups like"
                       " this, and a few CDNs generate many subdomains."),
        "recognize_fp": ("A home device has almost no reason to ask about"
                         " dozens of odd subdomains at once. If the parent"
                         " domain is a security product you run, it is"
                         " fine; otherwise search the domain."),
        "tuning": ("1-hour cooldown per device+parent-domain."),
        "tests": ["tests/test_detection_poc.py::DnsTunnelingPocTests"
                  ".test_tunnel_shape_fires"],
    },
    {
        "id": "new_busy_domain",
        "title": "New busy domain",
        "module": "netmon/detect.py",
        "rule": "check_dns_anomalies (runs every minute)",
        "description": ("Catches a domain a device has never asked about"
                        " before suddenly getting asked about dozens of"
                        " times -- like a stranger's name popping up all"
                        " over your call log."),
        "trigger": ("More than 50 lookups in 10 minutes of a domain the"
                    " device has no first-seen record for."),
        "severities": ["Low"],
        "mitre_id": "T1568.002",
        "mitre_name": "Domain Generation Algorithms",
        "mitre_tactic": "Defense Evasion",
        "fp_profile": ("New apps phoning home for the first time do this."
                       " Anything installed or opened today explains it."),
        "recognize_fp": ("Something new installed or opened recently ="
                         " expected. Nothing new = search the domain."),
        "tuning": ("1-hour cooldown per device+domain."),
        "tests": ["tests/test_detection_poc.py::NewBusyDomainPocTests"
                  ".test_new_busy_domain_fires"],
    },
    {
        "id": "new_device",
        "title": "New device joined",
        "module": "netmon/detect.py",
        "rule": "check_new_devices (runs every minute)",
        "description": ("Catches hardware the network has never seen before"
                        " -- a new face on the block. Usually a phone,"
                        " laptop, TV, or smart gadget connecting for the"
                        " first time."),
        "trigger": ("A MAC address with no first-seen record appears in"
                    " ARP sightings over the last hour."),
        "severities": ["Low"],
        "mitre_id": "T1200",
        "mitre_name": "Hardware Additions",
        "mitre_tactic": "Initial Access",
        "fp_profile": ("Guest phones, new TVs, smart plugs, and anything"
                       " rejoining after a factory reset all fire this."
                       " Randomized phone MACs can fire it repeatedly."),
        "recognize_fp": ("Check your router's connected-devices list. If"
                         " every device there is yours, it is fine. The"
                         " devices page also shows a probation badge with"
                         " the first-seen time."),
        "tuning": ("24-hour cooldown per MAC. Allowlist-aware ('Never alert"
                   " me about'). Dismissed MACs teach the learner."),
        "tests": ["tests/test_detection_poc.py::NewDevicePocTests"
                  ".test_unknown_mac_fires"],
    },
    {
        "id": "arp_spoof",
        "title": "ARP spoofing",
        "module": "netmon/detect.py",
        "rule": "check_arp_spoof (runs every minute)",
        "description": ("Catches lies in the local network's introductions."
                        " ARP is how devices say 'I'm 192.168.1.5, talk to"
                        " this hardware address' -- an attacker lies in"
                        " these introductions to intercept other devices'"
                        " traffic, like putting neighbors' nameplates on"
                        " their own door to grab their mail."),
        "trigger": ("Two shapes. (1) One hardware address claims 3 or more"
                    " different local addresses in 30 minutes. (2) A local"
                    " address that used to answer as one hardware address"
                    " is now also answering as a different one."),
        "severities": ["High"],
        "mitre_id": "T1557.002",
        "mitre_name": "Adversary-in-the-Middle: ARP Cache Poisoning",
        "mitre_tactic": "Credential Access",
        "fp_profile": ("Routers, hotspots, and virtual machines can"
                       " legitimately answer for more than one address."
                       " A device getting a new IP from the router after an"
                       " old one expired can trip shape 2. Note: brutedash's"
                       " own whole-network relay deliberately ARP-spoofs,"
                       " and this rule is built to flag it as a live"
                       " self-test -- that one is expected."),
        "recognize_fp": ("Check the router's device list for the hardware"
                         " address. If it is your router, your own relay"
                         " PC, or a VM host, it is benign. An ordinary"
                         " laptop or phone claiming several addresses is"
                         " not."),
        "tuning": ("1-hour cooldown per MAC (shape 1) or IP (shape 2)."),
        "tests": ["tests/test_detection_poc.py::ArpSpoofPocTests"
                  ".test_one_mac_many_ips_fires",
                  "tests/test_detection_poc.py::ArpSpoofPocTests"
                  ".test_ip_changing_mac_fires"],
    },
    {
        "id": "behavior_deviation",
        "title": "Behavior deviation (unlike itself)",
        "module": "netmon/detect.py",
        "rule": "check_behavior_deviation (runs every minute)",
        "description": ("Catches a device moving far more data than IT"
                        " usually moves at this hour -- like a roommate who"
                        " normally takes a ten-minute shower suddenly"
                        " running the water for two hours. Network-wide"
                        " thresholds cry wolf; this one knows each device's"
                        " own normal."),
        "trigger": ("The device moved at least 4x its learned hourly"
                    " baseline for the current hour AND cleared a 250 MB"
                    " absolute floor. The baseline hour needs 3+ days of"
                    " history, and devices under 24h old are left to the"
                    " new-device watch."),
        "severities": ["Medium"],
        "mitre_id": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "mitre_tactic": "Exfiltration",
        "fp_profile": ("Game/OS updates, cloud backups, and video uploads"
                       " blow past personal baselines all the time -- the"
                       " rule is deliberately tuned to catch 'unusually"
                       " big', which is what big legit transfers are too."),
        "recognize_fp": ("The alert shows the learned normal ('~90 MB/hr,"
                         " learned over 5 days'). If the device was doing"
                         " something big at that hour, it is fine. Nobody"
                         " touched it and nothing was scheduled = look at"
                         " the per-device traffic to see where the data"
                         " went."),
        "tuning": ("24-hour cooldown per device. 250 MB floor stops idle"
                   " devices paging over pocket change. New devices on"
                   " probation are skipped by design."),
        "tests": ["tests/test_detection_poc.py::BehaviorDeviationPocTests"
                  ".test_deviation_fires"],
    },
    {
        "id": "phishing_domain",
        "title": "Phishing/malware domain",
        "module": "netmon/detect.py",
        "rule": "check_threat_intel (runs every minute)",
        "description": ("Catches a device looking up a site that sits on a"
                        " community list of phishing and malware websites --"
                        " the kind behind fake login pages and bad"
                        " downloads. Like a phone number on a scam-call"
                        " list."),
        "trigger": ("A DNS lookup in the last hour matches the local copy"
                    " of the URLhaus malware/phishing domain feed (exact"
                    " match or parent-domain walk). Local-only names (.local,"
                    " .lan, .home.arpa, reverse-DNS) never count."),
        "severities": ["High"],
        "mitre_id": "T1566.002",
        "mitre_name": "Phishing: Spearphishing Link",
        "mitre_tactic": "Initial Access",
        "fp_profile": ("These lists are rarely wrong about a site, but"
                       " shared-hosting and URL shorteners can land"
                       " innocent pages near bad ones, and a mistyped"
                       " address can resolve to a parked scam domain."),
        "recognize_fp": ("If you meant to visit the site, type the address"
                         " yourself instead of clicking a link. Do not type"
                         " passwords or card numbers into it until you are"
                         " sure."),
        "tuning": ("24-hour cooldown per domain. Allowlist-aware. The feed"
                   " refreshes every 12 hours from abuse.ch URLhaus."),
        "tests": ["tests/test_threatintel.py::PhishingDetectionTests"
                  ".test_phishing_alert_fires"],
    },
    {
        "id": "malicious_ip",
        "title": "Malicious IP contact",
        "module": "netmon/detect.py",
        "rule": "check_threat_intel (runs every minute)",
        "description": ("Catches traffic with an address that security"
                        " researchers flag as malicious -- a 'known"
                        " malicious scanner' on sight. Like getting mail"
                        " from an address the post office has flagged."),
        "trigger": ("Outbound traffic in the last hour with an IP on the"
                    " local copy of the Emerging Threats compromised-IP"
                    " feed."),
        "severities": ["High"],
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("Unusual but not impossible: a CDN or shared host"
                       " whose address got flagged while hosting something"
                       " bad. Legit apps do not run from flagged addresses"
                       " on purpose."),
        "recognize_fp": ("Check the Cases view for which device was"
                         " involved and what it was doing then. The per-IP"
                         " intel page shows why the address is flagged"
                         " (scanning, brute-force, phishing, malware,"
                         " botnet) plus country, ISP, and ASN."),
        "tuning": ("24-hour cooldown per IP. Allowlist-aware. Feed"
                   " refreshes every 12 hours."),
        "tests": ["tests/test_threatintel.py::MaliciousIpDetectionTests"
                  ".test_malicious_ip_alert_fires"],
    },
    {
        "id": "host_event",
        "title": "Suspicious host event (Windows logs)",
        "module": "netmon/ingest.py",
        "rule": ("check_failed_logons + check_new_services +"
                 " check_defender (poll every 5 minutes)"),
        "description": ("Catches odd things in Windows Event Log exports: a"
                        " burst of failed logins, a brand-new background"
                        " service, or Defender's real-time guard being"
                        " switched off. The network half of the story; the"
                        " endpoint AV handles prevention."),
        "trigger": ("Three variants. (1) Event 4625: 5+ failed logins in"
                    " 10 minutes from one IP -> Medium. (2) Event 7045: a"
                    " service name never seen before -> Low. (3) Event 5007:"
                    " Defender real-time protection turned off -> High."
                    " One alert kind covers all three log flavors, so the"
                    " MITRE tag is the closest single umbrella (T1078,"
                    " the logon-abuse shape). Per-variant closest fits:"
                    " 4625 -> T1110.001 Brute Force; 7045 -> T1543.003"
                    " Windows Service; 5007 -> T1562.001 Impair Defenses."),
        "severities": ["Low", "Medium", "High"],
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "mitre_tactic": "Persistence",
        "fp_profile": ("A few mistyped passwords are normal (the rule needs"
                       " 5 in 10 minutes). New services appear with every"
                       " software install and update. Real-time protection"
                       " gets turned off deliberately while troubleshooting."),
        "recognize_fp": ("Failed logins: was the account owner actually"
                         " logging in then? New service: search the web for"
                         " the name -- tied to software you installed ="
                         " fine. RTP off: expected only if YOU turned it"
                         " off just now."),
        "tuning": ("24-hour cooldown per variant key. Failed-logon IPs are"
                   " correlated against network brute-force-style alerts"
                   " (port_scan / beaconing / unusual_port) and linked in"
                   " the alert. Loopback sources are ignored. Needs the"
                   " watch-dir log exports configured, or the rule is a"
                   " silent no-op."),
        "tests": ["tests/test_knownetwork.py::FailedLogonRuleTests"
                  ".test_burst_fires_medium",
                  "tests/test_knownetwork.py::NewServiceRuleTests"
                  ".test_new_service_alerts_once",
                  "tests/test_knownetwork.py::DefenderRuleTests"
                  ".test_rtp_disabled_is_high"],
    },
    {
        "id": "usb_insert",
        "title": "Unknown USB device plugged in",
        "module": "netmon/ingest.py",
        "rule": "check_usb_devices (poll every 5 minutes)",
        "description": ("Catches a USB drive (or a device acting like one)"
                        " plugged into a Windows machine for the first time."
                        " USB drives are a classic way malware walks into a"
                        " network -- and a classic way files walk out of"
                        " it."),
        "trigger": ("Event 6416/2003/2102 for a device ID never seen"
                    " before, identified as mass storage (USBSTOR / mass"
                    " storage class). Keyboards and mice are stored but"
                    " never alert."),
        "severities": ["Medium"],
        "mitre_id": "T1091",
        "mitre_name": "Replication Through Removable Media",
        "mitre_tactic": "Initial Access",
        "fp_profile": ("Your own drive, plugged in for the first time,"
                       " fires this once -- then it is known and stays"
                       " quiet forever. That is the common case, by"
                       " design."),
        "recognize_fp": ("Ask who plugged it in. If it was you, dismiss it"
                         " -- the device is now known and will not alert"
                         " again. If nobody claims it, unplug it."),
        "tuning": ("24-hour cooldown per device ID. Needs the watch-dir log"
                   " exports configured."),
        "tests": ["tests/test_knownetwork.py::UsbRuleTests"
                  ".test_unknown_usb_storage_alerts"],
    },
    {
        "id": "defender_detection",
        "title": "Defender caught something",
        "module": "netmon/ingest.py",
        "rule": "check_defender (poll every 5 minutes)",
        "description": ("Notes it when Windows Defender finds malware or"
                        " unwanted software on a machine and handles the"
                        " file itself. The network monitor keeps the note"
                        " so the full story is in one place -- it does not"
                        " re-fight the file."),
        "trigger": ("Defender event 1116/1117 (detection or action taken)."
                    " Severity follows Defender's own rating:"
                    " severe/critical/high -> High, anything lower ->"
                    " Medium."),
        "severities": ["Medium", "High"],
        "mitre_id": "T1204.002",
        "mitre_name": "User Execution: Malicious File",
        "mitre_tactic": "Execution",
        "fp_profile": ("Detections happen: Defender catches adware, trojans"
                       " in downloads, and PUAs regularly -- and"
                       " occasionally flags a tool you trust (cracks,"
                       " keygens, legit admin tools)."),
        "recognize_fp": ("Open Windows Security on that machine and check"
                         " the Protection history entry. A real trojan ="
                         " run a full scan. A tool you trust that Defender"
                         " dislikes = fine."),
        "tuning": ("24-hour cooldown per threat+path. Needs the watch-dir"
                   " log exports configured."),
        "tests": ["tests/test_knownetwork.py::DefenderRuleTests"
                  ".test_detection_alerts"],
    },
    {
        "id": "host_compromise",
        "title": "Host under attack (Defender + network agree)",
        "module": "netmon/ingest.py",
        "rule": "check_defender (poll every 5 minutes)",
        "description": ("Two independent witnesses agree: the antivirus"
                        " caught something bad on the machine, AND the"
                        " network saw that same machine phoning out to a"
                        " suspicious address. Either one alone is worth a"
                        " look; together they strongly suggest the machine"
                        " is compromised."),
        "trigger": ("A Defender 1116/1117 detection on a host that also"
                    " showed C2-shaped network traffic (beaconing,"
                    " unusual_port, new_external_ip, or volume_anomaly)"
                    " in the last 24 hours."),
        "severities": ["Critical"],
        "mitre_id": "T1071.001",
        "mitre_name": "Application Layer Protocol: Web Protocols",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("This is the highest bar in the catalog and it"
                       " almost never fires on benign activity -- it needs"
                       " both an endpoint detection AND matching network"
                       " behavior. A false positive needs Defender to cry"
                       " wolf at the same time the host talks to something"
                       " odd."),
        "recognize_fp": ("This is not normal -- treat it as a real incident"
                         " until proven otherwise. The shared outside"
                         " address is named in the alert so incident"
                         " grouping puts both alerts in one case."),
        "tuning": ("24-hour cooldown per threat+path (inherited from the"
                   " defender_detection path)."),
        "tests": ["tests/test_knownetwork.py::DefenderRuleTests"
                  ".test_detection_plus_c2_is_critical"],
    },
    {
        "id": "self_drift",
        "title": "Monitor-box drift (self-health)",
        "module": "netmon/selfcheck.py",
        "rule": "run_selfcheck (every 6 hours)",
        "description": ("Watches the box running brutedash itself:"
                        " unexpected listening ports, new services or"
                        " auto-start entries vs. baseline, and Defender's"
                        " real-time guard -- plus the monitor's own"
                        " pipeline: a nearly-full disk, or a pipeline"
                        " stage (capture, detection, feeds, email) gone"
                        " silent too long. A blind monitor is worse than"
                        " none."),
        "trigger": ("Four checks vs. learned baselines. New listening"
                    " ports -> Medium. New Windows services or autorun"
                    " entries -> Low. Defender real-time protection OFF"
                    " -> High (no baseline needed, checked directly)."
                    " One alert kind covers all four checks, so the MITRE"
                    " tag is the closest single umbrella (T1547.001, the"
                    " persistence shape). Per-check closest fits: new"
                    " listening ports -> T1046 Network Service Discovery;"
                    " new services/autoruns -> T1547.001; Defender RTP off"
                    " -> T1562.001 Impair Defenses."
                    " Pipeline self-alerts (netmon/pipeline.py) reuse this"
                    " kind -- they all mean 'the monitor itself needs"
                    " attention': disk nearly full -> Medium (one alert"
                    " per episode, non-essential writes pause); capture"
                    " silent 5+ min -> High; detection passes failing or"
                    " silent -> Medium; feed refresh stale 36h+ -> Low;"
                    " email sends failing or silent -> Medium. The"
                    " loop-down watchdog (dashboard-side, netmon/"
                    " pipeline.py): the monitor loop stamps a tick every"
                    " pass and leaves a pid file; pid file present + tick"
                    " stale 10+ min -> High, one per episode. Closest"
                    " fit for the pipeline variants: T1562.001 Impair"
                    " Defenses (the monitor's own defenses degraded)."
                    " When several stages go stale in the same check,"
                    " one combined alert fires at the highest member"
                    " severity instead of one per stage."),
        "severities": ["Low", "Medium", "High"],
        "mitre_id": "T1547.001",
        "mitre_name": ("Boot or Logon Autostart Execution: Registry Run"
                       " Keys"),
        "mitre_tactic": "Persistence",
        "fp_profile": ("Installing or updating software on the box changes"
                       " ports, services, and autoruns -- that is the"
                       " normal cause, every time. The first run learns the"
                       " baseline silently."),
        "recognize_fp": ("Normal right after installing or updating"
                         " something on this box. Not normal if nothing"
                         " changed and you do not recognize the entry."),
        "tuning": ("24-hour cooldown per drift key. Windows checks are"
                   " skipped elsewhere ('unavailable', never an alert)."),
        "tests": ["tests/test_knownetwork.py::SelfcheckTests"
                  ".test_drift_alerts",
                  "tests/test_pipeline_robustness.py::PipelineSelfAlertTests"
                  ".test_disk_full_alerts_once"],
    },
    {
        "id": "vuln_finding",
        "title": "Open doors on your network (self scan)",
        "module": "netmon/scan.py",
        "rule": "alert_new_findings (weekly + on-demand self scan)",
        "description": ("Knocks on your own devices' doors the way an"
                        " attacker would -- a weekly TCP connect scan of"
                        " your OWN LAN -- so you see what an attacker's"
                        " scan would find. An 'open door' (open port) is a"
                        " way into a device over the network."),
        "trigger": ("A genuinely NEW (or risk-changed) open door on one of"
                    " your devices: 31 common ports across up to 64 LAN"
                    " devices. Repeat scans with no changes stay completely"
                    " silent. Severity is the highest door risk"
                    " (Low/Medium); one alert per device."),
        "severities": ["Low", "Medium"],
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "fp_profile": ("Many open doors are normal -- routers serve admin"
                       " pages, printers listen for print jobs, consoles"
                       " run game services. The local risk knowledge base"
                       " grades each door; telnet/23 or RDP/3389 where they"
                       " do not belong is what matters."),
        "recognize_fp": ("Look at the list in the alert. If every door"
                         " belongs to a service the device is supposed to"
                         " run, it is fine. A door that surprises you is"
                         " the one to close."),
        "tuning": ("LAN-only (RFC1918/loopback enforced -- never scans the"
                   " internet). Also runs YAML template checks (Docker API,"
                   " Elasticsearch, Memcached, MQTT) as a second bounded"
                   " pass; overlapping ports never alert twice."),
        "tests": ["tests/test_knownetwork.py::ScanAlertTests"
                  ".test_alerts_only_for_new_doors"],
    },
    {
        "id": "amass_new_asset",
        "title": "New public-facing asset (outside view)",
        "module": "netmon/amass.py",
        "rule": "alert_new_assets (weekly Amass scan + on-demand)",
        "description": ("Maps what the internet can see of YOUR domain --"
                        " subdomains, addresses, certificates -- using"
                        " passive sources. A new entry means something new"
                        " is now visible to everyone."),
        "trigger": ("The Amass scan of a configured domain finds a"
                    " subdomain or IP it had not seen on a previous run."
                    " The FIRST run for a domain is the silent baseline."
                    " Capped at 10 individual alerts per run, then one"
                    " summary."),
        "severities": ["Medium"],
        "mitre_id": "T1590.002",
        "mitre_name": "Gather Victim Network Information: DNS",
        "mitre_tactic": "Reconnaissance",
        "fp_profile": ("New assets are normal when you launch something --"
                       " a new site, a VPN, a test server, a bulk DNS"
                       " change. A big diff at once is usually a migration."),
        "recognize_fp": ("Did you (or your host/registrar) launch or change"
                         " anything? Yes = fine. No = find out what the"
                         " asset is and whether it should be public."),
        "tuning": ("Targets come ONLY from config.yaml amass.domains -- the"
                   " dashboard can never supply a scan target. Passive"
                   " sources only; missing binary degrades gracefully."),
        "tests": ["tests/test_amass.py::AlertingTests"
                  ".test_second_run_alerts_on_new_assets"],
    },
    {
        "id": "nuclei_finding",
        "title": "Vulnerability match (deep scan)",
        "module": "netmon/nuclei.py",
        "rule": "alert_new_findings (weekly Nuclei scan + on-demand)",
        "description": ("Runs thousands of known vulnerability checks"
                        " against your own devices -- the same checks an"
                        " attacker would run. A match means the device shows"
                        " a weakness with a known fix or workaround."),
        "trigger": ("A Nuclei template matches a device on your LAN at or"
                    " above the configured severity floor (default:"
                    " medium+). The FIRST run is the silent baseline."
                    " Capped at 10 individual alerts per run, then one"
                    " summary."),
        "severities": ["Low", "Medium", "High"],
        "mitre_id": "T1046",
        "mitre_name": "Network Service Discovery",
        "mitre_tactic": "Discovery",
        "fp_profile": ("Most matches are outdated software or default"
                       " settings on gadgets -- worth fixing, rarely an"
                       " emergency. Scanners also flag 'informational'"
                       " items that are not really problems (stored, never"
                       " alert)."),
        "recognize_fp": ("It matters most on devices that face the internet"
                         " or hold important files. A printer with an old"
                         " web UI = update it when you can. Your router or"
                         " a NAS with a critical match = sooner."),
        "tuning": ("Own LAN only, targets from the asset inventory (never"
                   " user-supplied). Signed templates only (-dut). Alert"
                   " floor configurable; below-floor matches are stored,"
                   " never alerted."),
        "tests": ["tests/test_nuclei.py::FullScanFlowTests"
                  ".test_baseline_then_new_then_quiet"],
    },
    {
        "id": "cve_match",
        "title": "Known-exploited software on this box",
        "module": "netmon/swaudit.py",
        "rule": "alert_new_matches (daily software inventory)",
        "description": ("Checks the software installed on the box running"
                        " the monitor against CISA's short list of flaws"
                        " attackers are actively using in the real world"
                        " right now -- not theoretical, actually"
                        " exploited."),
        "trigger": ("An installed package (Python packages + OS"
                    " packages/apps, read locally) matches an entry in the"
                    " local CISA KEV catalog. One alert per (package, CVE),"
                    " then quiet."),
        "severities": ["Medium"],
        "mitre_id": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "mitre_tactic": "Initial Access",
        "fp_profile": ("Matches are common -- almost every box runs"
                       " something on this list at some point. And the"
                       " honest caveat: the list names PRODUCTS, not fixed"
                       " versions, so a match means 'check whether you are"
                       " patched', not 'you are hacked'."),
        "recognize_fp": ("Update the package to the latest version, then"
                         " dismiss -- it will not come back once the match"
                         " is gone. If you are already on the latest, you"
                         " were already fine."),
        "tuning": ("Once per (package, CVE); repeats stay quiet; vanished"
                   " matches are cleaned silently. Local reads only -- the"
                   " inventory never leaves the box. Daily from the monitor"
                   " loop."),
        "tests": ["tests/test_swaudit.py::CorrelateTests"
                  ".test_run_swaudit_alerts_once"],
    },
    {
        "id": "rule_muted",
        "title": "Chatty rule quieted down",
        "module": "netmon/db.py",
        "rule": "add_alert circuit-breaker gate (runs on every alert)",
        "description": ("The alert-fatigue circuit breaker: when one rule"
                        " fires many times in a few minutes, the monitor"
                        " mutes it for a while instead of paging for every"
                        " firing. The mute is never silent -- this alert is"
                        " the visible record, and the dashboard shows the"
                        " mute with its counts."),
        "trigger": ("10 firings of one alert kind within 10 minutes"
                    " (configurable under quiet in config.yaml). The 10th"
                    " alert is recorded, the mute notice fires, and further"
                    " firings are counted but dropped for 60 minutes."),
        "severities": ["Medium"],
        "mitre_id": "T1562.001",
        "mitre_name": "Impair Defenses: Disable or Modify Tools",
        "mitre_tactic": "Defense Evasion",
        "fp_profile": ("This is operational chrome, not a threat -- it"
                       " fires exactly when it should. The 'false positive'"
                       " question is whether the underlying rule was"
                       " crying wolf; the mute just kept the noise down."),
        "recognize_fp": ("Check the Detection rules panel: it names the"
                         " muted rule, how many times it fired, and how"
                         " many extra firings were held back. Match the"
                         " time to something real -- a backup, an update."),
        "tuning": ("Thresholds live under quiet in config.yaml"
                   " (circuit_fires / circuit_window_min /"
                   " circuit_mute_min). The owner can lift a mute early"
                   " from the Detection rules panel. Self-alerts, the mute"
                   " notice itself, and the canary always pass through."),
        "tests": ["tests/test_leftovers.py::CircuitBreakerTests"
                  ".test_trip_mutes_and_records_visible_notice"],
    },
    {
        "id": "canary_touch",
        "title": "Something touched the trap",
        "module": "netmon/canary.py",
        "rule": "CanaryListener accept loop + bait-file mtime watch (monitor loop)",
        "description": ("A lightweight tripwire: a fake open port on the"
                        " LAN interface plus a fake credentials file. No"
                        " legitimate device should ever touch either --"
                        " the listener accepts and closes immediately,"
                        " never reading or writing, so it can't be used"
                        " for anything. A touch is a High alert by"
                        " definition."),
        "trigger": ("A TCP connection to the trap port (default 23231), or"
                    " a content change to the bait credentials file. One"
                    " alert per touching address per day; one per day for"
                    " the file."),
        "severities": ["High"],
        "mitre_id": "T1595.002",
        "mitre_name": "Active Scanning: Vulnerability Scanning",
        "mitre_tactic": "Reconnaissance",
        "fp_profile": ("Nearly none by design -- nothing legitimate knocks"
                       " here. The known benign causes: a port scan YOU"
                       " ran, or a security tool sweeping the LAN. The"
                       " bait file only changes if something rewrote it."),
        "recognize_fp": ("Were you running a scan when it fired? That's"
                         " your answer. Otherwise check the Devices page"
                         " for the touching address -- a compromised"
                         " device scans its neighbors."),
        "tuning": ("24h cooldown per touching address. Port and bind"
                   " address under canary in config.yaml. The self-check's"
                   " listening-port baseline excludes the trap port."),
        "tests": ["tests/test_leftovers.py::CanaryTests"
                  ".test_touch_fires_high_alert"],
    },
    {
        "id": "doh_usage",
        "title": "Device using encrypted DNS",
        "module": "netmon/detect.py",
        "rule": "check_doh_usage (runs every minute)",
        "description": ("Notes when a LAN device talks port 443 to a"
                        " well-known public DNS resolver -- the shape of"
                        " DNS-over-HTTPS. DoH is a legitimate privacy"
                        " feature, but it blinds DNS-based detection, so"
                        " the dashboard marks the device with a lock and"
                        " says visibility is reduced."),
        "trigger": ("Outbound port-443 flows from a LAN device to a known"
                    " public resolver IP (Cloudflare, Google, Quad9,"
                    " OpenDNS, AdGuard anycasts) within the last hour. One"
                    " Low note per device per day."),
        "severities": ["Low"],
        "mitre_id": "T1071.004",
        "mitre_name": "Application Layer Protocol: DNS",
        "mitre_tactic": "Command and Control",
        "fp_profile": ("This is informational, not an accusation -- most"
                       " hits are browsers or phones with encrypted DNS on"
                       " by default. The heuristic can also catch plain"
                       " HTTPS to a resolver IP, which is harmless."),
        "recognize_fp": ("Check the device's browser/OS DNS settings. If"
                         " encrypted DNS is on there, this is expected."
                         " Dismiss it and the monitor learns."),
        "tuning": ("24h cooldown per device. The resolver list is the"
                   " DOH_RESOLVER_IPS set in netmon/detect.py --"
                   " deliberately conservative (major anycasts only)."),
        "tests": ["tests/test_leftovers.py::DohTests"
                  ".test_doh_flow_fires_low_note"],
    },
]


def all_ids():
    """Every alert kind in the catalog."""
    return [r["id"] for r in RULES]


def by_id(kind):
    """The catalog entry for an alert kind, or None."""
    kind = (kind or "").strip()
    for r in RULES:
        if r["id"] == kind:
            return r
    return None


def title_for(kind):
    """Plain-language title for an alert kind, for user-facing copy.

    Council review: the UI must never show raw snake_case kind ids; this
    is the single source of truth for the replacement label. Unknown kinds
    fall back to a prettified id so new rules degrade gracefully."""
    r = by_id(kind)
    if r and r.get("title"):
        return r["title"]
    return str(kind or "").replace("_", " ").strip() or "unknown"



# --- rendering ---------------------------------------------------------------

_WORKFLOW_MD = """## How to add a new rule

A new detection lands in five steps, in this order. The catalog-consistency
test (`tests/test_detection_catalog.py`) enforces every one of them, so a
rule cannot ship without its paperwork:

1. **Rule** -- write the deterministic detection. Code decides; the LLM
   only ever narrates. Wire the alert through `dbm.add_alert(kind, ...)`
   with plain-English meaning / is-this-normal / what-to-do fields, a
   cooldown, and allowlist awareness where a human would tune it.
2. **MITRE** -- add the kind to `netmon/mitre.py` with the closest real
   technique id + name + tactic. Verify the mapping against the rule's
   actual logic (a wrong technique id is worse than a close one).
3. **False-positive profile** -- write the honest version: what benign
   activity triggers this, how the owner tells a false positive from a
   real one, and what tuning exists. Never claim a rule "never
   false-positives" -- every rule in this catalog has an FP profile.
4. **PoC test** -- prove it fires. Feed synthetic fixtures (packets, flows,
   events) through the rule on a scratch DB and assert the alert is created
   with the right kind and severity -- plus a negative case where the rule
   must NOT fire. A test that cannot fail is not a test.
5. **Catalog entry** -- add the dict to `RULES` above (id, title, module,
   rule, description, trigger, severities, mitre_*, fp_profile,
   recognize_fp, tuning, tests), then re-render this doc.

Then run the release gate: full suite on both pythons, py_compile, and the
smoke boot. Quiet is a feature -- new tests must be synthetic and scratch-DB
only, never alert noise in a real database.
"""


def _rule_md(rule):
    lines = []
    lines.append(f"### `{rule['id']}` -- {rule['title']}")
    lines.append("")
    lines.append(f"- **What it detects:** {rule['description']}")
    lines.append(f"- **Fires when:** {rule['trigger']}")
    sev = ", ".join(rule["severities"])
    lines.append(f"- **Severity:** {sev}")
    lines.append(f"- **MITRE:** {rule['mitre_id']} {rule['mitre_name']}"
                 f" ({rule['mitre_tactic']})")
    lines.append(f"- **Where it lives:** `{rule['module']}` -- {rule['rule']}")
    lines.append("")
    lines.append("**False positives (be honest):**")
    lines.append("")
    lines.append(rule["fp_profile"])
    lines.append("")
    lines.append("**How to tell a false positive from a real one:**")
    lines.append("")
    lines.append(rule["recognize_fp"])
    lines.append("")
    lines.append("**Tuning:**")
    lines.append("")
    lines.append(rule["tuning"])
    lines.append("")
    tests = "; ".join(f"`{t}`" for t in rule["tests"])
    lines.append(f"**Proven by:** {tests}")
    lines.append("")
    return "\n".join(lines)


def render_markdown():
    """Render the full catalog document. Deterministic."""
    lines = []
    lines.append("# Detection catalog -- Project Orion")
    lines.append("")
    lines.append("> GENERATED FROM `netmon/detection_catalog.py` -- do not"
                 " edit by hand. Re-render with"
                 " `python -m netmon.detection_catalog --render`.")
    lines.append("")
    lines.append(f"Every rule that can raise an alert in brutedash"
                 f" ({len(RULES)} rules), what it watches for, what it maps"
                 " to in MITRE ATT&CK, what benign things set it off, and"
                 " the test that proves it fires.")
    lines.append("")
    lines.append("Design principles, from the roadmap: AI narrates, code"
                 " decides -- deterministic rules fire alerts; the model"
                 " only explains them. Quiet is a feature -- every"
                 " dismissal must make tomorrow quieter.")
    lines.append("")
    for rule in RULES:
        lines.append(_rule_md(rule))
    lines.append(_WORKFLOW_MD)
    return "\n".join(lines) + "\n"


def main(argv=None):
    import argparse
    import os
    ap = argparse.ArgumentParser(
        description="Render the detection catalog doc from the registry.")
    ap.add_argument("--render", action="store_true",
                    help="write docs/DETECTION-CATALOG.md")
    ap.add_argument("--check", action="store_true",
                    help="exit 1 if the doc is out of sync")
    args = ap.parse_args(argv)
    root = os.path.join(os.path.dirname(__file__), "..")
    path = os.path.join(root, "docs", "DETECTION-CATALOG.md")
    rendered = render_markdown()
    if args.check:
        try:
            with open(path, encoding="utf-8") as fh:
                current = fh.read()
        except OSError:
            current = None
        return 0 if current == rendered else 1
    if args.render:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(rendered)
        print(f"wrote {path}")
        return 0
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
