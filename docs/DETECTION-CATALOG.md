# Detection catalog -- Project Orion

> GENERATED FROM `netmon/detection_catalog.py` -- do not edit by hand. Re-render with `python -m netmon.detection_catalog --render`.

Every rule that can raise an alert in brutedash (23 rules), what it watches for, what it maps to in MITRE ATT&CK, what benign things set it off, and the test that proves it fires.

Design principles, from the roadmap: AI narrates, code decides -- deterministic rules fire alerts; the model only explains them. Quiet is a feature -- every dismissal must make tomorrow quieter.

### `port_scan` -- Port scan

- **What it detects:** Catches a device rapidly knocking on many of your ports -- the way an attacker looks for a way in. Think of it as someone walking down a hallway trying every doorknob.
- **Fires when:** 20 or more DIFFERENT destination ports touched by TCP SYN packets from one source address within 120 seconds.
- **Severity:** High
- **MITRE:** T1046 Network Service Discovery (Discovery)
- **Where it lives:** `netmon/capture.py` -- ScanTracker.observe (live, inline in capture)

**False positives (be honest):**

Your router or a security tool doing a health check can knock on several ports at once. A smart TV or game console phoning lots of servers usually hits a handful of ports, not twenty in two minutes.

**How to tell a false positive from a real one:**

Check which device the source address is. If it is your router, your own PC, or a security tool you run, it is benign. If it is a device you do not recognize -- especially on the guest Wi-Fi -- treat it as real.

**Tuning:**

1-hour cooldown per source address. Note: this rule only runs during LIVE capture (per-packet timing) -- it does not fire from pcap replays or the scheduled run_all loop.

**Proven by:** `tests/test_detection_poc.py::PortScanPocTests.test_scan_fires_high`

### `traffic_spike` -- Traffic spike

- **What it detects:** Catches the whole network (or this box) suddenly moving far more data than usual -- like a water bill jumping 5x in one month.
- **Fires when:** Bytes moved in the last 5 minutes are 5x or more than the average 5 minutes of the previous hour.
- **Severity:** Medium
- **MITRE:** T1041 Exfiltration Over C2 Channel (Exfiltration)
- **Where it lives:** `netmon/detect.py` -- check_traffic_spike (runs every minute)

**False positives (be honest):**

Large downloads, game updates, cloud photo backups, video calls, and OS updates all look exactly like this. This is the single most benign-looking rule in the catalog.

**How to tell a false positive from a real one:**

Match the time to what someone was doing. If a download, update, or backup was running, it is fine. It is suspicious only when nobody was doing anything data-heavy.

**Tuning:**

30-minute cooldown. Dismissals teach the allowlist (netmon/learn.py); quiet-hours windows can cover scheduled backups.

**Proven by:** `tests/test_detection_poc.py::TrafficSpikePocTests.test_spike_fires_medium`

### `unusual_port` -- Unusual port

- **What it detects:** Catches a device talking to the outside world on a channel (a 'port') everyday apps do not use. Ports are like TV channels -- most apps use the popular ones, and this one used an obscure channel.
- **Fires when:** Outbound TCP/UDP traffic in the last 15 minutes to a port outside the COMMON_PORTS list (web, DNS, mail, chat, video-call ports, and friends). Windows NetBIOS chatter (137-139) inside the LAN never counts.
- **Severity:** Medium
- **MITRE:** T1571 Non-Standard Port (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_unusual_ports (runs every minute)

**False positives (be honest):**

Games, work VPNs, video-chat apps, developer tools, and VoIP apps all use unusual ports every day. Port 4444 on a gamer PC is probably a game; port 4444 on the smart TV is worth a look.

**How to tell a false positive from a real one:**

Match the device and the time to what was running. Search the web for the port number. If a legit app explains it, dismiss it -- the dismissal learner will suggest silencing that exact device+port+destination pattern.

**Tuning:**

1-hour cooldown per device+address+port. Allowlist-aware ('Never alert me about' on the dashboard).

**Proven by:** `tests/test_detection_poc.py::UnusualPortPocTests.test_odd_port_fires`

### `beaconing` -- Beaconing (phoning home)

- **What it detects:** Catches a device checking in with the same outside address on a steady schedule -- like clockwork. Some of that is routine (apps checking for updates); malware also 'phones home' this way.
- **Fires when:** One device contacts one outside address in at least 8 of the twelve 5-minute buckets of the last hour.
- **Severity:** Medium
- **MITRE:** T1071.001 Application Layer Protocol: Web Protocols (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_beaconing (runs every minute)

**False positives (be honest):**

Email, chat, cloud backup, antivirus, and push notifications all check in on a schedule. This rule fires on legit software most of the time.

**How to tell a false positive from a real one:**

Search the web for the address. If it belongs to a service used on that device, it is fine. Suspicious when you do not recognize the address and each check-in moves only a tiny amount of data.

**Tuning:**

1-hour cooldown per device+address pair.

**Proven by:** `tests/test_detection_poc.py::BeaconingPocTests.test_clockwork_fires`

### `new_external_ip` -- First contact with a new outside address

- **What it detects:** Catches a device talking to an internet address it has never talked to before -- like getting a letter from a pen pal you have never heard of.
- **Fires when:** More than 1 MB exchanged in the last hour with an outside address the device has no first-seen record for.
- **Severity:** Low
- **MITRE:** T1071.001 Application Layer Protocol: Web Protocols (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_baseline_anomalies (runs every minute)

**False positives (be honest):**

New apps, games, updates, and work tools phone new servers constantly. This fires a lot on networks with a new device or a fresh OS install.

**How to tell a false positive from a real one:**

Think about what started running on that device in the last day or two. Something new matching the time = benign. Nothing new = worth a search of the address.

**Tuning:**

24-hour cooldown per device+address. Fires once per address -- after that the address is 'known'.

**Proven by:** `tests/test_detection_poc.py::NewExternalIpPocTests.test_first_contact_fires`

### `volume_anomaly` -- Volume anomaly (heavy upload)

- **What it detects:** Catches a KNOWN internet contact suddenly receiving far more data than ever before -- like a faucet that was dripping and is now running full blast. Could be a big upload, could be data quietly leaving the device.
- **Fires when:** A device sends more than 50 MB in the last hour to an outside address it has talked to before, AND that is more than 10x its own 7-day hourly average for that address.
- **Severity:** Medium
- **MITRE:** T1041 Exfiltration Over C2 Channel (Exfiltration)
- **Where it lives:** `netmon/detect.py` -- check_baseline_anomalies (runs every minute)

**False positives (be honest):**

Big uploads, photo/video syncs, cloud backups, and game-stream uploads all look like this. Needs the double condition (50 MB floor AND 10x), so small blips never fire it.

**How to tell a false positive from a real one:**

Match the time to what the device was doing. An upload or sync running then = expected. Nobody doing anything data-heavy = check which app sent the data.

**Tuning:**

24-hour cooldown per device+address.

**Proven by:** `tests/test_detection_poc.py::VolumeAnomalyPocTests.test_surge_fires`

### `dns_lookup_burst` -- DNS lookup burst

- **What it detects:** Catches a device asking 'where is this address?' for the same domain hundreds of times in a few minutes -- like calling directory assistance over and over for the same number.
- **Fires when:** More than 200 lookups of one domain by one device in the last 10 minutes.
- **Severity:** Medium
- **MITRE:** T1071.004 Application Layer Protocol: DNS (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_dns_anomalies (runs every minute)

**False positives (be honest):**

Glitchy or chatty apps retrying too fast do this constantly -- retry loops, captive-portal checks, and ad SDKs are the usual culprits.

**How to tell a false positive from a real one:**

Note which program was running on the device at the time. A chatty app you recognize = fine. A random-looking domain = search it.

**Tuning:**

1-hour cooldown per device+domain.

**Proven by:** `tests/test_detection_poc.py::DnsLookupBurstPocTests.test_burst_fires`

### `dns_tunneling` -- DNS tunneling

- **What it detects:** Catches lots of strange, one-time-looking addresses under the same domain being asked about in a hurry -- the classic shape of sneaking data out disguised as ordinary address lookups, like passing notes written on the back of postcards.
- **Fires when:** More than 25 DISTINCT subdomains of one parent domain looked up by one device in the last 10 minutes.
- **Severity:** High
- **MITRE:** T1071.004 Application Layer Protocol: DNS (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_dns_anomalies (runs every minute)

**False positives (be honest):**

Rarely benign on a home network. Some antivirus and corporate security tools do rapid lookups like this, and a few CDNs generate many subdomains.

**How to tell a false positive from a real one:**

A home device has almost no reason to ask about dozens of odd subdomains at once. If the parent domain is a security product you run, it is fine; otherwise search the domain.

**Tuning:**

1-hour cooldown per device+parent-domain.

**Proven by:** `tests/test_detection_poc.py::DnsTunnelingPocTests.test_tunnel_shape_fires`

### `new_busy_domain` -- New busy domain

- **What it detects:** Catches a domain a device has never asked about before suddenly getting asked about dozens of times -- like a stranger's name popping up all over your call log.
- **Fires when:** More than 50 lookups in 10 minutes of a domain the device has no first-seen record for.
- **Severity:** Low
- **MITRE:** T1568.002 Domain Generation Algorithms (Defense Evasion)
- **Where it lives:** `netmon/detect.py` -- check_dns_anomalies (runs every minute)

**False positives (be honest):**

New apps phoning home for the first time do this. Anything installed or opened today explains it.

**How to tell a false positive from a real one:**

Something new installed or opened recently = expected. Nothing new = search the domain.

**Tuning:**

1-hour cooldown per device+domain.

**Proven by:** `tests/test_detection_poc.py::NewBusyDomainPocTests.test_new_busy_domain_fires`

### `new_device` -- New device joined

- **What it detects:** Catches hardware the network has never seen before -- a new face on the block. Usually a phone, laptop, TV, or smart gadget connecting for the first time.
- **Fires when:** A MAC address with no first-seen record appears in ARP sightings over the last hour.
- **Severity:** Low
- **MITRE:** T1200 Hardware Additions (Initial Access)
- **Where it lives:** `netmon/detect.py` -- check_new_devices (runs every minute)

**False positives (be honest):**

Guest phones, new TVs, smart plugs, and anything rejoining after a factory reset all fire this. Randomized phone MACs can fire it repeatedly.

**How to tell a false positive from a real one:**

Check your router's connected-devices list. If every device there is yours, it is fine. The devices page also shows a probation badge with the first-seen time.

**Tuning:**

24-hour cooldown per MAC. Allowlist-aware ('Never alert me about'). Dismissed MACs teach the learner.

**Proven by:** `tests/test_detection_poc.py::NewDevicePocTests.test_unknown_mac_fires`

### `arp_spoof` -- ARP spoofing

- **What it detects:** Catches lies in the local network's introductions. ARP is how devices say 'I'm 192.168.1.5, talk to this hardware address' -- an attacker lies in these introductions to intercept other devices' traffic, like putting neighbors' nameplates on their own door to grab their mail.
- **Fires when:** Two shapes. (1) One hardware address claims 3 or more different local addresses in 30 minutes. (2) A local address that used to answer as one hardware address is now also answering as a different one.
- **Severity:** High
- **MITRE:** T1557.002 Adversary-in-the-Middle: ARP Cache Poisoning (Credential Access)
- **Where it lives:** `netmon/detect.py` -- check_arp_spoof (runs every minute)

**False positives (be honest):**

Routers, hotspots, and virtual machines can legitimately answer for more than one address. A device getting a new IP from the router after an old one expired can trip shape 2. Note: brutedash's own whole-network relay deliberately ARP-spoofs, and this rule is built to flag it as a live self-test -- that one is expected.

**How to tell a false positive from a real one:**

Check the router's device list for the hardware address. If it is your router, your own relay PC, or a VM host, it is benign. An ordinary laptop or phone claiming several addresses is not.

**Tuning:**

1-hour cooldown per MAC (shape 1) or IP (shape 2).

**Proven by:** `tests/test_detection_poc.py::ArpSpoofPocTests.test_one_mac_many_ips_fires`; `tests/test_detection_poc.py::ArpSpoofPocTests.test_ip_changing_mac_fires`

### `behavior_deviation` -- Behavior deviation (unlike itself)

- **What it detects:** Catches a device moving far more data than IT usually moves at this hour -- like a roommate who normally takes a ten-minute shower suddenly running the water for two hours. Network-wide thresholds cry wolf; this one knows each device's own normal.
- **Fires when:** The device moved at least 4x its learned hourly baseline for the current hour AND cleared a 250 MB absolute floor. The baseline hour needs 3+ days of history, and devices under 24h old are left to the new-device watch.
- **Severity:** Medium
- **MITRE:** T1041 Exfiltration Over C2 Channel (Exfiltration)
- **Where it lives:** `netmon/detect.py` -- check_behavior_deviation (runs every minute)

**False positives (be honest):**

Game/OS updates, cloud backups, and video uploads blow past personal baselines all the time -- the rule is deliberately tuned to catch 'unusually big', which is what big legit transfers are too.

**How to tell a false positive from a real one:**

The alert shows the learned normal ('~90 MB/hr, learned over 5 days'). If the device was doing something big at that hour, it is fine. Nobody touched it and nothing was scheduled = look at the per-device traffic to see where the data went.

**Tuning:**

24-hour cooldown per device. 250 MB floor stops idle devices paging over pocket change. New devices on probation are skipped by design.

**Proven by:** `tests/test_detection_poc.py::BehaviorDeviationPocTests.test_deviation_fires`

### `phishing_domain` -- Phishing/malware domain

- **What it detects:** Catches a device looking up a site that sits on a community list of phishing and malware websites -- the kind behind fake login pages and bad downloads. Like a phone number on a scam-call list.
- **Fires when:** A DNS lookup in the last hour matches the local copy of the URLhaus malware/phishing domain feed (exact match or parent-domain walk). Local-only names (.local, .lan, .home.arpa, reverse-DNS) never count.
- **Severity:** High
- **MITRE:** T1566.002 Phishing: Spearphishing Link (Initial Access)
- **Where it lives:** `netmon/detect.py` -- check_threat_intel (runs every minute)

**False positives (be honest):**

These lists are rarely wrong about a site, but shared-hosting and URL shorteners can land innocent pages near bad ones, and a mistyped address can resolve to a parked scam domain.

**How to tell a false positive from a real one:**

If you meant to visit the site, type the address yourself instead of clicking a link. Do not type passwords or card numbers into it until you are sure.

**Tuning:**

24-hour cooldown per domain. Allowlist-aware. The feed refreshes every 12 hours from abuse.ch URLhaus.

**Proven by:** `tests/test_threatintel.py::PhishingDetectionTests.test_phishing_alert_fires`

### `malicious_ip` -- Malicious IP contact

- **What it detects:** Catches traffic with an address that security researchers flag as malicious -- a 'known malicious scanner' on sight. Like getting mail from an address the post office has flagged.
- **Fires when:** Outbound traffic in the last hour with an IP on the local copy of the Emerging Threats compromised-IP feed.
- **Severity:** High
- **MITRE:** T1071.001 Application Layer Protocol: Web Protocols (Command and Control)
- **Where it lives:** `netmon/detect.py` -- check_threat_intel (runs every minute)

**False positives (be honest):**

Unusual but not impossible: a CDN or shared host whose address got flagged while hosting something bad. Legit apps do not run from flagged addresses on purpose.

**How to tell a false positive from a real one:**

Check the Cases view for which device was involved and what it was doing then. The per-IP intel page shows why the address is flagged (scanning, brute-force, phishing, malware, botnet) plus country, ISP, and ASN.

**Tuning:**

24-hour cooldown per IP. Allowlist-aware. Feed refreshes every 12 hours.

**Proven by:** `tests/test_threatintel.py::MaliciousIpDetectionTests.test_malicious_ip_alert_fires`

### `host_event` -- Suspicious host event (Windows logs)

- **What it detects:** Catches odd things in Windows Event Log exports: a burst of failed logins, a brand-new background service, or Defender's real-time guard being switched off. The network half of the story; the endpoint AV handles prevention.
- **Fires when:** Three variants. (1) Event 4625: 5+ failed logins in 10 minutes from one IP -> Medium. (2) Event 7045: a service name never seen before -> Low. (3) Event 5007: Defender real-time protection turned off -> High. One alert kind covers all three log flavors, so the MITRE tag is the closest single umbrella (T1078, the logon-abuse shape). Per-variant closest fits: 4625 -> T1110.001 Brute Force; 7045 -> T1543.003 Windows Service; 5007 -> T1562.001 Impair Defenses.
- **Severity:** Low, Medium, High
- **MITRE:** T1078 Valid Accounts (Persistence)
- **Where it lives:** `netmon/ingest.py` -- check_failed_logons + check_new_services + check_defender (poll every 5 minutes)

**False positives (be honest):**

A few mistyped passwords are normal (the rule needs 5 in 10 minutes). New services appear with every software install and update. Real-time protection gets turned off deliberately while troubleshooting.

**How to tell a false positive from a real one:**

Failed logins: was the account owner actually logging in then? New service: search the web for the name -- tied to software you installed = fine. RTP off: expected only if YOU turned it off just now.

**Tuning:**

24-hour cooldown per variant key. Failed-logon IPs are correlated against network brute-force-style alerts (port_scan / beaconing / unusual_port) and linked in the alert. Loopback sources are ignored. Needs the watch-dir log exports configured, or the rule is a silent no-op.

**Proven by:** `tests/test_knownetwork.py::FailedLogonRuleTests.test_burst_fires_medium`; `tests/test_knownetwork.py::NewServiceRuleTests.test_new_service_alerts_once`; `tests/test_knownetwork.py::DefenderRuleTests.test_rtp_disabled_is_high`

### `usb_insert` -- Unknown USB device plugged in

- **What it detects:** Catches a USB drive (or a device acting like one) plugged into a Windows machine for the first time. USB drives are a classic way malware walks into a network -- and a classic way files walk out of it.
- **Fires when:** Event 6416/2003/2102 for a device ID never seen before, identified as mass storage (USBSTOR / mass storage class). Keyboards and mice are stored but never alert.
- **Severity:** Medium
- **MITRE:** T1091 Replication Through Removable Media (Initial Access)
- **Where it lives:** `netmon/ingest.py` -- check_usb_devices (poll every 5 minutes)

**False positives (be honest):**

Your own drive, plugged in for the first time, fires this once -- then it is known and stays quiet forever. That is the common case, by design.

**How to tell a false positive from a real one:**

Ask who plugged it in. If it was you, dismiss it -- the device is now known and will not alert again. If nobody claims it, unplug it.

**Tuning:**

24-hour cooldown per device ID. Needs the watch-dir log exports configured.

**Proven by:** `tests/test_knownetwork.py::UsbRuleTests.test_unknown_usb_storage_alerts`

### `defender_detection` -- Defender caught something

- **What it detects:** Notes it when Windows Defender finds malware or unwanted software on a machine and handles the file itself. The network monitor keeps the note so the full story is in one place -- it does not re-fight the file.
- **Fires when:** Defender event 1116/1117 (detection or action taken). Severity follows Defender's own rating: severe/critical/high -> High, anything lower -> Medium.
- **Severity:** Medium, High
- **MITRE:** T1204.002 User Execution: Malicious File (Execution)
- **Where it lives:** `netmon/ingest.py` -- check_defender (poll every 5 minutes)

**False positives (be honest):**

Detections happen: Defender catches adware, trojans in downloads, and PUAs regularly -- and occasionally flags a tool you trust (cracks, keygens, legit admin tools).

**How to tell a false positive from a real one:**

Open Windows Security on that machine and check the Protection history entry. A real trojan = run a full scan. A tool you trust that Defender dislikes = fine.

**Tuning:**

24-hour cooldown per threat+path. Needs the watch-dir log exports configured.

**Proven by:** `tests/test_knownetwork.py::DefenderRuleTests.test_detection_alerts`

### `host_compromise` -- Host under attack (Defender + network agree)

- **What it detects:** Two independent witnesses agree: the antivirus caught something bad on the machine, AND the network saw that same machine phoning out to a suspicious address. Either one alone is worth a look; together they strongly suggest the machine is compromised.
- **Fires when:** A Defender 1116/1117 detection on a host that also showed C2-shaped network traffic (beaconing, unusual_port, new_external_ip, or volume_anomaly) in the last 24 hours.
- **Severity:** Critical
- **MITRE:** T1071.001 Application Layer Protocol: Web Protocols (Command and Control)
- **Where it lives:** `netmon/ingest.py` -- check_defender (poll every 5 minutes)

**False positives (be honest):**

This is the highest bar in the catalog and it almost never fires on benign activity -- it needs both an endpoint detection AND matching network behavior. A false positive needs Defender to cry wolf at the same time the host talks to something odd.

**How to tell a false positive from a real one:**

This is not normal -- treat it as a real incident until proven otherwise. The shared outside address is named in the alert so incident grouping puts both alerts in one case.

**Tuning:**

24-hour cooldown per threat+path (inherited from the defender_detection path).

**Proven by:** `tests/test_knownetwork.py::DefenderRuleTests.test_detection_plus_c2_is_critical`

### `self_drift` -- Monitor-box drift (self-health)

- **What it detects:** Watches the box running brutedash itself: unexpected listening ports, new services or auto-start entries vs. baseline, and Defender's real-time guard. A blind monitor is worse than none.
- **Fires when:** Four checks vs. learned baselines. New listening ports -> Medium. New Windows services or autorun entries -> Low. Defender real-time protection OFF -> High (no baseline needed, checked directly). One alert kind covers all four checks, so the MITRE tag is the closest single umbrella (T1547.001, the persistence shape). Per-check closest fits: new listening ports -> T1046 Network Service Discovery; new services/autoruns -> T1547.001; Defender RTP off -> T1562.001 Impair Defenses.
- **Severity:** Low, Medium, High
- **MITRE:** T1547.001 Boot or Logon Autostart Execution: Registry Run Keys (Persistence)
- **Where it lives:** `netmon/selfcheck.py` -- run_selfcheck (every 6 hours)

**False positives (be honest):**

Installing or updating software on the box changes ports, services, and autoruns -- that is the normal cause, every time. The first run learns the baseline silently.

**How to tell a false positive from a real one:**

Normal right after installing or updating something on this box. Not normal if nothing changed and you do not recognize the entry.

**Tuning:**

24-hour cooldown per drift key. Windows checks are skipped elsewhere ('unavailable', never an alert).

**Proven by:** `tests/test_knownetwork.py::SelfcheckTests.test_drift_alerts`

### `vuln_finding` -- Open doors on your network (self scan)

- **What it detects:** Knocks on your own devices' doors the way an attacker would -- a weekly TCP connect scan of your OWN LAN -- so you see what an attacker's scan would find. An 'open door' (open port) is a way into a device over the network.
- **Fires when:** A genuinely NEW (or risk-changed) open door on one of your devices: 31 common ports across up to 64 LAN devices. Repeat scans with no changes stay completely silent. Severity is the highest door risk (Low/Medium); one alert per device.
- **Severity:** Low, Medium
- **MITRE:** T1046 Network Service Discovery (Discovery)
- **Where it lives:** `netmon/scan.py` -- alert_new_findings (weekly + on-demand self scan)

**False positives (be honest):**

Many open doors are normal -- routers serve admin pages, printers listen for print jobs, consoles run game services. The local risk knowledge base grades each door; telnet/23 or RDP/3389 where they do not belong is what matters.

**How to tell a false positive from a real one:**

Look at the list in the alert. If every door belongs to a service the device is supposed to run, it is fine. A door that surprises you is the one to close.

**Tuning:**

LAN-only (RFC1918/loopback enforced -- never scans the internet). Also runs YAML template checks (Docker API, Elasticsearch, Memcached, MQTT) as a second bounded pass; overlapping ports never alert twice.

**Proven by:** `tests/test_knownetwork.py::ScanAlertTests.test_alerts_only_for_new_doors`

### `amass_new_asset` -- New public-facing asset (outside view)

- **What it detects:** Maps what the internet can see of YOUR domain -- subdomains, addresses, certificates -- using passive sources. A new entry means something new is now visible to everyone.
- **Fires when:** The Amass scan of a configured domain finds a subdomain or IP it had not seen on a previous run. The FIRST run for a domain is the silent baseline. Capped at 10 individual alerts per run, then one summary.
- **Severity:** Medium
- **MITRE:** T1590.002 Gather Victim Network Information: DNS (Reconnaissance)
- **Where it lives:** `netmon/amass.py` -- alert_new_assets (weekly Amass scan + on-demand)

**False positives (be honest):**

New assets are normal when you launch something -- a new site, a VPN, a test server, a bulk DNS change. A big diff at once is usually a migration.

**How to tell a false positive from a real one:**

Did you (or your host/registrar) launch or change anything? Yes = fine. No = find out what the asset is and whether it should be public.

**Tuning:**

Targets come ONLY from config.yaml amass.domains -- the dashboard can never supply a scan target. Passive sources only; missing binary degrades gracefully.

**Proven by:** `tests/test_amass.py::AlertingTests.test_second_run_alerts_on_new_assets`

### `nuclei_finding` -- Vulnerability match (deep scan)

- **What it detects:** Runs thousands of known vulnerability checks against your own devices -- the same checks an attacker would run. A match means the device shows a weakness with a known fix or workaround.
- **Fires when:** A Nuclei template matches a device on your LAN at or above the configured severity floor (default: medium+). The FIRST run is the silent baseline. Capped at 10 individual alerts per run, then one summary.
- **Severity:** Low, Medium, High
- **MITRE:** T1046 Network Service Discovery (Discovery)
- **Where it lives:** `netmon/nuclei.py` -- alert_new_findings (weekly Nuclei scan + on-demand)

**False positives (be honest):**

Most matches are outdated software or default settings on gadgets -- worth fixing, rarely an emergency. Scanners also flag 'informational' items that are not really problems (stored, never alert).

**How to tell a false positive from a real one:**

It matters most on devices that face the internet or hold important files. A printer with an old web UI = update it when you can. Your router or a NAS with a critical match = sooner.

**Tuning:**

Own LAN only, targets from the asset inventory (never user-supplied). Signed templates only (-dut). Alert floor configurable; below-floor matches are stored, never alerted.

**Proven by:** `tests/test_nuclei.py::FullScanFlowTests.test_baseline_then_new_then_quiet`

### `cve_match` -- Known-exploited software on this box

- **What it detects:** Checks the software installed on the box running the monitor against CISA's short list of flaws attackers are actively using in the real world right now -- not theoretical, actually exploited.
- **Fires when:** An installed package (Python packages + OS packages/apps, read locally) matches an entry in the local CISA KEV catalog. One alert per (package, CVE), then quiet.
- **Severity:** Medium
- **MITRE:** T1190 Exploit Public-Facing Application (Initial Access)
- **Where it lives:** `netmon/swaudit.py` -- alert_new_matches (daily software inventory)

**False positives (be honest):**

Matches are common -- almost every box runs something on this list at some point. And the honest caveat: the list names PRODUCTS, not fixed versions, so a match means 'check whether you are patched', not 'you are hacked'.

**How to tell a false positive from a real one:**

Update the package to the latest version, then dismiss -- it will not come back once the match is gone. If you are already on the latest, you were already fine.

**Tuning:**

Once per (package, CVE); repeats stay quiet; vanished matches are cleaned silently. Local reads only -- the inventory never leaves the box. Daily from the monitor loop.

**Proven by:** `tests/test_swaudit.py::CorrelateTests.test_run_swaudit_alerts_once`

## How to add a new rule

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

