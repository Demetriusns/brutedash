"""netmon/playbooks.py -- step-by-step fix-it guides.

Each guide answers three questions, in this order, in plain English:

  1. "Here's what we found"  -- what the finding means, no jargon
     (or jargon with an instant translation).
  2. "Here's what to do"     -- numbered steps a non-technical owner can
     follow. Short sentences. Nothing assumed.
  3. "When to escalate"      -- the line where this stops being a DIY job
     and becomes the admin's problem, with a pointer at the dashboard's
     "Escalate to admin" action on the case.

VOICE RULE (his, non-negotiable): casual, plain-spoken, non-technical.
No medical or doctor language -- a knowledgeable friend, not a clinic.

The slug registry (titles + blurbs) lives in netmon/attacksurface.py
PLAYBOOK_SLUGS; every key here must exist there (tests enforce it).
KIND_TO_SLUG maps each alert kind the monitor emits to its guide, so
case timelines can link "here's the fix-it guide" next to every alert.
"""

# alert kind -> playbook slug. Every kind brutedash emits must appear
# here (tests enforce it). A few kinds share a guide where the advice
# is genuinely the same (phishing_domain + malicious_ip both mean
# "talked to a known-bad address").
KIND_TO_SLUG = {
    "port_scan": "port-scan",
    "arp_spoof": "arp-spoofing",
    "beaconing": "beaconing",
    "dns_tunneling": "dns-tunneling",
    "dns_lookup_burst": "dns-lookup-burst",
    "unusual_port": "unusual-port",
    "traffic_spike": "traffic-spike",
    "volume_anomaly": "volume-anomaly",
    "behavior_deviation": "behavior-deviation",
    "new_device": "new-device",
    "new_external_ip": "new-external-ip",
    "new_busy_domain": "new-busy-domain",
    "vuln_finding": "risky-service",
    "nuclei_finding": "risky-service",
    "cve_match": "known-exploited-software",
    "host_event": "brute-force",
    "usb_insert": "usb-drive",
    "defender_detection": "defender-detection",
    "host_compromise": "host-compromise",
    "self_drift": "self-drift",
    "phishing_domain": "malicious-contact",
    "malicious_ip": "malicious-contact",
    "amass_new_asset": "amass-new-asset",
}


def playbook_slug_for_kind(kind):
    """The fix-it guide slug for an alert kind, or None."""
    if not kind:
        return None
    return KIND_TO_SLUG.get(str(kind).strip())


# Guide body: "found" paragraphs, numbered "do" steps as
# (step, detail) pairs, and the "escalate" paragraph. The dashboard
# appends the standard "how to escalate" box after `escalate`.
GUIDES = {
    "internet-exposed-door": {
        "found": [
            "Something on your network answers when the internet knocks."
            " A 'port' is just a numbered door apps use to talk -- and one"
            " of yours is visible to the whole internet.",
            "That doesn't mean anyone has walked through it. It means"
            " every automated scanner on the planet has it in an address"
            " book, trying the handle every day.",
        ],
        "do": [
            ("Find the port forward",
             "Log into your router -- usually by typing 192.168.1.1 or"
             " 192.168.0.1 into a browser on your home network. Look for a"
             " page called 'port forwarding', 'virtual servers', or 'NAT'."
             " Each entry is a door you (or a gadget) opened to the"
             " internet on purpose at some point."),
            ("Remove what you don't recognize",
             "Delete any forward you can't explain. If a game or camera"
             " stops working remotely afterward, you found the one it"
             " needed -- you can add just that one back."),
            ("Turn off UPnP",
             "UPnP lets gadgets open their own doors without asking you."
             " Find it in the router settings and switch it off. You'll"
             " open doors by hand from now on, which is the point."),
            ("Make sure DMZ is off",
             "DMZ puts one device fully outside the router's firewall."
             " Unless you set it deliberately for a games console, it"
             " should be off or empty."),
            ("Confirm it's closed",
             "Come back to the Attack surface page and re-check. The"
             " exposure should read 'No sign of outside access' within a"
             " few days of watching."),
        ],
        "escalate": ("If a door you closed keeps coming back open, or you"
                     " find forwards you never created, something on your"
                     " network may be opening them itself. That's admin"
                     " territory."),
    },
    "internet-exposed-printer": {
        "found": [
            "Your printer is visible to the whole internet. Printers should"
            " never face the internet -- their settings pages are an old,"
            " favorite break-in point, and exposed printers get abused for"
            " spam and snooping.",
            "Nobody needs to print from the internet. This one is always"
            " worth fixing.",
        ],
        "do": [
            ("Pull it back behind the router",
             "Log into your router (usually 192.168.1.1 in a browser) and"
             " delete any port forward pointing at the printer. Check the"
             " 'UPnP' setting too and turn it off -- printers love opening"
             " their own doors that way."),
            ("Password-protect the printer's settings page",
             "Type the printer's network address into a browser, find its"
             " settings/admin page, and set a strong password. Default"
             " passwords like 'admin/admin' are the whole problem."),
            ("Turn off cloud/remote printing features you don't use",
             "Features with names like 'cloud print', 'remote print', or"
             " 'ePrint' keep the printer chatting with the outside world."
             " If you only print from home, switch them off."),
            ("Confirm it's hidden",
             "Re-check the Attack surface page after a few days. You want"
             " 'No sign of outside access' next to the printer."),
        ],
        "escalate": ("If the printer keeps reappearing on the internet after"
                     " you close everything, or its settings page shows"
                     " logins you don't recognize, hand it to your admin."),
    },
    "open-admin-interface": {
        "found": [
            "A settings page -- your router's, a camera's, a smart hub's --"
            " is answering connections from the internet. That's the page"
            " where someone changes passwords and settings. It should never"
            " face the open internet.",
            "Attackers scan for exactly these pages and try the default"
            " passwords first. admin/admin still works depressingly often.",
        ],
        "do": [
            ("Take it off the internet",
             "Log into your router (192.168.1.1 in a browser, from home)"
             " and remove any port forward pointing at this device's"
             " settings port -- usually 80, 443, 8080, or 8443."),
            ("Set a strong, unique password on it",
             "On the device's own settings page, change the admin password"
             " to something long and unique. This matters even after it's"
             " off the internet, because everything on your home network"
             " can still reach it."),
            ("Use local-only admin if the device offers it",
             "Some routers and cameras have a 'remote management' or"
             " 'remote admin' toggle. Turn it off. You can still manage"
             " the device from home."),
            ("Update the device's firmware",
             "Old firmware on routers and cameras is how most of these get"
             " popped. Check the manufacturer's site for an update."),
            ("Check for logins you don't recognize",
             "If the device keeps logs, skim for admin logins at odd hours."
             " Anything unfamiliar goes straight to your admin."),
        ],
        "escalate": ("If you find logins you don't recognize, or the page"
                     " keeps becoming reachable after you close it, stop and"
                     " escalate. Assume the password is burned and say so in"
                     " the escalation."),
    },
    "risky-service": {
        "found": [
            "A 'risky service' is a network feature with a known weak spot:"
            " file sharing (port 445), remote desktop (3389), old-style"
            " logins (telnet, port 23), databases, that kind of thing."
            " Right now only devices inside your network can reach it, so"
            " today is fine.",
            "The risk is the day something untrustworthy gets inside -- a"
            " hacked smart plug, a visitor's laptop -- and finds these"
            " doors already open.",
        ],
        "do": [
            ("Figure out what it is",
             "Match the port number to the name: 445 is Windows file"
             " sharing, 3389 is Remote Desktop, 23 is telnet (ancient,"
             " sends passwords in plain text), 1433/3306 are databases."
             " The exposure on the dashboard names it too."),
            ("If you don't use it, turn it off",
             "On Windows: search 'Turn Windows features on or off' for"
             " telnet/SMB pieces, or Services for things set to Automatic"
             " that you don't need. On a gadget: its settings page."),
            ("If you do need it, lock it down",
             "Strong unique password, keep the software updated, and never"
             " forward its port through the router to the internet."),
            ("Never put these on the internet",
             "Exposing remote desktop or file sharing directly is how"
             " ransomware crews get in. If you need remote access, a VPN"
             " is the safe way."),
        ],
        "escalate": ("If the service keeps turning itself back on, or you"
                     " find one running on a device where nobody installed"
                     " it, that's worth an admin's eyes."),
    },
    "malicious-contact": {
        "found": [
            "One of your devices talked to an address that independent"
            " security researchers flag as malicious -- think of it as a"
            " phone number on a scam-call list. Legitimate apps don't run"
            " from addresses on these lists.",
            "One contact can be a fluke (a bad ad on a legit page). A"
            " pattern of them is not.",
        ],
        "do": [
            ("Find the device",
             "The exposure names it. Open its case on the dashboard -- the"
             " timeline shows exactly when the contact happened."),
            ("Match it to something you were doing",
             "Were you browsing at that time? A single hit during browsing"
             " is often a bad ad. Hits at 3am with nobody awake are not."),
            ("Run a malware scan on that device",
             "On Windows: Windows Security, 'Virus & threat protection',"
             " full scan. Let it finish."),
            ("If the scan is clean and it was a one-off, watch it",
             "Keep an eye on the device's case for a few days. One-off"
             " contacts that never repeat are usually noise."),
            ("If anything looks off, change passwords",
             "From a different, clean device: email, banking, and anything"
             " you logged into on the suspect machine."),
            ("Isolate it while you look",
             "The Devices section has an Isolate button per device. It"
             " cuts the device off from the internet; one click brings it"
             " back."),
        ],
        "escalate": ("Repeated contacts, contacts at odd hours, or a scan"
                     " that finds something it can't remove -- escalate with"
                     " the case's timeline attached. That's exactly what the"
                     " button is for."),
    },
    "iot-lateral-path": {
        "found": [
            "A low-trust gadget -- smart plug, camera, TV, that kind of"
            " thing -- has been seen talking to a computer or server on"
            " your network. Small gadgets get hijacked a lot (rarely"
            " updated, cheap software), and this shows where 'in' leads.",
            "This is observed traffic, one hop, no guessing: the gadget"
            " really did talk to that machine.",
        ],
        "do": [
            ("Understand the fix: separate lanes",
             "'Segmentation' is a fancy word for a simple idea: put the"
             " gadgets in one lane and the important stuff in another, so"
             " a hacked lightbulb can't reach your PC."),
            ("Move smart gadgets to the guest Wi-Fi",
             "Most routers have a guest network. Put cameras, plugs,"
             " TVs, and doorbells on it; keep computers and phones on the"
             " main network. They can still reach the internet, just not"
             " each other."),
            ("Give the guest network a strong password too",
             "It's still your network. Unique password, WPA2 or WPA3."),
            ("Check the gadget for updates",
             "Its app or settings page may offer a firmware update. Old"
             " gadget software is the usual way in."),
            ("Ask whether the gadget needs to talk to the PC at all",
             "If a camera app on your PC needs the camera, that's legit."
             " If there's no reason for the chatter, the guest-network"
             " move handles it."),
        ],
        "escalate": ("If the gadget's traffic looks deliberate and hostile"
                     " rather than chatty -- or you can't move it to a guest"
                     " network -- your admin can plan the segmentation with"
                     " you."),
    },
    "port-scan": {
        "found": [
            "Something knocked on lots of ports at once, checking which"
            " doors are open. That's called a port scan -- it's how"
            " attackers find a way in, and also how the entire internet"
            " background-scans everyone, all day.",
            "Most scans are noise. The question is always: was it aimed at"
            " you, and did it find anything?",
        ],
        "do": [
            ("Don't panic -- check if it was you",
             "Did you run the dashboard's 'Open doors check' around that"
             " time? That's your own scan, and it's supposed to look like"
             " this."),
            ("See what it was aimed at",
             "The alert names the target device. A scan from the internet"
             " hitting your router is background noise. A scan from a"
             " device inside your network is more interesting."),
            ("Make sure nothing sensitive faces the internet",
             "Open the Attack surface page. If nothing is reachable from"
             " outside, the scanner found nothing to work with."),
            ("A scan from inside your network deserves a look",
             "Find the scanning device on the Devices page. If you don't"
             " recognize it, that's a new-device problem too -- work that"
             " guide as well."),
            ("Keep everything patched",
             "Scans only matter when they find an unpatched door. Updates"
             " are the real defense here."),
        ],
        "escalate": ("A scan from inside your network by a device you don't"
                     " recognize, or scans paired with actual break-in"
                     " attempts, are worth escalating."),
    },
    "arp-spoofing": {
        "found": [
            "Devices on your network keep an 'address book' (called ARP)"
            " mapping network addresses to hardware addresses. Something"
            " is handing out wrong entries -- which lets it sit in the"
            " middle of other devices' traffic.",
            "Important: if you run whole-network mode, the monitor does"
            " this on purpose to see all the traffic. The dashboard says"
            " so when the relay is up -- that's your answer, and it's"
            " expected.",
        ],
        "do": [
            ("Check for the monitor's own relay first",
             "Whole-network mode on? Then this alert is the live self-test"
             " doing its job. Carry on."),
            ("Find the device doing it",
             "The alert names a hardware address. Match it on the Devices"
             " page -- name, vendor, and when it first showed up."),
            ("Isolate it",
             "Use the Isolate button on its device row. That cuts it off"
             " from the internet while you figure out what it is."),
            ("Figure out what it is",
             "Some VPNs, virtualization software, and network tools do"
             " this legitimately. If it's none of yours, treat it as"
             " hostile until proven otherwise."),
            ("If it's yours and legitimate, note it",
             "Rename the device so the next alert reads clearly, and"
             " mention it if you ever escalate."),
        ],
        "escalate": ("An unknown device poisoning your network's address"
                     " book is one of the few alerts worth escalating fast"
                     " -- it can see passwords and sessions."),
    },
    "beaconing": {
        "found": [
            "A device is checking in with one outside address on a steady"
            " rhythm -- every minute, every five minutes, like clockwork."
            " Malware does this to phone home. But so do Windows Update,"
            " cloud backups, and about a thousand legit apps.",
            "The rhythm is the clue, not the verdict. Now we figure out"
            " which one it is.",
        ],
        "do": [
            ("Find the device and the address",
             "The alert names both. Look the address up in the Threat"
             " intel section -- a flagged address answers the question"
             " immediately."),
            ("Match the rhythm to something you use",
             "Cloud backup running? Game launcher open? A work VPN? Steady"
             " check-ins usually belong to something installed on purpose."),
            ("Check what's running on the device",
             "On Windows: Task Manager, sorted by network. Anything you"
             " don't recognize gets a web search of its name before you"
             " touch it."),
            ("If nothing explains it, scan and isolate",
             "Full Defender scan on the device, then the Isolate button"
             " while you dig. Rhythmic traffic to an unknown address is"
             " exactly what isolation is for."),
            ("If it was malware, change passwords",
             "From a clean device: email, banking, anything touched on"
             " the suspect machine."),
        ],
        "escalate": ("Beaconing to a flagged address, or beaconing you"
                     " can't attribute to any program, is a strong"
                     " escalate candidate -- bring the timeline."),
    },
    "dns-tunneling": {
        "found": [
            "DNS is the internet's phone book -- your devices ask 'what's"
            " the address for this name?' thousands of times a day. This"
            " alert means those lookups look wrong: too long, too encoded,"
            " too strange. Data can be smuggled out inside DNS lookups"
            " because most people never inspect them.",
            "This is a technique real attackers use, so it deserves a"
            " proper look even though false alarms happen.",
        ],
        "do": [
            ("Find the device",
             "The alert names it. Note when it started -- the case"
             " timeline has the exact window."),
            ("Run a full malware scan on it",
             "Windows Security, full scan, let it finish. DNS tunneling"
             " needs software on the device doing the tunneling."),
            ("Check what programs were active",
             "Weird lookups with the browser closed are more suspicious"
             " than weird lookups during browsing."),
            ("Isolate the device while you investigate",
             "One click on the Devices page. DNS tunneling can't exfiltrate"
             " through a cut cable, so to speak."),
            ("Don't just block the domain and move on",
             "Blocking one weird domain when the device is still infected"
             " just makes the malware try the next one."),
        ],
        "escalate": ("This one is worth escalating early. Data smuggling"
                     " via DNS is a pro move -- your admin will want the"
                     " timeline and the device name."),
    },
    "dns-lookup-burst": {
        "found": [
            "A device suddenly made a burst of address lookups -- asking"
            " the internet's phone book for lots of names at once. Usually"
            " this is a misbehaving app or a web page loaded with ad"
            " trackers. Occasionally it's malware resolving its next"
            " instructions.",
            "Bursts are common and mostly boring. The check is quick.",
        ],
        "do": [
            ("See which device and which names",
             "The alert and its case name both. A burst of ad-network"
             " names during browsing is just the modern web being the"
             " modern web."),
            ("Close the browser tab or quit the app, then watch",
             "If the burst stops, you found it. If it keeps going with"
             " everything closed, keep going down this list."),
            ("Run a malware scan",
             "If it persists with no visible cause, full Defender scan on"
             " the device."),
            ("Check the names in Threat intel",
             "Paste the busiest domain into the intel lookup. Flagged"
             " means it graduates to the malicious-contact guide."),
        ],
        "escalate": ("A burst that survives a reboot with nothing open, or"
                     " names the intel lists flag, is worth an admin's"
                     " look."),
    },
    "unusual-port": {
        "found": [
            "A device talked on a port -- a numbered channel -- that"
            " nothing normally uses. Most internet traffic uses a handful"
            " of well-known ports (web pages on 443, for example), so an"
            " odd one stands out.",
            "Games, chat apps, remote tools, and game launchers all use"
            " odd ports legitimately. Malware does too, to dodge"
            " firewalls. The port alone can't tell you which.",
        ],
        "do": [
            ("Find the device and the port",
             "The alert names both. Check what was running on the device"
             " at the time -- the case timeline has the window."),
            ("Match it to software you installed",
             "Gaming? Video calls? A work tool? Those explain most odd"
             " ports. When in doubt, search the port number plus the app"
             " name."),
            ("Look up the outside address",
             "Paste it into the Threat intel lookup. Flagged is a"
             " different conversation than clean."),
            ("If nothing you recognize, scan and isolate",
             "Full malware scan, then the Isolate button while you sort it"
             " out."),
        ],
        "escalate": ("Odd port plus a flagged address, or traffic you can't"
                     " tie to any program, makes a clean escalation -- the"
                     " timeline has everything the admin needs."),
    },
    "traffic-spike": {
        "found": [
            "A device suddenly uploaded far more data than its usual -- a"
            " spike, not a drift. Big uploads happen all the time for"
            " innocent reasons: cloud backups, photo syncs, game updates,"
            " video calls.",
            "The innocent explanations are also the most common, so check"
            " those first. What's left after that is what matters.",
        ],
        "do": [
            ("Find the device",
             "The alert names it. Check the clock -- does the spike line up"
             " with something scheduled, like a nightly backup?"),
            ("Match it to something you do",
             "Photo backup running? Files syncing to the cloud? Someone on"
             " a video call uploading? Those are the usual suspects."),
            ("Check what's running on the device",
             "Task Manager sorted by network on Windows. A sync tool at"
             " the top is your answer."),
            ("If nothing matches, scan it",
             "Full Defender scan. Unexplained uploads are worth the hour"
             " it takes."),
            ("Isolate while you look, if it feels wrong",
             "The Isolate button stops the bleeding while you investigate."
             " One click brings it back."),
        ],
        "escalate": ("A spike you can't attribute to anything, especially"
                     " paired with other alerts on the same device, is"
                     " worth escalating -- possible data theft is the"
                     " admin's call to make."),
    },
    "volume-anomaly": {
        "found": [
            "More data moved across your network than its recent normal --"
            " not one dramatic spike, just heavier than usual overall."
            " Could be a big download day, a houseguest streaming, or"
            " something worth a closer look.",
        ],
        "do": [
            ("Check the top talkers",
             "The dashboard's traffic section shows who's moving the most"
             " data right now. Start with the biggest."),
            ("Match it to the household",
             "Game downloads, 4K streaming, video calls, cloud restores --"
             " the usual heavy hitters. Ask who's doing what if you have"
             " to."),
            ("Look at the per-device normal",
             "The Devices page shows each device's learned normal. A"
             " device far above its own normal is more interesting than a"
             " busy network overall."),
            ("Scan anything unexplained",
             "A device moving lots of data for no reason gets the full"
             " Defender scan."),
        ],
        "escalate": ("If the volume traces to a device nobody can explain,"
                     " or it keeps growing, escalate with the traffic"
                     " numbers."),
    },
    "behavior-deviation": {
        "found": [
            "The monitor learned this device's habits -- how much data it"
            " moves at each hour -- and it just broke them, hard. Four"
            " times its own normal, and not a small amount either.",
            "Devices don't change habits for no reason. New app, new"
            " person using it, or something you should know about.",
        ],
        "do": [
            ("Ask what changed",
             "New app installed? Someone else using the device? A big"
             " project? The human context solves most of these."),
            ("Check what's running",
             "Task Manager by network on Windows. The top talker usually"
             " explains the deviation by itself."),
            ("Give it a day of watching",
             "One-off deviations happen -- a big update, a backup catching"
             " up. If the device settles back to normal, that was it."),
            ("Scan it if it doesn't settle",
             "Persistent weirdness with no human explanation gets the full"
             " malware scan."),
        ],
        "escalate": ("A device that stays deviant for days with no"
                     " explanation is a good escalation -- the learned"
                     " baseline in the case is exactly the context an admin"
                     " wants."),
    },
    "new-device": {
        "found": [
            "Hardware the monitor has never seen joined your network. Most"
            " of the time it's yours -- a new phone, a guest's laptop, a"
            " gadget you forgot you plugged in. Sometimes it's a neighbor"
            " on your Wi-Fi. Rarely, it's someone you didn't invite.",
            "New devices get watched closely for their first 24 hours."
            " That's the probation badge on the Devices page.",
        ],
        "do": [
            ("Do you recognize it?",
             "Check the name, maker (vendor), and hostname on the Devices"
             " page. Your stuff usually identifies itself."),
            ("If it's yours, name it",
             "The Rename button makes every future alert about it read"
             " clearly. Future you says thanks."),
            ("If it's a guest's, that's fine -- note it",
             "Guests happen. The probation watch keeps an eye on it for"
             " the first day automatically."),
            ("If you don't recognize it at all",
             "Change your Wi-Fi password -- that kicks off everything"
             " that shouldn't be there. Check your router's connected-"
             " devices list for anything else unfamiliar."),
            ("Watch the probation badge",
             "For 24 hours the monitor flags anything aggressive from new"
             " devices. Quiet ones earn trust on their own."),
        ],
        "escalate": ("A mystery device that's also doing shady things"
                     " (scanning, beaconing, hammering logins) is an"
                     " escalate-now situation -- isolate it first, then"
                     " send the case up."),
    },
    "new-external-ip": {
        "found": [
            "Your network talked to an outside address for the first time."
            " This happens constantly in normal life -- new websites, new"
            " app servers, a CDN node you've never hit before.",
            "First contact is only interesting when the address itself is"
            " interesting.",
        ],
        "do": [
            ("Look it up",
             "Paste the address into the Threat intel lookup. Clean and"
             " unflagged is the end of the story 99 times out of 100."),
            ("Match it to what you were doing",
             "New app installed? New site visited? The timing usually"
             " explains it."),
            ("Only worry in combination",
             "A new address alone is nothing. A new address plus"
             " beaconing, plus odd ports -- that's a case, and the case"
             " page will show you all of it together."),
        ],
        "escalate": ("A new external IP only needs escalating when the"
                     " intel lookup flags it or it's part of a bigger"
                     " pattern -- then use the case's Escalate button so"
                     " the whole pattern goes up together."),
    },
    "new-busy-domain": {
        "found": [
            "A domain name nobody on your network had looked up before"
            " suddenly got lots of lookups. The usual cause is aggressively"
            " ad-loaded pages -- one news site can fire off hundreds of"
            " tracker domains. The unusual cause is malware cycling through"
            " generated names looking for its controller.",
        ],
        "do": [
            ("Check the domain itself",
             "Does the name look like a real company or service? Ad and"
             " analytics domains have recognizable owners. Random-looking"
             " strings of letters are the ones to squint at."),
            ("Match it to browsing",
             "Did the burst line up with someone browsing? Then it's"
             " almost certainly page junk."),
            ("Look it up in Threat intel",
             "Flagged means it graduates to the malicious-contact guide"
             " -- work that one instead."),
            ("If it persists with no browser open, scan",
             "Background domain-churn with everything closed is the"
             " pattern that matters. Full Defender scan on the device."),
        ],
        "escalate": ("Persistent gibberish domains, or a flagged domain"
                     " with ongoing lookups, are worth an admin's time."),
    },
    "brute-force": {
        "found": [
            "Repeated failed logins hammered one of your computers -- the"
            " digital equivalent of someone trying every key on your front"
            " door. This comes from the computer's own logs, correlated"
            " with what the network saw.",
            "Sometimes it's you fat-fingering a password, or a phone with"
            " an old saved password retrying forever. Sometimes it's an"
            " attack. The pattern tells you which.",
        ],
        "do": [
            ("Check if it was you",
             "Changed a password recently? Old phone or tablet with the"
             " old one saved will hammer away forever. Update it and the"
             " noise stops."),
            ("Look at the source",
             "Failed logins from inside your network point at a device --"
             " find it. From outside, they point at something you exposed"
             " (check the Attack surface page)."),
            ("The scary question: did any succeed?",
             "Failures are noise; a success after failures is a break-in."
             " Check the computer's logon logs for successes in the same"
             " window. If you find one, skip to escalate."),
            ("Lock down remote access",
             "Remote Desktop (port 3389) should never face the internet."
             " Strong, unique passwords everywhere -- password reuse is"
             " what makes brute force work."),
            ("Watch for the same source trying other machines",
             "One machine probed is an attempt. Several is a campaign."),
        ],
        "escalate": ("Any successful login mixed in with the failures is"
                     " an escalate-immediately situation -- say so first"
                     " thing in the escalation. Otherwise, persistent"
                     " attacks from outside deserve admin attention for"
                     " blocking."),
    },
    "usb-drive": {
        "found": [
            "A USB drive was plugged into a monitored computer. If it was"
            " you, this is just the monitor doing its job -- carry on.",
            "If it wasn't you, pay attention: planted USB drives ('USB"
            " drops') are one of the oldest tricks for getting malware"
            " into a network. Curiosity does the rest.",
        ],
        "do": [
            ("Was it you or someone in the house?",
             "Ask. The honest answer ends most of these."),
            ("If it's unknown, don't open it yet",
             "Scan it first: Windows Security can scan removable drives."
             " Let the scan finish before opening anything on it."),
            ("Check what the computer did afterward",
             "The case timeline shows whether anything odd followed the"
             " plug-in -- new programs, network weirdness."),
            ("Found drives stay found",
             "A USB stick in the parking lot is not a gift. Hand"
             " mystery drives to your admin instead of plugging them in."),
        ],
        "escalate": ("An unknown drive plus anything odd afterward --"
                     " Defender findings, new programs, strange traffic --"
                     " goes straight up to the admin."),
    },
    "defender-detection": {
        "found": [
            "Windows Defender -- the antivirus built into Windows --"
            " flagged or removed something on one of your computers. That's"
            " Defender doing its job, and most of the time the story ends"
            " there.",
            "The monitor flags it so you can confirm the job actually got"
            " finished, because 'detected' and 'removed' are two different"
            " things.",
        ],
        "do": [
            ("See what Defender found",
             "On that computer: Windows Security, 'Virus & threat"
             " protection', 'Protection history'. It names the threat and"
             " says what it did about it."),
            ("Make sure it finished the job",
             "You want 'Removed' or 'Quarantined'. 'Allowed' or anything"
             " pending needs your decision -- when in doubt, remove."),
            ("Run a full scan",
             "Quick scans catch the obvious; a full scan catches what came"
             " with it. Let it finish."),
            ("Think about where it came from",
             "Email attachment? Sketchy download? USB drive? The source"
             " tells you what habit to fix."),
            ("If it keeps coming back, isolate the machine",
             "Recurring detections mean something is reinstalling it. The"
             " Isolate button on the Devices page cuts it off while you"
             " get help."),
        ],
        "escalate": ("Detections that keep returning after removal, or a"
                     " detection paired with the monitor's own alerts"
                     " (beaconing, odd traffic) from the same machine,"
                     " should go to your admin -- that's the combination"
                     " the host-compromise guide covers."),
    },
    "host-compromise": {
        "found": [
            "This is the serious one, so let's be precise: endpoint"
            " protection flagged something on a computer AND the network"
            " saw that same computer talking suspiciously (for example,"
            " rhythmic check-ins with a shady address). Either one alone"
            " might be noise. Together, they mean the machine is probably"
            " compromised -- someone else is using it.",
            "Stay calm. This is fixable, and there's a clear order to do"
            " things in.",
        ],
        "do": [
            ("Isolate the machine NOW",
             "Devices page, Isolate button, confirm. This cuts it off from"
             " the internet. Do this before anything else -- every minute"
             " connected is a minute it can phone home."),
            ("Don't do sensitive stuff on it",
             "No banking, no shopping, no password changes from that"
             " machine. Assume anything typed there is seen."),
            ("Change important passwords from a clean device",
             "Phone or another computer: email first (it's the key to"
             " everything else), then banking, then the rest."),
            ("Let the antivirus finish, then scan fully",
             "Whatever Defender found -- let it remove or quarantine it,"
             " then run a full scan."),
            ("Check your other devices",
             "One compromised machine sometimes means the attacker looked"
             " around. Skim the Cases page for anything involving your"
             " other devices."),
            ("When it's clean, bring it back",
             "Release button on the Devices page. Watch it for a few days"
             " -- the monitor will tell you if the behavior returns."),
        ],
        "escalate": ("This is the number-one reason the Escalate button"
                     " exists. Isolate first, then escalate the case with"
                     " everything attached -- your admin handles the hard"
                     " 5%, and this is it."),
    },
    "self-drift": {
        "found": [
            "Something changed on the computer running the monitor itself:"
            " a new program listening on the network, a new background"
            " service, or a new startup entry versus the learned baseline.",
            "If you installed or updated software recently, that's almost"
            " certainly it. If you didn't touch the box, it's worth a"
            " look -- the watcher watching itself is the one alert you"
            " don't ignore.",
        ],
        "do": [
            ("Did you install or update anything?",
             "New software, a Windows update, a driver -- all of these"
             " legitimately change what the box looks like. Match the"
             " timing."),
            ("Identify the new listener or service",
             "The alert names it. Search the name -- legitimate Windows"
             " components and known apps explain themselves quickly."),
            ("Run a Defender scan on the box",
             "Full scan. The monitor is only as trustworthy as the box"
             " it runs on."),
            ("If it's legitimate, the baseline relearns",
             "The self-check learns the new normal. One alert, then"
             " quiet -- that's the system working."),
        ],
        "escalate": ("A change you can't attribute to anything you did,"
                     " on the box that watches everything else, is worth"
                     " an admin's eyes sooner rather than later."),
    },
    "amass-new-asset": {
        "found": [
            "A new subdomain or address belonging to your domain showed up"
            " on the public internet. The monitor maps what the internet"
            " sees of your domains, and this one wasn't there last time"
            " it looked.",
            "Attackers do this same reconnaissance before they pick"
            " targets -- so you want to see your public face before they"
            " do.",
        ],
        "do": [
            ("Is it yours and intentional?",
             "Did you (or your web person) spin up something new -- a"
             " test site, a new service, a migrated host? That's the"
             " common case."),
            ("If yes, make sure it should be public",
             "Test and staging sites have a habit of being internet-"
             " visible with default passwords. If the world shouldn't see"
             " it, restrict it."),
            ("If no, check your DNS",
             "Log into wherever your domain's DNS lives (your registrar"
             " or DNS provider) and look for records you didn't create."),
            ("Remove what shouldn't be there",
             "Delete rogue DNS records. If you didn't create them,"
             " assume the DNS account itself needs its password changed"
             " and a review."),
        ],
        "escalate": ("DNS records you didn't create are an escalate-now --"
                     " they can mean a compromised registrar account, and"
                     " that's admin work."),
    },
    "known-exploited-software": {
        "found": [
            "Something installed on the computer running the monitor"
            " matches CISA's known-exploited list -- security flaws that"
            " attackers are actively using in the real world right now,"
            " not just in theory.",
            "This is not proof anything is hacked. The list names"
            " products, not fixed versions -- you may already be patched."
            " But it's the shortest list in security worth taking"
            " seriously, so it's worth the ten minutes to check.",
        ],
        "do": [
            ("Update the named program",
             "The alert names the program. Update it however it was"
             " installed: Windows Update, the app's own updater, or pip"
             " for Python packages. 'Latest version' is the whole fix"
             " for most of these."),
            ("Restart it if the updater asks",
             "Some updates only take effect after a restart. If the"
             " updater suggests one, do it."),
            ("Check the CVE if you want the details",
             "The alert carries the CVE id (like CVE-2024-1234). Search"
             " it to see exactly what the flaw does -- useful if you're"
             " deciding how urgent the update is."),
            ("Confirm the match is gone",
             "The software check runs daily. Once you're patched, the"
             " match clears on its own and stays quiet."),
        ],
        "escalate": ("If the program can't be updated -- old software the"
                     " business depends on, a vendor that stopped patching"
                     " -- that's the conversation to have with your admin:"
                     " isolate it, replace it, or accept the risk on"
                     " purpose."),
    },
}


def get_guide(slug):
    """The full guide dict for a slug, or None when there isn't one yet.

    Unknown-but-well-formed slugs keep rendering the dashboard's friendly
    placeholder -- get_guide returning None is the signal for that.
    """
    if not slug:
        return None
    return GUIDES.get(str(slug))
