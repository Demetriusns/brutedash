FINDINGS:
1. [High] netmon/dashboard.py:623, 1155, 1518, 1767, 1921, 1949 — "healthy" language in user-facing copy
   User sees: `<b>a quiet network is a healthy network.</b>` (:623); `No alerts ever involved this device. A quiet device is a healthy device.` (:1155); `No exposures found. A quiet network is a healthy network.` (:1767); plus :1518, :1921, :1949
   Why it fails the bar: Six spots use medical/health language — the standing voice rule says the doctor metaphor is internal-only and user-facing copy stays casual, plain-spoken, non-technical. "Healthy network" is exactly the doctor framing leaking into the UI.
   Concrete fix: Replace with plain phrasing, e.g. `A quiet network is a good sign -- nothing suspicious is going on.` and `A quiet device is fine -- nothing suspicious recorded.`

2. [High] netmon/dashboard.py:1153 — raw snake_case alert kind rendered in device alert history
   User sees: `<span class="note">${esc(a.ts)} &middot; ${esc(a.kind)}</span>` — the user literally sees `arp_spoof`, `dns_lookup_burst`, etc. next to the alert title
   Why it fails the bar: detection_catalog.py's title_for() contract says "the UI must never show raw snake_case kind ids," and kindLabel()/KIND_TITLES exist for exactly this — but this one render path bypasses it. A home user cannot decode `new_external_ip`.
   Concrete fix: `... &middot; ${kindLabel(esc(a.kind))}</span>` so it shows "First contact with a new outside address".

3. [Medium] netmon/dashboard.py:937, 1540 — raw MITRE IDs with hover-only, jargon-filled tooltips
   User sees: a badge reading `T1046` (etc.) next to every alert; tooltip on hover only: e.g. `Application Layer Protocol: Web Protocols — tactic: Command and Control`
   Why it fails the bar: The badge itself is untranslated for anyone who doesn't hover (useless on phones), and the tooltip "translation" is itself jargon — "Application Layer Protocol", "Command and Control" mean nothing to a home user. Flagged per the MITRE-IDs-with-no-translation rule.
   Concrete fix: Render the badge as plain text first, e.g. `<span class="badge mitre" title="...">Known attacker trick</span>` with the T-code as small secondary text, or link the badge to the matching playbook's "Here's what we found" section.

4. [Medium] netmon/dashboard.py:1742 — "Warden's hit list — fix these first"
   User sees: `<h4>Warden's hit list — fix these first</h4>`
   Why it fails the bar: "Warden" is an internal system name a home user has never heard, and "hit list" is hitman language — neither plain nor friendly. Who is Warden? What is a hit list?
   Concrete fix: `<h4>Fix these first</h4>` with the existing note ("Ranked like an attacker would rank them") kept below it.

5. [Medium] netmon/dashboard.py:586, 1824, 1828 — "Amass" named without any explanation
   User sees: `What the internet sees is the outside view (via Amass, optional)` (:586); `Amass is not installed.` (:1824); `Amass is installed, but the external scan is switched off.` (:1828)
   Why it fails the bar: "Amass" is an unexplained proper noun / tool name — a home user has no idea what it is or whether they want it.
   Concrete fix: `What the internet sees is the outside view (a public-records check on your domain name, optional)` and `The outside-view check isn't installed yet.`

6. [Medium] netmon/dashboard.py:2791, 1647, 751, 759, 2044 + netmon/escalate.py:36 — non-technical users told to edit config.yaml
   User sees: `add your administrator's email in config.yaml under response → admin_email first.` (:2791); `Turn it on in config.yaml under reporting → rewind_enabled` (:1647); `Change the timing in config.yaml under alerts → digest_hours` (:751); `Change the windows in config.yaml under retention` (:759); `switch it on in config.yaml under canary → enabled.` (:2044); escalate.py SETUP_HINT: `No admin email is configured yet. Set response.admin_email in config.yaml ... restart the dashboard, then escalate again.`
   Why it fails the bar: The product bar is a non-technical home user; five separate flows (escalation, rewind, digest timing, data retention, tripwire) all dead-end at "edit a YAML file and restart." A Settings panel exists but covers none of these.
   Concrete fix: Add "Administrator email" (and ideally the rewind/digest toggles) as fields in the Settings panel, or reword each dead-end to `In Settings, ...` — never send a home user into a YAML file.

7. [Medium] netmon/dashboard.py:661, 662 — "Nuclei" tool name without translation
   User sees: `<h3>Deeper check <span class="note">(Nuclei)</span> ...` (:661); `Nuclei runs thousands of known vulnerability checks against your own devices` (:662)
   Why it fails the bar: "Nuclei" is unexplained jargon; the user sees a brand name with no hint what it is or why it's safe to run.
   Concrete fix: `<h3>Deeper check <span class="note">(a free open-source scanner)</span>` and `The deeper check runs thousands of known-vulnerability tests against your own devices -- ...`

8. [Low] netmon/dashboard.py:697 — "Forensic rewind" heading unexplained until JS loads
   User sees: `<h3>Forensic rewind</h3>` — the section header itself never explains the feature; the plain explanation only appears inside the JS-rendered status box.
   Why it fails the bar: "Forensic" is jargon; a home user scanning the page won't know this is a recording feature.
   Concrete fix: Add a static note under the heading: `<p class="note">Keeps a short recording of traffic so you can review what happened before an alert.</p>` and rename heading to `Replay buffer` or `Traffic rewind`.

NON-FINDINGS (checked and fine):
- Alert meaning/what_to_do copy in netmon/detect.py (spot-checked arp_spoof, beaconing): genuinely plain — analogies, "What this means / Is this normal? / What to do" structure, every alert carries action guidance.
- Severity rendering: SEV_WORDS maps Critical/High/Medium/Low to "Act now / Needs attention / Worth a look / Heads up" (dashboard.py:802) — exactly the plain bar.
- Playbooks (netmon/playbooks.py): spot-checked — casual voice, numbered steps, "When to escalate" on every guide; PLAYBOOK_SLUGS blurbs in attacksurface.py are plain.
- Port guide (netmon/explainer.py PORT_GUIDE + dashboard "What the numbers mean" section): every port gets a plain-English translation, no bare numbers.
- Alert emails (netmon/notify.py build_email): "What happened / What it means / Is this normal? / What to do" with safe fallbacks when fields are missing; calm, non-alarming tone.

VERDICT: NEEDS WORK