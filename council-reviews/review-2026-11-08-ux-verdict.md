# Council review 2026-11-08 — PLAIN-LANGUAGE UX verdict (brutedash / Project Orion)

Reviewer lens ONLY: Demetrius's product bar — would a non-technical home / small-business user understand every screen, banner, alert, and button? Product vision: small-business / home owner, plain-English, casual non-technical copy; the doctor metaphor is internal only, never user-facing.

Scope read in full at HEAD `75ffce6` (main, up to date with origin/main): `netmon/dashboard.py` (4301 lines — all rendered HTML, banners, buttons, help text), `app.py`, `netmon/explainer.py`, `netmon/notify.py`, `netmon/reporting.py`, `netmon/playbooks.py`, `netmon/escalate.py`, `netmon/amass.py`, `netmon/nuclei.py`, `README.md` user-facing sections, `templates/` (repo-root `templates/` holds scanner check YAML — `README.md`, `docker-api.yaml`, `elasticsearch.yaml`, `memcached.yaml`, `mqtt.yaml` — not pages; the dashboard has no HTML template files, all pages are inline in `dashboard.py` / `app.py`).

Headline fact for synthesis: **zero user-facing copy changed between the 2026-11-01 HEAD (`af51f64`) and today (`75ffce6`).** `git diff af51f64..HEAD -- netmon/dashboard.py app.py` touches only the `/api/health` gate, owner-gating on compliance downloads, rewind-export streaming, pcap unlink guards, a DB timeout, and a sample-read cap — no wording. Every 2026-11-01 UX item below was therefore re-checked line-by-line and is marked STILL PRESENT, with current line numbers (lines after ~3859 shifted +~41 from the rewind-streaming insert). One genuinely new finding was found (U9).

## Overall verdict: NEEDS WORK

No Critical findings. Nothing actively misleads a user into thinking they are safe when they are not — except the pcap garbage-file half of U6, which comes closest (a file that could not be read is presented as a clean 0-packet result). Two High dead-ends from three cycles ago are unchanged.

---

## High

### U1 — [High] STILL PRESENT — Non-technical users are dead-ended at "edit config.yaml" in 15 user-facing places (prior H1, cycles 2026-10-11 / 10-18 / 11-01, count grew 13+ → 15 rendered strings)

Current wording, verified at `75ffce6`:

- Sign-in page, `netmon/dashboard.py:410-412`: `Viewer sign-in isn't set up on this box -- use the owner password. (The owner can add a read-only viewer password under auth.viewer_password in config.yaml.)`
- `netmon/dashboard.py:868`: `Change the timing in config.yaml under alerts → digest_hours (0 turns it off).`
- `netmon/dashboard.py:872`: `Change the windows in config.yaml under retention (0 disables pruning for that type).`
- `netmon/dashboard.py:1767`: `Forensic rewind is off. Turn it on in config.yaml under reporting → rewind_enabled…`
- `netmon/dashboard.py:1948-1950`: `Amass is installed, but the external scan is switched off. Turn it on in config.yaml under amass → enabled…`
- `netmon/dashboard.py:1953-1954`: `No domains configured. Add the domain name(s) you own in config.yaml under amass → domains…`
- `netmon/dashboard.py:2064`: `Turn on the weekly deeper scan in config.yaml under nuclei → enabled, or run one now.`
- `netmon/dashboard.py:2102`: `Not set up yet -- point the monitor at your exported Windows logs in config.yaml under ingest → watch_dir (see INGEST.md for the export steps).`
- `netmon/dashboard.py:2164`: `Tripwire is off -- switch it on in config.yaml under canary → enabled.`
- `netmon/dashboard.py:2180`: `Turn on the installed-software check in config.yaml under swaudit → enabled…`
- Every fix-it guide, `netmon/dashboard.py:2913-2919`: `…add your administrator's email in config.yaml under response → admin_email first.`
- AI-off message (Ask page + triage), `netmon/dashboard.py:3912-3915`: `AI answers are off -- to turn them on, set your OpenAI API key as OPENAI_API_KEY and ai.provider in config.yaml.`
- The message the Escalate button actually returns, `netmon/escalate.py:36-40`: `No admin email is configured yet. Set response.admin_email in config.yaml (or the BRUTEDASH_RESPONSE_ADMIN_EMAIL environment variable) to your administrator's address, restart the dashboard, then escalate again.` Second copy at `netmon/escalate.py:218-220`: `Fix response.admin_email in config.yaml and try again.`
- API responses rendered verbatim next to the "Run scan now" button by `startAmass()` (`netmon/dashboard.py:1996-1998`): `netmon/dashboard.py:2840`: `"note": "amass.enabled is off in config.yaml"`; `netmon/dashboard.py:2843`: `"error": "amass binary not installed"`; `netmon/dashboard.py:2846-2848`: `"note": "no domains configured under amass.domains"`.

Why a home user fails here: they do not know what YAML is, where the file lives, or what an environment variable is; one typo silently breaks the file. There is still no Settings field for the admin email and no Settings toggle for any named feature — verified: no admin-email input exists anywhere in Settings. Escalate (U5) remains unusable end-to-end for this user: click → error → hand-edit a file → restart.

Concrete fix: Minimum viable: an "Administrator email" field in Settings (owner-only, writes the config) so Escalate works in the UI, plus on/off toggles in Settings for rewind, tripwire, software check, deeper scan, and outside view. Until a control exists, reword every dead-end to name a person, not a file: `Ask whoever set up this monitor to add an administrator email in the setup file, then try again.` Never show `BRUTEDASH_RESPONSE_ADMIN_EMAIL`, `OPENAI_API_KEY`, `auth.viewer_password`, or dotted keys like `response.admin_email` as the primary instruction.

### U2 — [High] STILL PRESENT — `app.py` demo front door is technician-only end to end (prior H2)

Current wording, verified at `75ffce6` (line numbers shifted +3 by the L7 comment block; copy identical):

- `app.py:334`: `<h1>brutedash — mini SOC analyst</h1>`; `app.py:335`: `Paste an SSH auth log below, hit Analyze.` The form is pre-filled with the whole raw sample log in monospace dark-terminal styling (`app.py` `STYLE` + `INDEX_HTML`) — a wall of log lines is literally the first screen.
- Results, `app.py:346`: columns `IP / Failed attempts / Severity`; `app.py:350`: `repeat attacker` tag; `app.py:355`: `Generate brief` button — "brief" is never explained. Severity renders the raw words `Medium`/`High`, not the dashboard's plain `Needs attention`/`Worth a look`.
- Brief page, `app.py:374-376`: `Technical brief: {{ ip }}`, `origin: {{ origin }}` (literally `llm` or `rule-based`), then a `<pre>` block headed `Observed pattern:` / `Recommended actions:`.
- Rule-based brief itself, `app.py:182-186`: `Consistent with a brute-force attack.` and actions `Block the IP at the firewall (or fail2ban).` / `Review and rotate credentials on targeted accounts.`
- `README.md:3` repeats the pitch to the same reader: `A mini SOC analyst for a home network`.

Why a home user fails here: SOC, SSH, auth log, IP, fail2ban, firewall, rotate credentials, llm — none of it is translated, and none of it matches the netmon dashboard's vocabulary for the same ideas. A home user landing on the repo's public front door cannot say what the tool did or what to do next.

Concrete fix: Heading `brutedash — who tried to break in, in plain English`; intro `Paste a sign-in log from a computer (the kind that records failed SSH sign-ins) below, then hit Analyze. The sample log is already filled in — just hit Analyze to see it work.` Results columns: `Address / Failed sign-ins / How serious` with the dashboard's severity words. Button `Explain this one`; brief heading `What happened: <address>`; drop the `origin:` line entirely (or `Written by the AI` / `Written by the monitor`); rewrite fallback actions as: `Block this address in your router or firewall settings.` / `Check whether any sign-in from this address ever succeeded.` / `Change the passwords on the accounts it tried.`

---

## Medium

### U3 — [Medium] STILL PRESENT — Bare MITRE codes as badges, hover-only jargon tooltip (prior M3)

Current wording: `netmon/dashboard.py:1053` (main alert list) and `netmon/dashboard.py:1660` (case timeline): a badge whose entire visible text is the code (e.g. `T1046`), with tooltip `Application Layer Protocol: Web Protocols — tactic: Command and Control` (pattern: `title="${mitre_name} — tactic: ${mitre_tactic}"`). Downloads copy repeats it at `netmon/dashboard.py:803`: `incidents with MITRE tags, what you did about them…`.

Why a home user fails here: a code with no words is decoration to them, tooltips do not exist on touch devices, and the tooltip "translation" is itself jargon. Nothing on the page ever says what MITRE is or why the code is shown.

Concrete fix: badge text becomes the plain label, code demoted: `Known attacker trick · T1046`; keep the bare code only inside the compliance download, where a technical reader (insurer/auditor) actually wants it, and change `:803` to `a record of what happened, what you did about it, alert counts, and your score history.`

### U4 — [Medium] STILL PRESENT — Tool brand names (Amass / Nuclei) unexplained; "not installed" notes order the user to run developer commands (prior M4)

Current wording:

- `netmon/dashboard.py:702`: `What the internet sees is the outside view (via Amass, optional)`; `netmon/dashboard.py:778-779`: heading `Deeper check (Nuclei)` and `Nuclei runs thousands of known vulnerability checks…`.
- `netmon/amass.py:136-141` (rendered verbatim by `renderAmass`, `netmon/dashboard.py:1944`): `Amass is not installed -- it is optional. Install it to map what the internet sees of your domain(s): go install github.com/owasp-amass/amass/v4/...@latest (needs Go), or on Kali sudo apt install amass. Then list your own domain(s) under amass.domains in config.yaml.`
- `netmon/nuclei.py:127-132` (rendered verbatim at `netmon/dashboard.py:2055`, and also returned as the error when "Run deeper scan" is clicked, via `netmon/dashboard.py:3015-3017`): `Nuclei is not installed -- it is optional. Install it for deeper vulnerability checks of your own network: download the release for your system from github.com/projectdiscovery/nuclei/releases and put the binary on your PATH (or go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest).`
- When found, both leak a raw file path: `netmon/amass.py:133-134` / `netmon/nuclei.py:124-125`: `Amass found … at /home/…/amass` — a log line, not a sentence.

Why a home user fails here: "Amass" and "Nuclei" are names, not explanations — the user cannot tell what either does, whether it is safe, or whether they need it. The fallback then asks the least technical user in the product to use a terminal, Go, Kali, apt, and PATH editing. This remains the most technical paragraph in the product.

Concrete fix: headings/copy name the job, not the tool: `What the internet sees (a check of public records about your domain name, optional)`; `Deeper check (a free scanner that tests for known flaws)`. Missing-tool note becomes: `The outside-view check isn't set up on this box. It's optional — everything else keeps working. Whoever installed the monitor can add it later.` Delete the go/apt/PATH instructions from user-facing notes entirely (they belong in INSTALL.md); drop the binary path from the "found" note.

### U5 — [Medium] STILL PRESENT — "Escalate to admin" assumes an administrator the home user doesn't have (prior M5)

Current wording: button `escalate to admin` (lowercase, unlike neighbouring `close case`) at `netmon/dashboard.py:1632`; badge `awaiting admin` at `netmon/dashboard.py:1628` and `:1656` (`escalated to <email> · <when>`); confirm dialog at `netmon/dashboard.py:1692-1694`: `Escalate "<title>" to your administrator? … emails it to the admin address in your config. The case will show as "awaiting admin" until it is closed.` Playbook version `Escalate to admin` at `netmon/dashboard.py:2915`. The underlying playbook text in `netmon/playbooks.py` repeats "your admin" / "hand it to your admin" throughout its `escalate` paragraphs (e.g. `:134`, `:168`, `:202`).

Why a home user fails here: in the target install the owner IS the only person. Who is "your administrator"? Where does the email go? The UI never says — and by default no admin address exists (U1), so the feature reads as sending their problem to an unnamed third party. "In your config" names no place the user can picture.

Concrete fix: button `Email this case to my helper`; badge `Emailed — waiting for a reply`; confirm: `This sends the whole case — timeline, what was found, what you already tried — to the helper email address in Settings. The case stays marked as waiting until you close it.` Pair with U1's Settings field so the address is visible where the button lives.

### U6 — [Medium] STILL PRESENT — "pcap", "Wireshark" and "forensic" used as if the user already speaks capture files; garbage file still gets a clean-looking results page instead of plain "couldn't read that" (prior M6 + the copy half staged with robustness M2 in the 2026-11-01 synthesis)

Current wording:

- Footer link `Analyze a pcap file` (`netmon/dashboard.py:904`); page heading/intro `netmon/dashboard.py:2355-2357`: `Analyze a pcap file` / `Upload a .pcap (e.g. exported from Wireshark). It runs through the same pipeline: flows, detection rules, and a plain-English AI explanation.`
- Results heading `netmon/dashboard.py:2367-2368`: `pcap results: <filename>` with `<n> packets processed.`
- Case-timeline link `netmon/dashboard.py:1668`: `download packets from this case's window (.pcap)` + `raw packets from the forensic buffer -- opens in Wireshark`.
- Reports heading `netmon/dashboard.py:813`: `Forensic rewind` with only a `Loading...` box under it — the plain explanation exists only inside the JS off-state message (`netmon/dashboard.py:1767`), so a user with the feature ON never sees any explanation, just segment counts and megabytes (`netmon/dashboard.py:1773-1775` also offers `download the last hour (.pcap)`).
- Garbage-file flow, unchanged: `netmon/capture.py` `run_pcap` now swallows the read failure and returns an empty aggregator (robustness fix landed), but the route at `netmon/dashboard.py:4295-4296` renders `PCAP_RESULT_HTML` unconditionally with `packets=agg.packets_seen`. A text file renamed `.pcap` therefore produces `0 packets processed.`, an "AI explanation", and `No alerts fired on this capture.` (`netmon/dashboard.py:2383`) — indistinguishable from a genuinely empty, clean recording.

Why a home user fails here: nothing ever says what a pcap is, where one comes from, or why a home user would have one. "Forensic" is investigator jargon. Worse, the garbage-file case actively mis reassures: "couldn't read that file" and "I read it and found nothing" are opposite facts presented identically.

Concrete fix: heading/link `Look at a saved traffic recording`; intro `If another tool (like Wireshark) saved a recording of network traffic as a .pcap file, upload it here and the monitor will explain what was happening in plain English.` Case link: `download the recording from this case's time window (for a technical helper to open)`. Results: `What the recording shows: <filename>` / `<n> packets looked at.` Rename `:813` to `Traffic recording` and add a static line under it, always rendered: `Keeps a short rolling recording of traffic so you can download what happened just before an alert. It stays on this box.` For the garbage case: if `packets_seen == 0` and the reader stopped early (or the file yielded nothing readable), render instead: `We couldn't read that file. It doesn't look like a traffic recording — check you picked the right file and try again.` Do not show the alerts/summary sections in that case.

### U7 — [Medium] STILL PRESENT, evidence widened — The same severity and the same state get two or three different vocabularies depending on the panel (prior M7)

Current wording:

- Main alert list translates severity — `[Needs attention] <title>` via `SEV_WORDS` (`netmon/dashboard.py:918`, rendered `:1050`) — but device alert history (`netmon/dashboard.py:1273`), threat-intel lookup results (`netmon/dashboard.py:1383`), case timelines (`netmon/dashboard.py:1659`), and the pcap results page (`netmon/dashboard.py:2378`) all render the raw word: `[High] <title>`.
- NEW evidence, same screen: the Urgency filter directly above the translated list still offers the raw words — `netmon/dashboard.py:691-693`: `<option value="Critical">Critical</option><option value="High">High</option>…` — so the user must map `High` (filter) to `Needs attention` (card) themselves.
- NEW evidence: attack-surface badges bypass `SEV_WORDS` too — `sevBadge()` at `netmon/dashboard.py:1841-1843` renders the raw severity, and the Nuclei findings table does the same at `netmon/dashboard.py:2068`.
- NEW evidence: the digest email does the same — `netmon/notify.py:543`: `- [High] <title>` — while the dashboard card for the identical alert says `[Needs attention]`.
- State vocabulary, unchanged: every main-list alert carries a raw status chip `[new]` / `[acknowledged]` / `[dismissed]` (`netmon/dashboard.py:1052`), while the button that sets it says `Mark seen` (`:1065`), the filter above the list says `Acknowledged` (`:688`), and the Settings rule-health table heads a column `Acknowledged` (`:1486`) — three names for one state on one screen.

Why a home user fails here: the plain severity words were the fix that made the main list readable; six other render paths quietly kept the old vocabulary, so the user must learn both and guess they are the same thing. `[acknowledged]` in brackets reads like a system code, not a state a person chose.

Concrete fix: use `SEV_WORDS` in all render paths, including the Urgency filter labels, `sevBadge()`, the Nuclei table, and the digest email. Replace the status chip with words matching the buttons: `Not seen yet` / `Seen` / `Dismissed` — or drop the chip when the status is new and show only `Seen`/`Dismissed`.

### U8 — [Medium] STILL PRESENT — "Probation" device badge is never explained anywhere (prior M8)

Current wording: banner over the Devices table, `netmon/dashboard.py:1213`: `🟡 N devices on 24h probation watch`, and per-device badge, `netmon/dashboard.py:1218`: `🟡 Probation · trusted in 13.5h` (opposite `✅ Trusted`). The only note on the Devices section (`netmon/dashboard.py:755`) says `Name your devices so alerts read like English instead of hardware addresses.` — it never mentions probation.

Why a home user fails here: "probation" is a word from the criminal-justice system applied to the user's own TV or phone, with no sentence anywhere saying what the device did (nothing — it is simply new), what changes while it lasts, or what "trusted in 13.5h" will mean when it ends. A new user meets this badge on day one, for every device they own.

Concrete fix: badge `🟡 New — being watched closely for the first 24h`; banner `N new devices — the monitor watches new devices extra closely for their first 24 hours.` Add one static line under the Devices heading: `New devices are watched extra closely for their first 24 hours while the monitor learns what's normal for them. Nothing is blocked — it's just watching.`

### U9 — [Medium] NEW — A device the user cut off from the internet still shows "✅ Trusted", with no status indication it is isolated

Current wording/behaviour, verified at `75ffce6`: the Devices table Status cell is computed solely from probation — `netmon/dashboard.py:1217-1219`: `const status = v.on_probation ? …Probation… : ✅ Trusted` — and never consults `v.quarantined`. The only sign a device is isolated is that its action button flips from `Isolate` to `Release` (`netmon/dashboard.py:1227`). The confirm dialog itself is plain and good (`netmon/dashboard.py:1782-1788`: `This cuts the device off from the internet… Undo any time: click Release…`), but after confirming, the row looks identical to every other trusted device.

Why a home user fails here: isolating a device is the strongest action in the product. Hours later the user — or a family member — has no way to tell from the Status column why that device has no internet, and "Trusted" actively says the opposite of the device's real state. This is a state-vocabulary failure of the same class as U7, but for a state the user deliberately created.

Concrete fix: Status cell shows isolation first: if `v.quarantined`, render `⛔ Cut off from the internet — click Release to bring it back` (badge warn/bad) ahead of / alongside the probation/trusted badge. Keep `Isolate`/`Release` button wording as-is.

---

## Low

### U10 — [Low] STILL PRESENT — `netmon/dashboard.py:1862`: `Warden's hit list — fix these first` (prior L9)

"Warden" is an internal system name that appears nowhere a user can learn it; "hit list" is the only violent metaphor in an otherwise calm UI. The note directly below (`Ranked like an attacker would rank them`) already explains the ranking. Fix: `<h4>Fix these first</h4>`, keep the existing note.

### U11 — [Low] STILL PRESENT — `netmon/dashboard.py:874`, `:872`, `:1599-1608`: "Prune now" — permanent deletion behind a jargon verb, one click, no confirmation (prior L10)

User sees Settings → Data retention button `Prune now`; while running `pruning...`; result `Done.` / `Prune failed: <error>`. `pruneNow()` fires immediately — no confirm dialog, unlike Isolate and Escalate, which both confirm. The panel's own explanation (`:872`) is about database mechanics (`deletes expired rows in small batches so the database never locks up`), not about what the user loses. Fix: button `Delete old data now`; confirm first: `Delete records older than the windows above? This can't be undone. Alerts on open cases are kept.` Result: `Old data deleted.` / `Nothing was old enough to delete.`

### U12 — [Low] STILL PRESENT — `netmon/dashboard.py:1059`, `:1662`: "Follow-up ID" is an unexplained hex string on every alert (prior L11)

User sees `Follow-up ID: 9f3ac41be207…` on every main-list alert and every timeline entry, with no hint what it is for. It looks like an error code or something the user must save, and it adds a line of noise to the highest-frequency surface in the product. Fix: label its purpose and truncate: `Reference code (only needed if you email this case to a helper): 9f3a…` — or remove it from the alert card and keep it only inside the case timeline.

### U13 — [Low] STILL PRESENT, one new site — Error banners paste programmer text and (mostly) give no next step (prior L12)

Pattern, ~12 sites, unchanged: the refresh banner `netmon/dashboard.py:1139-1141` does reassure (`Dashboard refresh hit a snag: <raw JS exception text> — the monitor keeps recording; this is a display hiccup. Retrying…`) but still pastes the exception; the loader failures do not even reassure: `Could not load assets: server returned 500`, `Could not load attack surface: …`, `Could not load external scan: …` — every loader builds its error from `throw new Error("server returned " + r.status)` (e.g. `netmon/dashboard.py:1206, :1252, :1291`, and peers throughout) and renders the message verbatim into a red banner. NEW site of the same class: the explainer's failure path is rendered as the summary body — `netmon/explainer.py:344-346`: headline `Summary unavailable`, body `The explainer hit an error: {e}.` with the raw exception interpolated, shown wherever the summary renders. Fix: one shared shape for every loader/summary failure: `Couldn't load <thing> just now — the monitor is still recording. This usually clears on its own; if it keeps happening, restart the monitor.` Log the exception to console/server log only, never into the banner.

### U14 — [Low] STILL PRESENT — Settings health tables still speak status-code, and scanner findings lead with slugs and CVE numbers (prior L13)

User sees: deeper-scan findings show a raw template slug + CVE string under each finding name (`netmon/dashboard.py:2068`: `<template_id> · CVE-2021-…`), with fallback text `See the finding name above.` when there is no description; self-check badges read raw `ok` / `drift` (`netmon/dashboard.py:2126`); pipeline-health badges read raw `ok` / `stale` / `unknown` (`netmon/dashboard.py:2150-2153`, `renderPipelineHealth`); software-check rows lead with `CVE-…` and `fix-by <date>` (`netmon/dashboard.py:2189`), and the section header line says `${sw.packages} programs inventoried, ${sw.kev_entries} known-exploited flaws on the list` (`netmon/dashboard.py:2184`). Fix: map badges to words at render: ok → `Fine`, drift → `Changed since first check`, stale → `Quiet too long`, unknown → `No data yet`. Demote template_id/CVE to small grey reference text after the plain description; replace the `See the finding name above.` fallback with `No plain description for this one yet — the name above is what the scanner calls it.`; `:2184` → `<n> programs checked, <n> flaws on the list of flaws attackers are actively using.`

### U15 — [Low] STILL PRESENT in all parts, one extension — Small jargon slips in the summary header, Ask page, briefing preview, emails, banner, nav, retention labels, and README (prior L14 a–h)

- (a) Summary header leaks its machinery: `netmon/dashboard.py:1074` renders `(<origin>, 15 min window)` where origin is literally `llm` or `rule-based` (values set in `netmon/explainer.py` — `origin = "rule-based"`, `origin = "llm"`); `netmon/dashboard.py:1193` repeats it (`Summary updated (llm).`); the pcap results page does the same at `netmon/dashboard.py:2370`. "llm" means nothing to the reader. Fix: `(written by the AI, last 15 minutes)` / `(written by the monitor, last 15 minutes)`.
- (b) Ask-your-network answers render inside a raw `<pre>` block, `netmon/dashboard.py:3954` (was `:3913`), so a friendly paragraph arrives looking like a code/log dump. EXTENSION, same defect: the morning-briefing preview does the identical thing at `netmon/dashboard.py:1742`: `"<pre>" + esc(d.body) + "</pre>"`. Fix both: render in a normal paragraph div with whitespace preserved via CSS, not `<pre>`.
- (c) The "alert emails aren't going out" alert tells the user to `Check your email settings (SMTP host, user, and password in the environment)` — `netmon/notify.py:356-357`. SMTP and "the environment" are both unknown terms, in the very message meant to unstick a non-technical owner. Fix: `Check the email settings the monitor was set up with (mail server, login, and password), then send a test from the dashboard's Email digest panel.`
- (d) Digest email subject, `netmon/notify.py:538-539`: `[netmon] Digest: 5 alerts across 3 kinds` — alerts do not come in "kinds" in any user-facing vocabulary. Fix: `…5 alerts of 3 different types`. (Body severity is covered in U7.)
- (e) Whole-network banner, `netmon/dashboard.py:673` and `:1014`: `Whole-network view: this computer is relaying the LAN, so every device's traffic is monitored.` "LAN" and "relaying" are unexplained, in a banner whose whole job is reassurance. Fix: `Whole-network view: this computer is passing along traffic for your whole home network, so every device is being watched.`
- (f) Top nav labels with no gloss, `netmon/dashboard.py:660-664`: `Attack surface`, `Threat intel`, `Assets`. The section headings below do gloss the first two, but a first-time user choosing where to click sees only the jargon. Fix: `Where you're exposed`, `Known-bad addresses`, `Devices seen` — or keep the short labels only if the headings stay glossed.
- (g) Threat-intel lookup details, `netmon/dashboard.py:1305` and `:1366-1376`: `AbuseIPDB scores are on (API key configured).` and a details line built from `abuse score 87/100`, a country, an ISP, `AS12345`, and `Reverse lookup: …` — the service name, "API key", "AS" numbers, and "reverse lookup" are all unexplained. Fix: heading `Outside reports about this address:` with `reported as abusive 87 times out of 100` style phrasing, and drop the AS number and "reverse lookup" label (show the name itself, unlabelled, or omit).
- (h) Retention table labels, `netmon/dashboard.py:1579-1581`: `DNS/ARP observations`, `Flow records`, `Score snapshots` — ARP is never expanded or explained anywhere user-facing. Fix: `Address lookups and network introductions`, `Traffic records`, `Score history`.
- (i) `README.md:3` still pitches `A mini SOC analyst`; `README.md:50` and `:173-174` still document the triage buttons as `Ack / Dismiss / AI verdict`, cycles after the UI renamed Ack to "Mark seen". Fix: gloss SOC once (`a mini security-operations (SOC) analyst — a watcher that explains what it sees`) and update the button names to `Mark seen / Dismiss / AI verdict`.

---

## Non-findings (checked and fine)

- Doctor metaphor: still absent from user-facing copy — full-repo search confirms the surviving phrasing is `A quiet network is a good sign -- nothing suspicious is going on.` (`netmon/reporting.py:340`, `netmon/reporting.py:524`, `netmon/dashboard.py:739` and peers). No `healthy network/device/box` string in product copy.
- Raw snake_case alert kinds in device/intel history: still fixed — both render paths use `kindLabel()` (`netmon/dashboard.py:1273, :1383`).
- Alert emails (`netmon/notify.py`, `build_email`): still the model for the bar — "What happened / What it means / Is this normal? / What to do", calm subject, safe fallbacks. Morning briefing (`netmon/reporting.py`) and weekly rollup likewise plain, apart from U15(d).
- Explainer port guide (`netmon/explainer.py` `PORT_GUIDE`) and the dashboard "What the numbers mean" panel: every port translated, no bare numbers.
- Playbooks (`netmon/playbooks.py`) step content and the "Here's what we found / what to do / When to escalate" structure: plain, numbered, calm — apart from the "your admin" framing (U5) and the config.yaml dead-end appended to every guide (U1).
- Stale-data, loop-down, and maintenance banners (`netmon/dashboard.py:967-1024` region): plain and reassuring — apart from the whole-network banner wording in U15(e).
- Isolate/Release confirm dialogs (`netmon/dashboard.py:1782-1799`): plain, reversible, with a clear undo — the defect is only that the resulting state is invisible afterwards (U9).
- Severity words on the main alert list (`SEV_WORDS`: Act now / Needs attention / Worth a look / Heads up) remain exactly right — U7 is that the other panels don't use them.
- No new screens or new user-facing copy were introduced since 2026-11-01 (verified by diff), so there is no new-copy regression to report beyond U9/U13/U15(b), which are new observations about pre-existing surfaces.
- `netmon/templates.py` and repo-root `templates/`: not page templates — scanner check definitions. No user-facing copy; nothing to flag.

VERDICT: NEEDS WORK
