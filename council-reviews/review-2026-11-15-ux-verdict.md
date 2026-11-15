# PLAIN-LANGUAGE UX Verdict — brutedash @ `481b417`

**Overall: NEEDS WORK. No Critical.** Verified against the 2026-11-08 verdict: `git diff 75ffce6..HEAD` changes **no user-facing copy** in `dashboard.py`/`app.py`/`templates.py`/`notify.py`/`playbooks.py`/`escalate.py`/`explainer.py` except one retention label (U10, below — a regression). Every prior finding U1–U9 is **STILL PRESENT, verbatim**. No doctor/medical metaphor anywhere — that rule still holds. `netmon/templates.py` is scanner-check definitions, not pages: nothing to flag.

## High

**U1 — STILL PRESENT — "edit config.yaml" dead-ends (15 rendered strings)**
`dashboard.py:412` (`auth.viewer_password` on the sign-in page), `:868` digest timing, `:872` retention, `:1768` rewind, `:1950/:1955` Amass off/no domains, `:2065` deeper scan, `:2103` Windows-log ingest, `:2165` Tripwire, `:2181` software check, `:2920` every fix-it guide, `:3913-3916` AI-off (`OPENAI_API_KEY` + `ai.provider`); `escalate.py:36-40,218-220` (incl. `BRUTEDASH_RESPONSE_ADMIN_EMAIL` + "restart the dashboard"); API notes rendered by the scan buttons, `dashboard.py:2841`.
*Confuses:* home user doesn't know YAML, where the file is, or what an env var is; Escalate is unusable end-to-end. Still no Settings field for admin email, no Settings toggle for any named feature.
*Fix:* Settings "Administrator email" field + on/off toggles for rewind/tripwire/software check/deeper scan/outside view. Until then: "Ask whoever set up this monitor to add an administrator email in the setup file, then try again." Never surface dotted keys or env-var names as the instruction.

**U2 — STILL PRESENT — `app.py` demo front door is technician-only**
`app.py:334` "brutedash — mini SOC analyst"; `:335` "Paste an SSH auth log below" over a pre-filled wall of raw log; results `:346-355` `IP / Failed attempts / Severity`, `repeat attacker`, unexplained `Generate brief`; brief `:374-376` "Technical brief", `origin: llm|rule-based`, `<pre>` block; fallback `app.py:182-186` "brute-force attack… Block the IP at the firewall (or fail2ban)… rotate credentials." `README.md:3` repeats "mini SOC analyst."
*Fix:* Heading "brutedash — who tried to break in, in plain English"; intro explaining the sample is pre-filled; columns "Address / Failed sign-ins / How serious" using dashboard severity words; button "Explain this one"; drop `origin:` (or "Written by the AI / by the monitor"); actions: "Block this address in your router or firewall settings / Check whether any sign-in from it ever succeeded / Change the passwords on the accounts it tried."

## Medium

**U3 — STILL PRESENT — Bare MITRE badges.** `dashboard.py:1053,1661`: visible text is only `T1046`; tooltip "… — tactic: Command and Control" is itself jargon and absent on touch. `:803` "incidents with MITRE tags…"
*Fix:* Badge "Known attacker trick · T1046"; bare code only in the compliance download; `:803` → "a record of what happened, what you did about it, alert counts, and your score history."

**U4 — STILL PRESENT — Scanner brand names + developer install orders.** `dashboard.py:702` "(via Amass, optional)", `:778-779` "Deeper check (Nuclei)"; rendered verbatim: `amass.py:137-141` "`go install github.com/owasp-amass/…` (needs Go), or on Kali `sudo apt install amass`"; `nuclei.py:128-132` "download the release… put the binary on your PATH (or `go install …`)"; both leak a raw binary path when found (`amass.py:134`, `nuclei.py:125`).
*Fix:* Name the job, not the tool: "What the internet sees (a check of public records about your domain name, optional)" / "Deeper check (a free scanner that tests for known flaws)". Missing-tool note: "The outside-view check isn't set up on this box. It's optional — everything else keeps working. Whoever installed the monitor can add it later." Install commands belong in INSTALL.md only.

**U5 — STILL PRESENT — "Escalate to admin" assumes an admin the owner doesn't have.** Button `dashboard.py:1633`, badge `awaiting admin` `:1629,1657`, confirm `:1693-1695` ("the admin address in your config"), playbook `:2916` and "your admin" throughout `playbooks.py` escalate text.
*Fix:* Button "Email this case to my helper"; badge "Emailed — waiting for a reply"; confirm: "This sends the whole case — timeline, what was found, what you already tried — to the helper email address in Settings. The case stays marked as waiting until you close it." (Depends on U1's Settings field.)

**U6 — STILL PRESENT — pcap/Wireshark/"forensic" unexplained; unreadable file still looks like a clean result.** Link `dashboard.py:904` "Analyze a pcap file"; page `:2356-2357`; results `:2368` "pcap results… packets processed"; case link `:1669` "raw packets from the forensic buffer — opens in Wireshark"; heading `:813` "Forensic rewind" (explanation only appears in the off-state message `:1768`). The `/pcap` route (`:4235-4301`) renders `PCAP_RESULT_HTML` unconditionally with `packets=agg.packets_seen` — a renamed text file still gets "0 packets processed" + "No alerts fired," indistinguishable from a genuinely clean recording. This is the closest item to misleading.
*Fix:* "Look at a saved traffic recording"; intro explaining a .pcap is a recording another tool (like Wireshark) saved; rename `:813` to "Traffic recording" with an always-visible line "Keeps a short rolling recording of traffic so you can download what happened just before an alert. It stays on this box." If nothing was readable, render only: "We couldn't read that file. It doesn't look like a traffic recording — check you picked the right file and try again."

**U7 — STILL PRESENT — Severity/state vocabulary split.** Main list translates via `SEV_WORDS` (`dashboard.py:918`, rendered `:1050`), but the Urgency filter directly above it offers raw `Critical/High/…` (`:691-692`), `sevBadge()` renders raw severity (`:1842-1844`), the Nuclei table does too (`:2068-2070`), device/intel/case/pcap paths render `[High]`, and the digest email does (`notify.py:~543` `- [High] …`) for the same alert the dashboard calls "Needs attention." State: raw chip `[acknowledged]` (`:1052`) vs button "Mark seen" vs filter "Acknowledged."
*Fix:* Use `SEV_WORDS` in every render path, filter labels, `sevBadge()`, Nuclei table, and digest email. Chip becomes "Not seen yet / Seen / Dismissed" (or drop it when new).

**U8 — STILL PRESENT — "Probation" badge never explained.** Banner `dashboard.py:1213` "N devices on 24h probation watch"; badge `:1218` "🟡 Probation · trusted in 13.5h". No sentence anywhere says the device did nothing wrong, is simply new, or that nothing is blocked.
*Fix:* Badge "🟡 New — being watched closely for the first 24h"; banner "N new devices — the monitor watches new devices extra closely for their first 24 hours"; static line under Devices: "New devices are watched extra closely for their first 24 hours while the monitor learns what's normal for them. Nothing is blocked — it's just watching."

**U9 — STILL PRESENT — Quarantined device still shows "✅ Trusted."** Status cell `dashboard.py:1217-1219` is computed only from `on_probation` and never consults `v.quarantined` (the data is already in the row — the button at `:1227` flips Isolate/Release). The strongest action in the product is invisible in the Status column hours later.
*Fix:* Isolation first: if quarantined, render "⛔ Cut off from the internet — click Release to bring it back" ahead of Trusted/Probation.

## Low — New

**U10 — NEW regression (only copy change since 2026-11-08) — Retention labels got *more* technical.** `dashboard.py:1579-1580`: "DNS/ARP observations" → "DNS/ARP/hostname observations", plus a new row "Windows host events" (R7's `host_events_days`). ARP and DHCP/mDNS-style terms are never explained; a home user cannot tell what is being kept or deleted.
*Fix:* "Address lookups and device names", "Windows security log entries", "Traffic records", "Score history" — plain labels for every row in that table.

*Note:* Prior Lows U10–U15 from 2026-11-08 (Warden's hit list `:1863`, "Prune now" `:874`, "Follow-up ID" `:1059/:1663`, raw-exception error banners, `llm`/`rule-based` origin leaks `:1074`, `<pre>` answers `:3955/:1743`, SMTP wording `notify.py:356`, "relaying the LAN" `:673/:1014`, nav labels `:660-661`) were spot-checked and are also still present unchanged.
