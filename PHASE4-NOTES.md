# brutedash roadmap — Phase 3.5 and Phase 4

Phase 3 shipped 2026-09-30. What's next, in order.

Items marked (new 2026-09-30) came out of the "top-notch automated SOC
analyst" review that night. Everything else was already on the roadmap.

---

## Continuous testing & council review (his directive, 2026-10-02)

"Treat it like family" means it gets checked constantly, not just built.

- **Test suite is the enforcement arm.** `tests/` (unittest, stdlib only,
  no new dependencies) covers secret-scrubbing of diagnostics bundles,
  relay detection, and config parsing. The daily build cron runs the full
  suite, plus py_compile, a dashboard smoke boot against a scratch DB,
  and a secret-scan of the staged diff. ALL GREEN or no commit; unfixable
  failures get reported to Demetrius instead of pushed.
- **Weekly council review** (Sundays): three independent reviewers --
  security, plain-language UX, robustness -- return structured verdicts
  (Critical/High/Medium/Low, file:line, concrete fix). The agent, as head
  of council, ships only on quorum: 2-of-3 agreement, or 1 Critical the
  head endorses. One focused batch per session, under Add → Test →
  Release.
- **The council is general-purpose**, not Orion-only: the same review
  pattern serves every project. External heavyweight models (DeepSeek V4,
  Kimi K2, Qwen3.5-max, GLM-5.2) plug into the council once their API
  keys are provided; until then the council runs as independent reviewer
  agents.

---

## Phase 3.5 — the true automated SOC analyst (Demetrius's call, 2026-09-30)

Goal: one system doing the job of a senior analyst for small companies —
detect, correlate, investigate, respond, and prove it. All on one box.

North star: the SOC analyst a 20-person company can't afford to hire.
A junior analyst costs ~$70k/year. This is a box plus a subscription.

### Design principles (his call, 2026-09-30)
- AI narrates, code decides. Deterministic detection fires alerts; the LLM
  explains them. Never let the model decide what's malicious — rules don't
  hallucinate, and every alert must be explainable.
- Response is approval-only. One-click contain from the dashboard, but a
  human clicks. No autonomous blocking — one false positive that kills the
  register on a busy Saturday ends the product.
- Don't build a SIEM. Splunk wins that fight. The wedge is dead simple,
  plain English, one box for shops that will never buy Splunk.
- One box that works beats three that kind of do. No multi-sensor/cloud
  until single-box is boring and reliable.
- Quiet is a feature. Every dismissal must make tomorrow quieter. A muted
  SOC is a paperweight.

### Priority order (his call, 2026-09-30)
1. Quiet-first: learning from dismissals, behavior profiles, device naming,
   quiet hours, digest emails.
2. Incidents, not alerts: grouping + timelines + incident pages.
3. Know the network: asset inventory, self vulnerability scans.
4. Rap sheets: threat intel enrichment on every external IP/domain.
5. Respond: per-device quarantine with approval, full playbooks.
6. See more: Windows Event Log + firewall log ingestion.
7. Prove it: briefings, score card, PDFs, compliance, forensic rewind.

### Stop crying wolf (priority 1)
- Learning from dismissals — tune thresholds and suggest allowlists from
  his triage feedback; stop crying wolf.
- Per-device behavior profiles — "this laptop never uploads 2GB at 3am"
  without hand-written rules. DONE 2026-10-02 (batch 3): per-MAC,
  per-hour baselines learned from 14 days of flows
  (`device_profiles` table: avg bytes + avg outside contacts per local
  hour); new `behavior_deviation` rule (Medium) fires only when a device
  moves >=4x its own baseline for the current hour AND clears a 250 MB
  floor, needs 3+ days behind the baseline hour, ignores devices <24h
  old (probation watch covers them), 24h cooldown per MAC; dashboard
  devices table shows a "Normal for this device" column ("~90 MB/hr ·
  busiest 6-7am · learned over 5d") via /api/devices profile summaries.
- Device naming (new 2026-09-30) — MAC → friendly-name table ("PS5",
  "Mom's iPhone") so alerts read like English instead of IP addresses.
  Trivial to build, huge readability win.
- Quiet hours / maintenance mode (new 2026-09-30) — "backups run 2–4am,
  don't page me about the traffic spike." Scheduled windows per alert type.
- Digest emails (new 2026-09-30) — one "3 things happened overnight"
  email, not 3 emails. Per-alert email stays for critical only.
- Alert fatigue circuit breaker (new 2026-09-30) — the same alert firing
  N times in an hour becomes one "this keeps happening" escalation, not
  N notifications.
- Per-rule precision tracking (new 2026-09-30) — show "this rule was right
  8 of its last 10 alerts" on the dashboard. Rules that cry wolf get tuned
  or retired.
- New-device probation (new 2026-09-30) — first-seen devices get watched
  closely for 24h, then trusted. A bouncer watching the new guy. DONE
  2026-10-01 (batch 2): 24h probation window derived from first_seen,
  `probation_watch` rule (Medium) fires when a probationary device moves
  >500 MB/hr, contacts 100+ outside addresses/hr, or uses unusual ports;
  dashboard devices page shows 🟡 Probation / ✅ Trusted badges with a
  "trusted in Nh" countdown and first-seen timestamps.

### Think like a senior (analysis)
- Incident grouping — bundle related alerts into one case with a timeline.
  Analysts think in incidents, not scattered alerts.
- Incident pages (new 2026-09-30) — click any alert → full case view:
  timeline, every related flow, raw packets, AI narrative. The
  investigation workspace.
- MITRE ATT&CK tagging — label every detection with the attacker's
  technique. Professional SOC language; strong resume signal.
- Canary / honeypot (new 2026-09-30) — plant a fake vulnerable-looking
  target (bogus open port or share); anything touching it is hostile by
  definition. Highest-signal detection there is, cheap to build.
- TLS fingerprinting (new 2026-09-30) — can't read HTTPS content, but
  JA3-style fingerprints spot malware command-and-control hiding inside
  encrypted traffic.
- New-country first contact (new 2026-09-30) — alert the first time the
  network talks to a country it's never talked to, not on every foreign IP.
- DoH awareness (new 2026-09-30) — flag DNS-over-HTTPS tunnels that bypass
  local DNS; the connection itself is the signal.

### Know the network (visibility)
- Asset inventory — auto-discover every device, OS, open ports. Can't spot
  abnormal without knowing normal per machine.
- Self vulnerability scan (new 2026-09-30) — weekly lightweight scan of his
  OWN network: "here are the open doors on your LAN." The analyst auditing,
  not just watching.
- Windows Event Log + firewall log ingestion — failed logins, new services,
  USB drives. Network-only is half the picture.
- Top talkers / "who's slowing my internet" (new 2026-09-30) — live
  per-device bandwidth view. Every small-business owner asks this; answer
  it in one glance.
- Internet uptime log (new 2026-09-30) — "down 4 times this week, 37
  minutes total" with timestamps. Evidence for the ISP call. (Outage
  detection already exists in Phase 3; productize the log.)

### Rap sheets (threat intel)
- Threat intel lookups — check external IPs/domains against blocklists;
  "known malicious scanner" on sight.
- Per-IP intel page (his call 2026-09-30): blocklist status/reason,
  abuse-confidence score, scanning/brute-force/phishing/malware/botnet
  behavior, country/city, ISP/hosting owner + ASN, associated domains,
  provider first-seen/last-seen, reverse DNS.
- Auto-updating feeds (new 2026-09-30) — pull community blocklists
  (AbuseIPDB, emerging-threats) on a schedule into a local table, not just
  on-demand lookup.
- Local device page (his call 2026-09-30): first seen, last seen, bytes
  sent/received, ports contacted, local device involved, full alert history.

### Act, not just watch (response)
- One-click contain — per-device quarantine (ARP-isolate a single device)
  from the dashboard, with his approval. Detection without response is a
  newsletter. (The 2026-09-30 kill-switch test was the prototype.)
- Full playbooks — step-by-step runbooks per alert type, beyond the tip line.

### Prove it (reporting)
- Daily morning briefing email — overnight summary, the SOC ritual.
- Security score card (new 2026-09-30) — one 0–100 grade for the network
  with "here's why" and "do this to improve." Non-technical owners
  understand a grade; insurers love it.
- Compliance-ready reports — auto-answer the cyber-insurance questionnaire.
- Forensic rewind — rolling raw-packet buffer for post-incident review.
- Exportable PDF reports (his call 2026-09-30) — weekly report and incident
  briefs as one-click PDFs; file it, email it, hand it to an insurer.
  Server-side generation (WeasyPrint/reportlab), brutedash header, readable
  tables.

### Run it like a product (new 2026-09-30)
- Data retention policy — rolling windows with automatic summarization
  (e.g. 90 days of flows, 1 year of incidents). SQLite grows forever
  otherwise.
- Sensor-down alerting — a SOC that silently dies is worse than none.
  Watchdog exists (Phase 3); add "haven't heard from the sensor" pages.
- Roles — owner vs. viewer logins. The IT guy sees everything; the business
  owner sees the briefing. (Dashboard login exists in Phase 3; extend it.)

### Dashboard polish (his call 2026-09-30)
- Visual refresh, traffic charts, mobile-friendly layout, smoother
  navigation, plain-English loading/empty states. Polish the look, not the
  reading level.

### AI backend (his ideas 2026-09-30, refreshed 2026-10-02)

Orion's AI has three jobs: narrate alerts in plain English, help triage,
and get smarter over time. The design principle stands: **AI narrates,
code decides** -- deterministic rules fire alerts; models explain them.

**Provider picks (his call 2026-10-02):**
1. **Google Gemini free tier first** -- most generous free API (~1,500
   req/day, no card), OpenAI-compatible endpoint, zero hardware questions.
2. **Self-hosted Qwen3 second** -- Apache 2.0, runs on a normal PC via
   Ollama (`ollama pull qwen3:8b`), zero cost forever, data never leaves
   the network. The long-term answer for customer sites.
3. Bench: Groq (fastest), Cerebras, OpenRouter (`:free` models, one key),
   GitHub Models, Mistral, DeepSeek. Open-weight frontier in 2026 is
   Qwen / DeepSeek / Kimi / GLM (all downloadable); Llama 4 has slipped.

**Keys:** one API key per provider, always as environment variables, never
in config or code. The config selects the active provider + model + base
URL, so swapping providers is a config change, not a rewrite. `ai_assist.py`
stays provider-agnostic (OpenAI-compatible interface).

**The night shift (his vision 2026-10-02):** when he's asleep/inactive,
Orion itself is the overnight agent -- it never sleeps, it runs on his PC.
Detect -> consult the model council -> act within his pre-approved
playbook -> notify him. He pre-approves *what the agent may do alone*
(e.g. quarantine a device beaconing to a known-malicious IP) and everything
else waits for morning review. Response stays approval-only by default;
autonomous actions are opt-in per playbook, never silent.

**Model council (his vision 2026-10-02):** for High/Critical or ambiguous
alerts, Orion asks 2-3 models at once (e.g. local Qwen3 + Gemini free tier
+ Groq) and compares verdicts. Agreement -> act per playbook. Disagreement
-> escalate to the human. Only alert metadata and flow summaries go out --
never packet contents, never PII (free tiers may train on prompts). Home
alert volume is a handful per day; free-tier rate limits are plenty.

**Constant learning:** every council verdict plus his morning review feeds
the dismissal-learning loop (Phase 3.5 priority 1: quiet-first). The system
gets smarter every night -- rules tuned, thresholds adjusted, new patterns
proposed by the council and approved by him. The nurse (the watching agent)
monitors the heartbeat, triages software bugs, and delivers the overnight
report each morning: what happened, what the agent did, what needs him.

**Escalation path:** critical -> push notification to his phone via the
Muse app (note: cannot override Do Not Disturb/silent mode) + email;
everything else -> morning briefing. If the heartbeat itself dies, the
nurse wakes and investigates.

---

## Phase 4 — expansion (planned, parked until Demetrius says go)

Keep improving the software first. The Pi phase starts only on his word.

- Raspberry Pi sensor(s) for whole-network monitoring.
- Pi likely too weak for local LLM — keep Pi as sensor, PC (or small box)
  as the AI server.
- Multi-site / central console if it ever goes beyond one network.
- Banner update when the Pi arrives (his call 2026-10-02): the dashboard
  banner currently keys off a *local* bettercap process. Once the Pi is
  the always-on relay, the banner must reflect the Pi's relay state
  instead (e.g. via the sensor API), not the viewing machine's.

### Buying the Pi (researched 2026-09-30)

- Recommended board: Raspberry Pi 5, 4GB — plenty for a capture sensor
  (capture + forward flows to the PC); no need for 8GB+ since the AI stays
  on the PC. Skip the 16GB (mini-PC money, overkill for a sensor).
- Pricing is inflated in 2026 (memory shortage): expect roughly $75-130
  street for the 4GB board, $175-200 for 8GB. Board-only price; budget
  another $30-50 for official power supply, case, and microSD card.
- Buy from Raspberry Pi Approved Resellers only (fair MSRP, genuine boards,
  valid warranty) — US options include Adafruit, SparkFun, CanaKit,
  Micro Center, Newark, DigiKey, PiShop.us. Avoid marketplace scalpers.
- Watch out: the 2GB Pi 5 has been out of stock at major retailers for
  weeks; the 1GB ($45) or Pi 4 are fallback options if 4GB is unavailable.
- Re-verify prices and stock when Phase 4 starts — this market moves fast.

---

## Phase 5 — cloud console for remote monitoring (his call, 2026-10-01;
expanded 2026-10-02: the central multi-monitor system)

The company version. Motivation, in his words: if we outsource this,
companies want their network monitored without being on the network.
And his bigger picture (2026-10-02): one center that watches many
systems at once -- every customer site is a monitor on the wall, and the
watching agent sees all of them.

Architecture flip: the dashboard stops living on the monitored box.
Instead, each client site runs a lightweight sensor that ships summaries
up to a central cloud server, and the dashboard lives in the cloud.

- **Sensor (client site):** capture + detection rules stay local — fast,
  private, works even if the uplink drops. Ships flow summaries, alerts,
  and metadata to the cloud over TLS. Raw packets never leave the site
  (privacy + bandwidth).
- **Cloud server:** multi-tenant console — one login sees every client
  site. Alerting, digest emails, and AI briefs run centrally.
- **Sensors dial out, never accept inbound.** Like a Cloudflare Tunnel:
  no port forwarding at client sites, no open doors. This is a security
  property, not just convenience -- a sensor that accepts inbound is a
  target, and Orion would flag it on anyone else's network.
- **One center, many monitors:** each site is a monitor card -- health,
  alert counts, traffic -- with drill-down per site. The site owner sees
  their site; the operator (Demetrius) sees all of them.
- **The nurse gets a badge:** the watching agent holds a read-only API
  role on the console. Scheduled checks poll site health + new critical
  alerts across every monitor, investigate, and notify. No inbound access
  to customer networks is ever needed -- the console is the single pane.
- **Security:** per-site API keys, TLS everywhere, password-gated
  console. The Flask dev server gets replaced by a production server
  (gunicorn/uvicorn behind a reverse proxy) before anything faces the
  internet.
- **Stepping stone first (parked per his call 2026-10-02):** Tailscale for
  his own remote access — phone views the home dashboard from anywhere
  over a private encrypted tunnel, no open ports, nothing internet-facing.
  Needs: free Tailscale account, app on the PC + phone, NETMON_PASSWORD
  set (non-negotiable off localhost), dashboard host bound to the tailnet
  (config knob `dashboard.host` exists since 2026-10-02). Mobile-friendly
  dashboard CSS shipped 2026-10-02. Build when he says go — proves the
  remote story on his own network before the product version.

### The council, expanded (his call 2026-10-02)

The triage council grows to the biggest and smartest openly-usable
models, tiered by cost and gravity. And per his directive the same
day: the council is a GENERAL capability, not an Orion-only one --
the agent heads it and consults it across all work (big decisions,
job hunt, analysis, coding), not just this project.

- **Everyday tier (local, always):** Qwen3 8B via Ollama on the sensor
  box -- private, free, instant. Handles routine narration and
  low-severity triage.
- **Heavyweight tier (API, High/Critical only):** the open-weight
  frontier -- DeepSeek V4, Kimi K2, Qwen3.5-max, GLM-5.2 -- consulted
  only when it matters. Home/small-business alert volume is a handful
  per day, so API cost stays near zero.
- **License rule for the product:** prefer Apache 2.0 / MIT models
  (Qwen, GLM, DeepSeek, Mistral) for anything shipped commercially.
  Kimi's weights are open but under a custom license -- read the
  redistribution terms before building the product on it.
- Only alert metadata and flow summaries ever leave the site -- never
  packet contents, never PII. Free tiers may train on prompts.

Design principles carried forward from Phase 3.5: AI narrates, code
decides; response is approval-only; quiet is a feature. Multi-site was
already hinted at in Phase 4 — Phase 5 is where it becomes the product.
