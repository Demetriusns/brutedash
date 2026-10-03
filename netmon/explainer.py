"""netmon/explainer.py -- "what am I looking at?" in plain English.

Every SUMMARY_INTERVAL minutes (or on demand from the dashboard), this
rolls the recent flows/alerts/outages up into a compact evidence block
and asks for a plain-English explanation:

  headline           one-line read on the network right now
  whats_happening    2-3 sentences a non-expert can follow
  stands_out         bullets for anything unusual
  suggested_actions  concrete next steps (only if something needs doing)

LLM when OPENAI_API_KEY is set, otherwise a rule-based template summary.
Output is JSON-schema validated before it is saved or shown -- the same
discipline as brutedash's brief writer.
"""
import json
import os
import time

from . import db as dbm
from . import config as cfgm

SUMMARY_INTERVAL = 900  # 15 minutes
WINDOW_MIN = 15

SUMMARY_PROMPT = """You are a friendly network analyst explaining a home
network to its non-technical owner. Below is EVIDENCE: aggregated traffic
metadata (no packet contents), recent alerts, and connectivity status.

EVIDENCE:
{evidence}

Return ONLY a JSON object with exactly these keys:
{{
  "headline": "one short line: the current state of the network",
  "whats_happening": "2-3 plain sentences describing the traffic. No jargon; if you must use a term like 'port scan', explain it briefly.",
  "stands_out": ["bullet 1 -- anything unusual, or 'Nothing unusual' as a single bullet", "bullet 2"],
  "suggested_actions": ["concrete next step 1", "step 2"] -- empty list [] if nothing needs doing
}}
Rules: ground every claim in the evidence; never invent IPs, countries, or
events. Calm tone -- most home traffic is boring and that is fine to say.
No markdown, no extra text."""

VALID_KEYS = {"headline", "whats_happening", "stands_out",
              "suggested_actions"}


def _validate(data):
    if not isinstance(data, dict):
        return None
    if set(data.keys()) != VALID_KEYS:
        return None
    if not isinstance(data.get("headline"), str) or not data["headline"].strip():
        return None
    if (not isinstance(data.get("whats_happening"), str)
            or not data["whats_happening"].strip()):
        return None
    for k in ("stands_out", "suggested_actions"):
        v = data.get(k)
        if (not isinstance(v, list)
                or not all(isinstance(x, str) and x.strip() for x in v)):
            return None
    return {k: (v.strip() if isinstance(v, str) else
                [x.strip() for x in v]) for k, v in data.items()}


_SEV_RANK = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
MAX_STANDS_OUT = 5


def compact_stands_out(alerts):
    """Turn raw alert rows into a short, readable bullet list.

    alerts: iterable of (severity, title, meaning, what_to_do).
    Repeats collapse into one bullet ("Possible ARP spoofing (x4)"),
    ordered worst-first, capped at MAX_STANDS_OUT. The full detail
already lives in the alerts section, so bullets stay one line.
    """
    groups = {}
    for sev, title, _meaning, _action in alerts:
        key = (sev, title)
        g = groups.get(key)
        if g is None:
            groups[key] = {"sev": sev, "title": title, "n": 1}
        else:
            g["n"] += 1
    ordered = sorted(groups.values(),
                     key=lambda g: (_SEV_RANK.get(g["sev"], 9), -g["n"]))
    bullets = [
        f"{g['title']} (x{g['n']})" if g["n"] > 1 else g["title"]
        for g in ordered[:MAX_STANDS_OUT]
    ]
    if len(ordered) > MAX_STANDS_OUT:
        bullets.append(
            f"...and {len(ordered) - MAX_STANDS_OUT} more --"
            " see the alerts above for detail.")
    return bullets


def build_evidence(window_min=WINDOW_MIN, now=None):
    """Compact text summary of the last `window_min` minutes."""
    now = now or time.time()
    since = now - window_min * 60
    lines = [f"Window: last {window_min} minutes."]

    tot = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0),"
        " COUNT(*) FROM flows WHERE ts > ?", (since,))[0]
    total_bytes, total_packets, nflows = tot
    lines.append(f"Total: {total_bytes/1e6:.1f} MB across {total_packets}"
                 f" packets in {nflows} flow records.")

    talkers = dbm.query(
        "SELECT src_ip, dst_ip, dst_port, proto, SUM(bytes) FROM flows"
        " WHERE ts > ? GROUP BY src_ip, dst_ip, dst_port, proto"
        " ORDER BY SUM(bytes) DESC LIMIT 8", (since,))
    if talkers:
        lines.append("Top conversations (by bytes):")
        for s, d, p, proto, b in talkers:
            lines.append(f"  {s} -> {d}:{p}/{proto}: {b/1e6:.2f} MB")

    ports = dbm.query(
        "SELECT dst_port, proto, COUNT(*) FROM flows WHERE ts > ?"
        " AND direction='outbound' GROUP BY dst_port, proto"
        " ORDER BY COUNT(*) DESC LIMIT 6", (since,))
    if ports:
        lines.append("Most-used remote ports (outbound): " +
                     ", ".join(f"{p}/{pr} ({c} flows)"
                               for p, pr, c in ports))

    protos = dbm.query(
        "SELECT proto, COALESCE(SUM(bytes),0) FROM flows WHERE ts > ?"
        " GROUP BY proto", (since,))
    if protos:
        total = sum(b for _, b in protos) or 1
        lines.append("Protocol mix: " +
                     ", ".join(f"{pr} {100*b/total:.0f}%"
                               for pr, b in protos))

    ext = dbm.query(
        "SELECT COUNT(DISTINCT dst_ip) FROM flows WHERE ts > ?"
        " AND direction='outbound'", (since,))[0][0]
    lines.append(f"Distinct external IPs contacted: {ext}.")

    alerts = dbm.query(
        "SELECT severity, title, detail FROM alerts WHERE ts > ?"
        " ORDER BY CASE severity"
        "  WHEN 'Critical' THEN 0 WHEN 'High' THEN 1"
        "  WHEN 'Medium' THEN 2 WHEN 'Low' THEN 3 ELSE 4 END,"
        " ts DESC LIMIT 10",
        (since,))
    if alerts:
        lines.append("Alerts fired in window (worst first):")
        for sev, title, detail in alerts:
            lines.append(f"  [{sev}] {title}: {detail}")
        total_alerts = dbm.query(
            "SELECT COUNT(*) FROM alerts WHERE ts > ?", (since,))[0][0]
        if total_alerts > len(alerts):
            # Budget honesty: say what was cut. Severity-first ordering
            # guarantees anything omitted is lower-or-equal severity to
            # what is shown -- Critical/High can never be silently dropped
            # by newer Low alerts.
            lines.append(f"  (Note: {total_alerts - len(alerts)} more"
                         " alert(s) omitted -- lower severity than those"
                         " shown above.)")
    else:
        lines.append("Alerts fired in window: none.")

    ongoing = dbm.ongoing_outages()
    recent_out = dbm.query(
        "SELECT target, start_ts, end_ts, gap_seconds FROM outages"
        " WHERE start_ts > ? ORDER BY start_ts DESC LIMIT 5", (since,))
    if ongoing:
        lines.append("Connectivity: OUTAGE IN PROGRESS -- " +
                     ", ".join(t for _, t, _ in ongoing))
    elif recent_out:
        lines.append("Connectivity: recovered outages in window:")
        for target, s, e, gap in recent_out:
            lines.append(f"  {target} was down for {gap:.0f}s")
    else:
        lines.append("Connectivity: no drops detected (gateway + internet"
                     " reachable all window).")
    return "\n".join(lines)


# Plain-English guide to the ports a home machine actually uses.
# Shared with the dashboard's "Port guide" section.
PORT_GUIDE = {
    80: "web browsing (unencrypted)",
    443: "encrypted web browsing and apps -- this is most of your traffic",
    53: "address lookups (your computer asking 'where is this website?')",
    123: "clock syncing (keeping your computer's time correct)",
    22: "secure remote login",
    25: "sending email",
    465: "sending email (encrypted)",
    587: "sending email (encrypted)",
    993: "reading email (encrypted)",
    995: "reading email",
    67: "getting a network address when joining Wi-Fi",
    68: "getting a network address when joining Wi-Fi",
    1900: "finding smart devices on your own network",
    5353: "finding smart devices on your own network",
    137: "Windows network chatter (normal on home networks)",
    138: "Windows network chatter (normal on home networks)",
    139: "Windows file sharing (should stay inside your home network)",
    3389: "remote desktop (someone controlling this screen remotely)",
    445: "Windows file sharing (should stay inside your home network)",
    3478: "video/voice calls setting up",
    5222: "chat app notifications",
}


def _port_words(port):
    return PORT_GUIDE.get(port, "an uncommon channel -- see the Port guide")


def rule_based_summary(evidence, window_min=WINDOW_MIN, now=None):
    """Narrative summary a non-technical reader can follow. No LLM needed."""
    now = now or time.time()
    since = now - window_min * 60
    tot = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0)"
        " FROM flows WHERE ts > ?", (since,))[0]
    total_mb = (tot[0] or 0) / 1e6
    total_packets = tot[1] or 0

    ports = dbm.query(
        "SELECT dst_port, SUM(bytes) FROM flows WHERE ts > ?"
        " AND direction='outbound' GROUP BY dst_port"
        " ORDER BY SUM(bytes) DESC LIMIT 3", (since,))
    ext = dbm.query(
        "SELECT COUNT(DISTINCT dst_ip) FROM flows WHERE ts > ?"
        " AND direction='outbound'", (since,))[0][0] or 0

    alerts = dbm.query(
        "SELECT severity, title, meaning, what_to_do FROM alerts"
        " WHERE ts > ? ORDER BY ts DESC", (since,))

    wn = os.environ.get(
        "NETMON_WHOLE_NETWORK", "").strip().lower() in ("1", "true", "yes")
    subject = "your network" if wn else "this computer"
    dev_breakdown = ""
    if wn:
        devs = dbm.query(
            "SELECT src_ip, COALESCE(SUM(bytes),0) FROM flows WHERE ts > ?"
            " AND direction='outbound' GROUP BY src_ip"
            " ORDER BY SUM(bytes) DESC LIMIT 3", (since,))
        devs = [(ip, b) for ip, b in devs if ip]
        if devs:
            try:
                names = dbm.ip_name_map()
            except Exception:
                names = {}
            parts = [f"{names.get(ip, ip)} ({b/1e6:.1f} MB)"
                     for ip, b in devs]
            dev_breakdown = (f" {len(devs)} device(s) were active."
                             f" Busiest: {'; '.join(parts)}.")

    if ports:
        uses = "; ".join(
            f"{b/1e6:.1f} MB on port {p} ({_port_words(p)})"
            for p, b in ports)
        happening = (
            f"In the last {window_min} minutes {subject} moved"
            f" {total_mb:.1f} MB across {total_packets} packets, talking to"
            f" {ext} different outside addresses.{dev_breakdown}"
            f" The breakdown: {uses}.")
    elif total_packets:
        happening = (
            f"In the last {window_min} minutes {subject} moved"
            f" {total_mb:.1f} MB across {total_packets} packets."
            f"{dev_breakdown}")
    else:
        happening = (f"In the last {window_min} minutes {subject} sent"
                     " almost no traffic -- it was quiet.")

    if alerts:
        n = len(alerts)
        headline = (f"{n} thing{'s' if n > 1 else ''} worth a look"
                    f" in the last {window_min} minutes")
        stands_out = compact_stands_out(alerts)
        actions = [a for _, _, _, a in alerts if a]
        # de-dupe while keeping order
        seen, suggested = set(), []
        for a in actions:
            if a not in seen:
                seen.add(a)
                suggested.append(a)
    else:
        headline = f"All quiet in the last {window_min} minutes"
        stands_out = ["Nothing unusual -- this looks like normal,"
                      " everyday traffic."]
        suggested = []

    return {
        "headline": headline,
        "whats_happening": happening,
        "stands_out": stands_out,
        "suggested_actions": suggested,
    }


def summarize(window_min=WINDOW_MIN, save=True, now=None):
    """Build evidence, get an explanation, validate, optionally save.

    `now` anchors the window (wall-clock for live, newest packet for pcap).
    Returns (summary_dict, origin). Never raises."""
    try:
        evidence = build_evidence(window_min, now=now)
        api_key = os.environ.get("OPENAI_API_KEY")
        summary, origin = None, "rule-based"
        if api_key and cfgm.ai_enabled():
            try:
                from openai import OpenAI  # optional dependency
                # short timeout: a stuck API call must never wedge the dashboard
                client = OpenAI(api_key=api_key, timeout=30)
                resp = client.chat.completions.create(
                    model=cfgm.ai_model(),
                    messages=[{"role": "user", "content":
                               SUMMARY_PROMPT.format(evidence=evidence)}],
                    response_format={"type": "json_object"},
                    max_tokens=600,
                )
                candidate = _validate(
                    json.loads(resp.choices[0].message.content))
                if candidate:
                    # keep the AI's list as tight as the rule-based one
                    if len(candidate["stands_out"]) > MAX_STANDS_OUT:
                        candidate["stands_out"] = (
                            candidate["stands_out"][:MAX_STANDS_OUT]
                            + ["...and more -- see the alerts above."])
                    summary, origin = candidate, "llm"
            except Exception:
                pass
        if summary is None:
            summary = rule_based_summary(evidence, window_min, now=now)
        if save:
            dbm.save_summary(window_min, summary["headline"],
                             summary["whats_happening"],
                             summary["stands_out"],
                             summary["suggested_actions"], origin)
        return summary, origin
    except Exception as e:  # explainer never breaks the monitor
        return {"headline": "Summary unavailable",
                "whats_happening": f"The explainer hit an error: {e}.",
                "stands_out": [], "suggested_actions": []}, "error"
