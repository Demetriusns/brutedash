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

SUMMARY_INTERVAL = 900  # 15 minutes
WINDOW_MIN = 15

SUMMARY_PROMPT = """You are a friendly network analyst explaining a home
network to its non-technical owner. Below is EVIDENCE: aggregated traffic
metadata (no packet contents), recent alerts, and connectivity status.

EVIDENCE:
{evidence}

Return ONLY a JSON object with exactly these keys:
{
  "headline": "one short line: the current state of the network",
  "whats_happening": "2-3 plain sentences describing the traffic. No jargon; if you must use a term like 'port scan', explain it briefly.",
  "stands_out": ["bullet 1 -- anything unusual, or 'Nothing unusual' as a single bullet", "bullet 2"],
  "suggested_actions": ["concrete next step 1", "step 2"] -- empty list [] if nothing needs doing
}
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
        " ORDER BY ts DESC LIMIT 10", (since,))
    if alerts:
        lines.append("Alerts fired in window:")
        for sev, title, detail in alerts:
            lines.append(f"  [{sev}] {title}: {detail}")
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


def rule_based_summary(evidence, window_min=WINDOW_MIN):
    """Fallback when no LLM key is available: template over the evidence."""
    return {
        "headline": "Network summary (rule-based -- no AI key configured)",
        "whats_happening": (
            "This is an automated roll-up of the traffic metadata collected"
            " in the window. Set OPENAI_API_KEY for a plain-English AI"
            " explanation. Raw evidence is listed below so nothing is"
            " hidden."),
        "stands_out": [line.strip() for line in evidence.splitlines()
                       if line.strip()][:12],
        "suggested_actions": [],
    }


def summarize(window_min=WINDOW_MIN, save=True, now=None):
    """Build evidence, get an explanation, validate, optionally save.

    `now` anchors the window (wall-clock for live, newest packet for pcap).
    Returns (summary_dict, origin). Never raises."""
    try:
        evidence = build_evidence(window_min, now=now)
        api_key = os.environ.get("OPENAI_API_KEY")
        summary, origin = None, "rule-based"
        if api_key:
            try:
                from openai import OpenAI  # optional dependency
                client = OpenAI(api_key=api_key)
                resp = client.chat.completions.create(
                    model="gpt-4o-mini",
                    messages=[{"role": "user", "content":
                               SUMMARY_PROMPT.format(evidence=evidence)}],
                    response_format={"type": "json_object"},
                    max_tokens=600,
                )
                candidate = _validate(
                    json.loads(resp.choices[0].message.content))
                if candidate:
                    summary, origin = candidate, "llm"
            except Exception:
                pass
        if summary is None:
            summary = rule_based_summary(evidence, window_min)
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
