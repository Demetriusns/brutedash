"""netmon/ai_assist.py -- on-demand LLM tie-ins for the dashboard.

A teammate's dashboard code calls these guarded by try/except:

  llm_available()   True when OPENAI_API_KEY is set and `openai` imports.
  triage_verdict()  LLM second opinion on one alert (verdict + reasoning).
  answer_question() natural-language Q&A over the monitor's own data.
  polish_weekly()   tighten the rule-based weekly report text.

Same discipline as netmon/explainer.py: `api_key = os.environ.get(...)`,
`from openai import OpenAI` inside try/except (optional dependency), JSON
prompts validated before use, and never raise -- every function returns
None when there is no key or anything goes wrong.

The LLM NEVER writes SQL and never touches the DB: answer_question builds
its context from a fixed set of dbm.query() calls and the question text
is only ever sent as chat content, never into a query.
"""
import json
import os
import time

from . import db as dbm
from . import explainer
from . import config as cfgm

QA_WINDOW_S = 24 * 3600  # context window for Q&A: last 24 hours
VALID_VERDICTS = {"real concern", "likely benign", "uncertain"}


def _model():
    """Configured LLM model (falls back to gpt-4o-mini). Never raises."""
    try:
        return cfgm.ai_model()
    except Exception:
        return "gpt-4o-mini"


def llm_available():
    """True if an OpenAI key is configured, the package imports,
    and ai.provider in config.yaml is not "off"."""
    try:
        if not os.environ.get("OPENAI_API_KEY"):
            return False
        if cfgm.get(cfgm.load_cached(), "ai.provider", "openai") == "off":
            return False
        import openai  # noqa: F401  (optional dependency)
        return True
    except Exception:
        return False


def _client():
    """OpenAI client, or None when key/package is missing. Never raises."""
    try:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            return None
        from openai import OpenAI  # optional dependency
        return OpenAI(api_key=api_key)
    except Exception:
        return None


def _json_chat(client, prompt, max_tokens=400):
    """Ask the LLM for a JSON object. Returns the dict, or None. Never."""
    try:
        resp = client.chat.completions.create(
            model=_model(),
            messages=[{"role": "user", "content": prompt}],
            response_format={"type": "json_object"},
            max_tokens=max_tokens,
        )
        data = json.loads(resp.choices[0].message.content)
        return data if isinstance(data, dict) else None
    except Exception:
        return None


TRIAGE_PROMPT = """You are a calm, friendly network analyst giving a second
opinion to a home network owner. Below is ONE ALERT from their network
monitor, plus RECENT ALERTS for calibration (other things the monitor
flagged lately, so you can tell routine from unusual).

ALERT:
{alert_block}

RECENT ALERTS (for calibration):
{recent_block}

Return ONLY a JSON object with exactly these keys:
{{
  "verdict": "one of: real concern | likely benign | uncertain",
  "reasoning": "2-3 plain-English sentences explaining your verdict. No jargon; if you must use a term like 'port scan', explain it briefly."
}}
Rules: base the verdict only on the alert and calibration above; never
invent IPs, devices, countries, or events. Calm tone -- most home alerts
turn out to be boring and that is fine to say. No markdown, no extra
text."""


def _validate_verdict(data):
    """Check the triage JSON; return the cleaned dict or None."""
    if not isinstance(data, dict):
        return None
    if set(data.keys()) != {"verdict", "reasoning"}:
        return None
    verdict, reasoning = data.get("verdict"), data.get("reasoning")
    if verdict not in VALID_VERDICTS:
        return None
    if not isinstance(reasoning, str) or not reasoning.strip():
        return None
    return {"verdict": verdict, "reasoning": reasoning.strip()}


def _recent_alerts_block(since, limit=5):
    rows = dbm.query(
        "SELECT severity, title, detail FROM alerts WHERE ts > ?"
        " ORDER BY ts DESC LIMIT ?", (since, limit))
    if not rows:
        return "No other recent alerts."
    return "\n".join(
        f"[{sev}] {title}: {detail}" for sev, title, detail in rows)


def triage_verdict(alert):
    """Second opinion on one alert.

    alert: dict with keys severity/title/detail/meaning/is_normal/what_to_do.
    Returns {"verdict": ..., "reasoning": ...} or None. Never raises.

    When the model is unavailable (no key, bad response, API error), the
    deterministic rule-based take below answers instead of silence -- the
    dashboard labels it as such.
    """
    try:
        client = _client()
        if client is None or not isinstance(alert, dict):
            return _rule_based_verdict(alert)
        lines = []
        for key in ("severity", "title", "detail", "meaning",
                    "is_normal", "what_to_do"):
            val = alert.get(key)
            if val:
                lines.append(f"{key}: {val}")
        alert_block = "\n".join(lines) or "No alert details available."
        recent_block = _recent_alerts_block(time.time() - 7 * 86400)
        data = _json_chat(
            client,
            TRIAGE_PROMPT.format(alert_block=alert_block,
                                 recent_block=recent_block),
            max_tokens=300,
        )
        verdict = _validate_verdict(data)
        return verdict if verdict is not None else _rule_based_verdict(alert)
    except Exception:
        return _rule_based_verdict(alert)


def _rule_based_verdict(alert):
    """Deterministic second opinion when the model is unavailable.

    Built only from the alert's own plain-English fields and the static
    detection catalog's false-positive notes -- it never invents facts,
    devices, or events. Same {"verdict", "reasoning"} shape as the model
    path, with the origin stated up front so the dashboard can tell it
    apart. Never raises.
    """
    try:
        alert = alert if isinstance(alert, dict) else {}
        sev = (alert.get("severity") or "").strip()
        kind = (alert.get("kind") or "").strip()
        title = (alert.get("title") or "this alert").strip()
        meaning = (alert.get("meaning") or "").strip()
        what_to_do = (alert.get("what_to_do") or "").strip()
        verdict = {"Critical": "real concern", "High": "real concern",
                   "Medium": "uncertain",
                   "Low": "likely benign"}.get(sev, "uncertain")
        fp_note = ""
        try:
            from . import detection_catalog as catm
            entry = next((r for r in catm.RULES if r.get("id") == kind),
                         None)
            if entry and entry.get("recognize_fp"):
                fp_note = str(entry["recognize_fp"]).strip()
        except Exception:
            pass
        parts = ["The AI second opinion is unavailable right now -- this"
                 " is the rule-based take."]
        if verdict == "real concern":
            parts.append(f"{title} is {sev} urgency: treat it as worth"
                         f" acting on, not just watching.")
        elif verdict == "likely benign":
            parts.append(f"{title} is low urgency: these usually turn out"
                         f" to be routine.")
        else:
            parts.append(f"{title} is medium urgency: worth a look when"
                         f" you have a minute.")
        if meaning:
            parts.append(meaning)
        if fp_note:
            parts.append(f"How to tell it's a false alarm: {fp_note}")
        if what_to_do:
            parts.append(f"Suggested next step: {what_to_do}")
        reasoning = " ".join(parts)
        if len(reasoning) > 900:
            reasoning = reasoning[:897] + "..."
        return {"verdict": verdict, "reasoning": reasoning}
    except Exception:
        return {"verdict": "uncertain",
                "reasoning": ("The AI second opinion is unavailable right"
                              " now. Not enough detail to judge -- treat"
                              " it as worth a quick look.")}


QA_PROMPT = """You are a friendly network analyst answering a question from
the owner of a home network. Use ONLY the CONTEXT below: aggregated
traffic metadata (no packet contents), alerts, and connectivity status
from the last 24 hours.

CONTEXT:
{context}

TOOLS (optional, at most 2 rounds):
If the context above is not enough to answer, you may ask for more data
with tool calls. Return ONLY a JSON object shaped like this:
{{"tool_calls": [{{"tool": "name", "params": {{"limit": 20}}}}]}}
Available tools (name -- what it does -- parameters):
{tools_block}

Rules for tool calls: "tool" must be exactly one of the names above;
"params" holds only the listed parameters (types, allowed values, and
defaults are shown). At most 3 calls per round. A rejected call comes
back as an error -- read it and fix the call. After your tool calls run,
their results are appended to the context and you are asked again; then
you MUST return a final {{"answer": "..."}} even if the tools did not
help -- say what is missing instead of guessing.

QUESTION:
{question}

Return ONLY a JSON object: either
{{"answer": "your answer in plain English, 1-4 short sentences"}}
or {{"tool_calls": [...]}} -- never both, never anything else.

Rules: answer only from the context (plus any tool results); if the data
cannot answer the question, say so plainly instead of guessing. Never
invent IPs, countries, devices, or events. Calm tone, no jargon. No
markdown, no extra text."""

QA_FINAL_PROMPT = """You are a friendly network analyst answering a question from
the owner of a home network. Use ONLY the CONTEXT below: aggregated
traffic metadata (no packet contents), alerts, connectivity status, and
TOOL RESULTS (data returned by the monitor's tools) from the last 24
hours.

CONTEXT:
{context}

QUESTION:
{question}

Return ONLY a JSON object with exactly one key:
{{"answer": "your answer in plain English, 1-4 short sentences"}}

Rules: answer only from the context; if the data cannot answer the
question, say what is missing plainly instead of guessing. Never invent
IPs, countries, devices, or events. Calm tone, no jargon. No markdown,
no extra text."""

MAX_TOOL_ROUNDS = 2      # model tool-call rounds before a final answer
MAX_TOOL_CALLS = 3       # tool calls accepted per round


def _tools():
    """The tool registry module, or None. Lazy import keeps startup
    light; the registry is only needed on the /ask path."""
    try:
        from . import tools as toolsm
        return toolsm
    except Exception:
        return None


def _tools_block():
    """Compact tool catalog for the model prompt: name, description,
    and parameter shapes. Never raises; empty string when the registry
    is unavailable (the model then just answers from context)."""
    try:
        toolsm = _tools()
        if toolsm is None:
            return ""
        lines = []
        for t in toolsm.list_tools():
            parts = []
            for pname, p in t["params"].items():
                bit = f"{pname} ({p['type']}"
                if p["type"] == "enum":
                    bit += f": {'|'.join(p['allowed'])}"
                if p.get("min") is not None:
                    bit += f" {p['min']}-{p.get('max', '?')}"
                if p.get("scope"):
                    bit += f", {p['scope']}"
                if not p["required"]:
                    bit += f", default {p['default']}"
                else:
                    bit += ", required"
                parts.append(bit + ")")
            lines.append(f"- {t['name']}: {t['description']}"
                         f" Params: {'; '.join(parts) or 'none'}.")
        return "\n".join(lines)
    except Exception:
        return ""


def _validate_tool_calls(calls):
    """Strict shape check on model-proposed tool calls.

    Returns the cleaned list [{tool, params}] or None. This is the
    SHAPE check only -- the registry re-validates names and parameters
    against schemas before executing (defense in depth: the shape
    check keeps the loop honest, the registry is the real gate).
    """
    if not isinstance(calls, list) or not calls:
        return None
    if len(calls) > MAX_TOOL_CALLS:
        return None
    out = []
    for c in calls:
        if not isinstance(c, dict):
            return None
        tool = c.get("tool")
        params = c.get("params", {})
        if not isinstance(tool, str) or not tool:
            return None
        if not isinstance(params, dict):
            return None
        out.append({"tool": tool, "params": params})
    return out


def _validate_qa_response(data):
    """Check the /ask JSON; return ("answer", text), ("tool_calls",
    calls), or None. Exactly one of the two keys must be present."""
    if not isinstance(data, dict):
        return None
    if set(data.keys()) == {"answer"}:
        answer = data.get("answer")
        if not isinstance(answer, str) or not answer.strip():
            return None
        return ("answer", answer.strip())
    if set(data.keys()) == {"tool_calls"}:
        calls = _validate_tool_calls(data.get("tool_calls"))
        if calls is None:
            return None
        return ("tool_calls", calls)
    return None


def _run_tool_calls(calls):
    """Execute model-proposed tool calls through the registry.

    TRUST BOUNDARY (read carefully): `calls` is UNTRUSTED model output.
    It is passed as DATA to tools.invoke(), which validates the tool
    name and every parameter against the registered schemas BEFORE
    executing anything. Model text never reaches a shell, never reaches
    SQL except through parameterized queries inside the handlers, and
    never selects scan targets (those come from the asset inventory /
    config). Results come back as DATA and are appended to the next
    prompt's context -- still data, never instructions. Never raises.
    """
    results = []
    try:
        toolsm = _tools()
        if toolsm is None:
            return [{"tool": c["tool"], "ok": False,
                     "error": "tool server unavailable"} for c in calls]
        for c in calls:
            try:
                inv = toolsm.invoke(c["tool"], c["params"],
                                    requested_by="ai_analyst")
            except Exception as exc:
                inv = {"ok": False, "tool": c["tool"],
                       "error_kind": "execution",
                       "error": f"tool failed: {exc}"[:200]}
            if inv.get("ok"):
                results.append({"tool": inv.get("tool"),
                                "ok": True,
                                "result": inv.get("result")})
            else:
                results.append({"tool": inv.get("tool") or c["tool"],
                                "ok": False,
                                "error_kind": inv.get("error_kind"),
                                "error": inv.get("error"),
                                "retry_hint": inv.get("retry_hint")})
    except Exception:
        pass
    return results


def _build_qa_context(now=None):
    """Fixed read-only evidence block for answer_question.

    Built from a fixed set of dbm queries only -- the user's question is
    never interpolated into SQL or used to choose queries.
    """
    now = now or time.time()
    since = now - QA_WINDOW_S
    lines = ["Monitor data: last 24 hours."]

    tot = dbm.query(
        "SELECT COALESCE(SUM(bytes),0), COALESCE(SUM(packets),0), COUNT(*)"
        " FROM flows WHERE ts > ?", (since,))[0]
    total_bytes, total_packets, nflows = tot
    lines.append(f"Totals: {total_bytes/1e6:.1f} MB in {total_packets}"
                 f" packets across {nflows} flow records.")

    talkers = dbm.query(
        "SELECT src_ip, dst_ip, dst_port, proto, SUM(bytes) FROM flows"
        " WHERE ts > ? GROUP BY src_ip, dst_ip, dst_port, proto"
        " ORDER BY SUM(bytes) DESC LIMIT 10", (since,))
    if talkers:
        lines.append("Top talkers (by bytes):")
        for s, d, p, proto, b in talkers:
            lines.append(f"  {s} -> {d}:{p}/{proto}"
                         f" ({explainer._port_words(p)}): {b/1e6:.2f} MB")
    else:
        lines.append("Top talkers: none -- no traffic in the window.")

    ext = dbm.query(
        "SELECT COUNT(DISTINCT dst_ip) FROM flows WHERE ts > ?"
        " AND direction='outbound'", (since,))[0][0]
    lines.append(f"Distinct external IPs contacted: {ext}.")

    alerts = dbm.query(
        "SELECT severity, title, detail, meaning FROM alerts WHERE ts > ?"
        " ORDER BY ts DESC LIMIT 15", (since,))
    if alerts:
        lines.append("Alerts (newest first):")
        for sev, title, detail, meaning in alerts:
            line = f"  [{sev}] {title}: {detail}"
            if meaning:
                line += f" ({meaning})"
            lines.append(line)
    else:
        lines.append("Alerts: none in the last 24 hours.")

    ongoing = dbm.ongoing_outages()
    recent_out = dbm.query(
        "SELECT target, start_ts, end_ts, gap_seconds FROM outages"
        " WHERE start_ts > ? ORDER BY start_ts DESC LIMIT 5", (since,))
    if ongoing:
        lines.append("Connectivity: OUTAGE IN PROGRESS -- " +
                     ", ".join(t for _, t, _ in ongoing))
    elif recent_out:
        lines.append("Connectivity: recent recovered outages:")
        for target, _s, _e, gap in recent_out:
            lines.append(f"  {target} was down for {gap:.0f}s")
    else:
        lines.append("Connectivity: no drops detected (gateway + internet"
                     " reachable all day).")
    return "\n".join(lines)


def answer_question(question):
    """Answer a natural-language question from the 24h monitor data.

    The question is only ever sent as chat content; the context comes
    from fixed dbm queries. When the context is not enough, the model
    may request tool calls (validated + executed by netmon/tools.py --
    see _run_tool_calls for the trust boundary); results return as data
    and the model is asked again, at most MAX_TOOL_ROUNDS rounds.
    Returns {"answer": str} or None. Never raises.
    """
    try:
        client = _client()
        if client is None:
            # No model available: say so plainly instead of returning
            # silence. The dashboard's summary and alert list still work.
            return {"answer": ("The AI answering service is unavailable"
                               " right now (no API key configured or the"
                               " service didn't respond). The network"
                               " summary and alert list on the dashboard"
                               " still work -- start there.")}
        if not isinstance(question, str) or not question.strip():
            return None
        question = question.strip()
        context = _build_qa_context()
        tools_block = _tools_block()
        for _round in range(MAX_TOOL_ROUNDS):
            data = _json_chat(
                client,
                QA_PROMPT.format(context=context, question=question,
                                 tools_block=tools_block),
                max_tokens=400,
            )
            checked = _validate_qa_response(data)
            if checked is None:
                return None
            kind, payload = checked
            if kind == "answer":
                return {"answer": payload}
            # Tool-call round: execute through the registry, append the
            # results as data, and ask again.
            results = _run_tool_calls(payload)
            context += ("\n\nTOOL RESULTS (data from the monitor's tools"
                        " -- use only what answers the question):\n"
                        + json.dumps(results)[:6000])
        # Tool budget spent: one final answer-only round, no more tools.
        data = _json_chat(
            client,
            QA_FINAL_PROMPT.format(context=context, question=question),
            max_tokens=400,
        )
        checked = _validate_qa_response(data)
        if checked is not None and checked[0] == "answer":
            return {"answer": checked[1]}
        return None
    except Exception:
        return None


POLISH_PROMPT = """You are polishing a rule-based weekly network report for
a non-technical home owner. Tighten the wording: warmer, clearer, easier
to skim -- but keep every fact exactly as stated. Do not add new facts,
devices, IPs, numbers, or events, and do not soften or hide any warning
the report gives.

ORIGINAL REPORT:
{report}

Return ONLY a JSON object with exactly one key:
{{"polished": "the polished report, in plain English"}}

Rules: same facts, no invented details, no markdown, no extra text."""


def polish_weekly(text):
    """Tighten/polish a rule-based weekly report. Returns str or None."""
    try:
        client = _client()
        if client is None or not isinstance(text, str) or not text.strip():
            return None
        data = _json_chat(
            client,
            POLISH_PROMPT.format(report=text.strip()),
            max_tokens=800,
        )
        if not isinstance(data, dict):
            return None
        polished = data.get("polished")
        if not isinstance(polished, str) or not polished.strip():
            return None
        return polished.strip()
    except Exception:
        return None
