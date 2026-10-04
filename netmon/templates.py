"""netmon/templates.py -- detection-as-code: small YAML check templates.

Nuclei's big idea, our scale: a new self-scan check is a FILE in
templates/, not a code change. Each template says what to look for
(id/info/severity/matcher-style) in plain data; the matcher engine in
this module evaluates it against scan results. Adding a check means
dropping a YAML file in the directory -- no Python edits, no restarts
beyond the next scheduled scan.

Why our own tiny YAML reader instead of PyYAML: the schema is small and
fixed, so a strict subset parser is enough -- and it can never do what
a full YAML parser can do. No anchors/aliases (no billion-laughs
bombs), no !!python tags (nothing ever executes), no nested flow
syntax (the one flow idiom allowed is inline [a, b] scalar lists). A
template that uses anything outside the documented schema is rejected
with a logged warning, never evaluated. Templates are DATA; the
matchers below are the only code that runs.

Supported schema (see templates/README.md for the full doc):

    id: docker-api-open            # ^[a-z0-9-]{1,64}$
    info:
      name: "Docker remote API is open"
      service: "Docker API"        # short label for the findings table
      severity: medium             # low | medium
      description: "plain-English, shown in the dashboard and alerts"
      tags: [network, insecure-default]   # optional, informational
    match:
      port_open: 2375              # OR ports_open: [9200, 9300]

Matcher types (implemented below, never exec'd):
  * port_open: <port>      -- fires when that port is open on a device
  * ports_open: [<ports>]  -- fires per port when ALL are open on a device

Migration note: the built-in scan's RISK_KB checks predate this DSL and
stay in code for now (they're stable and well-tested). New checks go in
templates/. The loader skips templates whose ports overlap SCAN_PORTS
so one door never alerts twice; the findings table keys on
(source, ip, port), so the two check families coexist cleanly.
"""

import os
import re
import sys

from . import db as dbm

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "..", "templates")

_ID_RE = re.compile(r"^[a-z0-9-]{1,64}$")
_SEVERITIES = {"low", "medium"}


# ---------------------------------------------------------------------------
# Minimal YAML-subset parser
# ---------------------------------------------------------------------------
# Supports ONLY what the template schema needs:
#   key: value            (top level, or indented 2 spaces for nesting)
#   key:                  (starts a nested mapping or a list)
#   - item                (list items, indented 2 spaces under their key)
#   key: [a, b, c]        (inline list of plain scalars)
# Scalars: "double-quoted", 'single-quoted', plain words, integers,
# true/false. Lines starting with # and blank lines are ignored.
# Everything else (tabs, anchors &, aliases *, tags !!, nested flow
# {}/[], deeper nesting than the schema) is a parse error -> the
# template is rejected, never evaluated.

def _parse_scalar(text):
    text = text.strip()
    if len(text) >= 2 and text[0] == text[-1] and text[0] in ("\"", "'"):
        return text[1:-1]
    low = text.lower()
    if low == "true":
        return True
    if low == "false":
        return False
    if re.fullmatch(r"[+-]?\d+", text):
        try:
            return int(text)
        except ValueError:
            pass
    return text


def _promote_lists(text):
    """Parse the documented subset into nested dicts/lists.

    A 'key:' line followed by indented '- ' lines becomes a list;
    otherwise it starts a nested mapping (2-space indent per level).
    Raises ValueError on anything outside the subset.
    """
    lines = [l for l in text.splitlines()
             if l.strip() and not l.lstrip().startswith("#")]

    def _indent(s):
        return len(s) - len(s.lstrip(" "))

    def _block(start, base_indent):
        """Parse a mapping block starting at lines[start]."""
        mapping = {}
        j = start
        while j < len(lines):
            line = lines[j]
            ind = _indent(line)
            if ind < base_indent:
                break
            if ind > base_indent:
                raise ValueError(f"line {j + 1}: bad indentation")
            stripped = line.strip()
            if stripped.startswith("-"):
                raise ValueError(f"line {j + 1}: '-' outside a list")
            if "\t" in line:
                raise ValueError(f"line {j + 1}: tabs are not allowed")
            if ":" not in stripped:
                raise ValueError(f"line {j + 1}: expected 'key: value'")
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            if not re.fullmatch(r"[A-Za-z0-9_.-]+", key):
                raise ValueError(f"line {j + 1}: bad key {key!r}")
            if key in mapping:
                raise ValueError(f"line {j + 1}: duplicate key {key!r}")
            if value.startswith(("[", "{", "&", "*", "!", "|", ">")):
                if value.startswith("[") and value.endswith("]"):
                    # Inline flow list of scalars: tags: [a, b]. Split on
                    # commas; each item must be a plain scalar (no nested
                    # flow, anchors, or tags).
                    inner = value[1:-1].strip()
                    items = []
                    if inner:
                        for part in inner.split(","):
                            part = part.strip()
                            if (not part or ":" in part
                                    or part[0] in "[{&*!|>"):
                                raise ValueError(
                                    f"line {j + 1}: only scalar list items")
                            items.append(_parse_scalar(part))
                    mapping[key] = items
                    j += 1
                    continue
                raise ValueError(
                    f"line {j + 1}: flow/anchor syntax rejected")
            j += 1
            if value == "":
                # Look ahead: list or nested mapping?
                if j < len(lines) and lines[j].strip().startswith("-"):
                    items = []
                    li = _indent(lines[j])
                    if li != ind + 2:
                        raise ValueError(
                            f"line {j + 1}: list items indent 2 spaces")
                    while j < len(lines) and lines[j].strip().startswith(
                            "-"):
                        if _indent(lines[j]) != li:
                            raise ValueError(
                                f"line {j + 1}: bad indentation")
                        item = lines[j].strip()[1:].strip()
                        if (not item or ":" in item
                                or item[0] in "[{&*!|>"):
                            raise ValueError(
                                f"line {j + 1}: only scalar list items")
                        items.append(_parse_scalar(item))
                        j += 1
                    mapping[key] = items
                else:
                    sub, j = _block(j, ind + 2)
                    mapping[key] = sub
            else:
                mapping[key] = _parse_scalar(value)
        return mapping, j

    mapping, _ = _block(0, 0)
    return mapping


def parse_template_text(text):
    """Parse + validate one template's YAML. Returns the normalized
    template dict, or raises ValueError with the reason."""
    return validate_template(_promote_lists(text))


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def _valid_port(p):
    return isinstance(p, int) and not isinstance(p, bool) \
        and 1 <= p <= 65535


def validate_template(data):
    """Validate the parsed dict against the schema. Returns a normalized
    template: {"id", "info": {name, service, severity, description,
    tags}, "match": {"port_open": int} | {"ports_open": [int]}}.
    Raises ValueError on any violation."""
    if not isinstance(data, dict):
        raise ValueError("template must be a mapping")
    tid = data.get("id")
    if not isinstance(tid, str) or not _ID_RE.match(tid):
        raise ValueError("id must match ^[a-z0-9-]{1,64}$")
    info = data.get("info")
    if not isinstance(info, dict):
        raise ValueError("info: mapping is required")
    name = info.get("name")
    if not isinstance(name, str) or not name.strip() or len(name) > 120:
        raise ValueError("info.name: non-empty string, max 120 chars")
    service = info.get("service", name)
    if not isinstance(service, str) or len(service) > 60:
        raise ValueError("info.service: string, max 60 chars")
    severity = info.get("severity")
    if not isinstance(severity, str) \
            or severity.strip().lower() not in _SEVERITIES:
        raise ValueError("info.severity: low | medium")
    description = info.get("description")
    if not isinstance(description, str) or not description.strip() \
            or len(description) > 500:
        raise ValueError(
            "info.description: non-empty string, max 500 chars")
    tags = info.get("tags", [])
    if not isinstance(tags, list) or any(
            not isinstance(t, str) for t in tags):
        raise ValueError("info.tags: list of strings")
    match = data.get("match")
    if not isinstance(match, dict) or set(match) not in (
            {"port_open"}, {"ports_open"}):
        raise ValueError(
            "match: exactly one of port_open / ports_open")
    if "port_open" in match:
        port = match["port_open"]
        if not _valid_port(port):
            raise ValueError("match.port_open: integer 1-65535")
        match = {"port_open": port}
    else:
        ports = match["ports_open"]
        if not isinstance(ports, list) or not ports \
                or not all(_valid_port(p) for p in ports):
            raise ValueError(
                "match.ports_open: non-empty list of ports 1-65535")
        match = {"ports_open": sorted(set(ports))}
    # No unknown top-level keys: typos fail loudly, not silently.
    unknown = set(data) - {"id", "info", "match"}
    if unknown:
        raise ValueError(f"unknown top-level keys: {sorted(unknown)}")
    return {
        "id": tid,
        "info": {
            "name": name.strip(),
            "service": service.strip() or name.strip(),
            "severity": severity.strip().lower(),
            "description": description.strip(),
            "tags": [t.strip() for t in tags if t.strip()][:10],
        },
        "match": match,
    }


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def default_dir():
    d = os.path.normpath(TEMPLATES_DIR)
    return d


def _builtin_ports():
    """Ports the built-in scan already covers (overlap = skip)."""
    try:
        from . import scan as scanm
        return {p for p, _ in scanm.SCAN_PORTS}
    except Exception:
        return set()


def load_templates(directory=None):
    """Load every *.yaml in the directory. Returns [template, ...].

    Invalid files are skipped with a stderr warning -- one bad template
    never breaks the scan. Templates whose matcher ports overlap the
    built-in SCAN_PORTS are skipped too (one door should not alert
    twice -- the findings table keys on (source, ip, port), so this is
    about alert hygiene, not integrity).
    Never raises."""
    directory = directory or default_dir()
    templates = []
    try:
        names = sorted(os.listdir(directory))
    except OSError as exc:
        print(f"netmon templates: cannot list {directory}: {exc}",
              file=sys.stderr)
        return []
    builtin_ports = _builtin_ports()
    for name in names:
        if not name.endswith(".yaml"):
            continue
        path = os.path.join(directory, name)
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read(65536)
        except OSError as exc:
            print(f"netmon templates: cannot read {path}: {exc}",
                  file=sys.stderr)
            continue
        try:
            tmpl = parse_template_text(text)
        except ValueError as exc:
            print(f"netmon templates: skipping {name}: {exc}",
                  file=sys.stderr)
            continue
        ports = matcher_ports(tmpl)
        if ports & builtin_ports:
            print(f"netmon templates: skipping {name}: matcher ports"
                  f" {sorted(ports & builtin_ports)} overlap the built-in"
                  " scan -- template checks cover NEW ports (keeps one"
                  " door from alerting twice)",
                  file=sys.stderr)
            continue
        templates.append(tmpl)
    return templates


def matcher_ports(tmpl):
    """Every port a template's matcher needs probed."""
    m = tmpl["match"]
    if "port_open" in m:
        return {m["port_open"]}
    return set(m["ports_open"])


def required_ports(templates):
    """Union of matcher ports across templates (bounded)."""
    ports = set()
    for tmpl in templates or []:
        ports |= matcher_ports(tmpl)
    return sorted(ports)[:32]


def risk_ports():
    """{port: (risk, description)} for template checks at Medium -- lets
    the attack-surface view count template findings as risky doors.
    Never raises."""
    out = {}
    try:
        for tmpl in load_templates():
            if tmpl["info"]["severity"] != "medium":
                continue
            for port in matcher_ports(tmpl):
                out[port] = ("Medium", tmpl["info"]["description"])
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# Matcher engine -- templates are data, these functions are the code
# ---------------------------------------------------------------------------

def evaluate(templates, results):
    """Evaluate templates against scan results.

    results: {ip: set(open ports)}. Returns [(ip, port, template)]
    findings -- one per matched door. Pure function, no I/O.
    """
    findings = []
    for tmpl in templates or []:
        m = tmpl["match"]
        if "port_open" in m:
            wanted = {m["port_open"]}
        else:
            wanted = set(m["ports_open"])
        for ip in sorted(results or {}):
            open_ports = results[ip] or set()
            if wanted <= set(open_ports):
                for port in sorted(wanted):
                    findings.append((ip, port, tmpl))
    return findings
