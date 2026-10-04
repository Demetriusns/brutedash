# templates/ -- detection-as-code for the self vulnerability scan

A new self-scan check is a FILE here, not a code change. Drop a YAML
file in this directory describing the check; the next scheduled scan
picks it up. Evaluated by `netmon/templates.py` (the matcher engine);
nothing in these files ever executes.

## Schema

```yaml
id: docker-api-open            # required; ^[a-z0-9-]{1,64}$
info:
  name: "Docker remote API is open"   # required; shown in the dashboard
  service: "Docker API"               # short label for the findings table
  severity: medium                    # low | medium  (only low/medium:
                                      # a home scanner reports hygiene,
                                      # not emergencies)
  description: "..."                  # required; plain-English, shown in
                                      # the dashboard and alert text
  tags: [network, insecure-default]   # optional list of strings
match:
  port_open: 2375              # fires when this port is open on a device
  # -- OR --
  ports_open: [9200, 9300]     # fires per port when ALL are open
```

Rules the loader enforces (violations skip the file with a warning,
never break the scan):

- exactly one of `port_open` / `ports_open` under `match`;
- ports are integers 1-65535;
- no unknown top-level keys (typos fail loudly);
- **matcher ports must not overlap the built-in scan's port list**
  (`SCAN_PORTS` in `netmon/scan.py`) -- the findings table keys on
  (ip, port), so two check families must not claim the same door.
  Template checks are for NEW coverage, not re-describing built-in
  checks.

## Why a hand-rolled YAML reader

`netmon/templates.py` parses only this schema with its own tiny
parser -- deliberately not PyYAML. A full YAML parser can do things
these files must never do: anchors/aliases (YAML bomb denial of
service), `!!python/*` tags (arbitrary code execution), nested flow
syntax. The subset parser rejects all of that (inline `[a, b]` scalar
lists are the one flow idiom allowed, since `tags:` reads naturally
that way), and the matchers themselves are implemented in code --
template content is data, never evaluated.

## Migration path

The built-in scan's `RISK_KB` checks predate this DSL and stay in
Python for now (stable, well-tested, and the release gate's LLM audit
watches that file). The loader skips templates whose ports overlap
`SCAN_PORTS` so one door never alerts twice; the findings table keys on
(source, ip, port), so the two check families coexist cleanly. A future
batch may port the `RISK_KB` entries to YAML file-by-file, with the
existing test suite confirming nothing changed.
