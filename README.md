# Sentinel Arena

An authorized, non-destructive multi-agent **security-resilience** platform. A
red (attacker) team and a blue (defender) team run a controlled engagement
against a target you own; the engagement is watchable in real time and produces
a resilience audit report.

> **This is an authorized security-testing platform, not an attack tool.** No
> component acts against any host until ownership of that exact host is
> cryptographically proven and the action falls inside an explicit, enforced
> scope. Demos, tests, and CI run only against a self-deployed vulnerable app on
> 127.0.0.1 — never a third party. See [`docs/SAFETY.md`](docs/SAFETY.md).

## Run one in a single command

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"

arena run --scenario shop-01 --red scripted --blue scripted --seed 42
```

Example output:

```
  Resilience: 88/100
  Outcome:    max_ticks after 12 tick(s)
  Red 13  |  Blue 48  |  flag not captured
  Report:  var/engagements/shop-01-42/report.html
```

Against a passive defender the attacker gets through, which is the point of a
baseline:

```bash
arena run --blue noop        # scripted red reaches the flag; resilience ~30
```

Other commands:

```bash
arena scenarios                         # list scenarios
arena replay var/engagements/shop-01-42 # re-print the timeline + score
arena verify-audit <dir>/audit.jsonl    # check the tamper-evident hash chain
```

## Watch it live (optional)

```bash
uv pip install -e ".[api]"
uvicorn sentinel_arena.api.server:app
# open http://127.0.0.1:8000  — split-screen red/blue, network map, live score
```

PDF export of the audit report turns on with `uv pip install -e ".[pdf]"`.

## What's here

A full end-to-end vertical slice, built in the brief's milestone order:

- **Authorization gate + scope engine** (`authz`) — built first. Ownership
  verification (DNS TXT / well-known file / meta tag), frozen scope with
  blocklist/allowlist/path/time-window enforcement and staging-first production
  caps, immutable consent, and a tamper-evident hash-chained audit log.
- **Bundled range** (`range`) — a self-deployed vulnerable app on 127.0.0.1 with
  benign planted weaknesses; serves the gate's token so ownership is proven *for
  real*. No Docker required.
- **Scenarios** (`scenarios`) — YAML + seeded randomizer so runs can't be won by
  memorization.
- **Non-destructive detection** (`detect`) — a gated outbound client (the only
  way out) and observation-only checks that map to the OWASP Top 10.
- **Referee + scoring** (`engine`) — turn-based tick loop, ≤3 actions/team/tick,
  action validation, blue defensive whitelist (no free shell), MITRE ATT&CK
  tagging, a kill switch, and a transparent resilience score.
- **Scripted agents** (`agents`) — baseline red/blue bots (the bar the LLM teams
  must beat) + a no-op blue to prove scenarios are solvable.
- **Resilience report** (`report`) — HTML / Markdown / PDF, OWASP mapping,
  severity, mitigations, timeline, and the audit trail.
- **Live arena API** (`api`) — FastAPI + WebSocket split-screen view.
- **CLI** (`cli.py`) and the **orchestrator** (`engagement.py`).
- **CI** that runs the scripted-bot smoke tests and a safety-invariant gate.

**79 tests passing.** See [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) and
[`docs/authz.md`](docs/authz.md).

## Not yet built (honest status)

LLM-backed red/blue agents (provider-agnostic), the Docker-backed range,
multi-tenant/RBAC/OAuth platform security, the model leaderboard across seeded
runs, MCP bring-your-own-agent, OpenTelemetry tracing, and the Next.js web app.
The current arena view is a single served HTML page, not a Next.js app. The
interfaces (`Range`, `Agent`, the gated client) are shaped so these slot in
without touching the safety core.

## Develop

```bash
uv pip install -e ".[dev]"
uv run pytest
```
