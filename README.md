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
arena bench --seeds 42,7,101,2,5        # leaderboard across agents + seeds
```

## Leaderboard (honest benchmark)

`arena bench` runs a red × blue agent cross-product over many seeds. Agents are
registry entries, so a future LLM/MCP agent appears here the same way. Current
results on `shop-01` over 5 seeds (42, 7, 101, 2, 5):

| Red | Blue | Runs | Attacker win % | Mean resilience | Mean red | Mean blue | Mean ticks-to-detect |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| scripted | scripted | 5 | 0% | 88.0 | 13.0 | 48.0 | 1.0 |
| scripted | noop | 5 | 100% | 30.0 | 62.0 | 20.0 | – |

Read: the scripted defender detects the attacker on tick 1 and stops every flag
capture (0% attacker win, resilience 88); a passive defender loses every time
(100% attacker win, resilience 30). Only two agents are registered today, so the
table is small — but it is produced by the real harness, not hand-written.

## Watch it live

Two frontends. A **Next.js app** (the primary UI — live arena with a React Flow
network map, leaderboard, and report pages):

```bash
uv pip install -e ".[api]"
uvicorn sentinel_arena.api.server:app      # backend on :8000

cd web && npm install && npm run dev       # UI on http://localhost:3000
```

Or a zero-build **single served page** at `http://127.0.0.1:8000` (same backend,
no Node needed).

PDF export turns on with `.[pdf]`. An LLM red/blue agent (`--red llm` / `--blue
llm`) turns on with `.[llm]` and an `ANTHROPIC_API_KEY`. A Docker-hosted range
(`range_backend="docker"`) turns on with `.[docker]`.

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
- **Live arena API** (`api`) — FastAPI + WebSocket.
- **Next.js frontend** (`web/`) — React + React Flow live arena, leaderboard, and
  report pages. Builds and type-checks cleanly.
- **Leaderboard** (`leaderboard.py`) — real benchmark harness across agents + seeds.
- **LLM agents** (`agents/llm.py`) — provider-agnostic, plug into the same
  interface; Anthropic adapter behind the `llm` extra.
- **Docker-backed range** (`range/docker_runner.py` + `Dockerfile` + compose) —
  same `Range` interface, internal network, no docker.sock.
- **CLI** (`cli.py`), the **orchestrator** (`engagement.py`), and **CI** that runs
  the scripted-bot smoke tests + a safety-invariant gate.

**88 Python tests passing** + the Next.js app builds. See
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md), [`docs/authz.md`](docs/authz.md),
[`web/README.md`](web/README.md), and [`docs/DEMO.md`](docs/DEMO.md).

## Honest status of the harder pieces

- **LLM agents** are written and unit-tested with a fake client, but not yet run
  against a live model here (needs an API key).
- **The Docker range** is written to the same interface but **not exercised by
  the offline suite** (this environment has no Docker); the in-process range is
  the tested default. Shipping request telemetry out of the container to the
  blue team's log store is a further step.
- **The demo GIF** must be recorded on your machine — see [`docs/DEMO.md`](docs/DEMO.md).

Still not built: multi-tenant/RBAC/OAuth + secrets vault, MCP bring-your-own-agent,
and OpenTelemetry tracing. The `Range`, `Agent`, and gated-client interfaces are
shaped so these slot in without touching the safety core.

## Develop

```bash
uv pip install -e ".[dev]"
uv run pytest
```
