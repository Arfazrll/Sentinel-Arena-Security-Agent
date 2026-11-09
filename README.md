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
arena agents                            # list registered red/blue agents
arena export <dir> --format sarif       # SARIF / ATT&CK Navigator layer / CSV
```

## Leaderboard (honest benchmark)

`arena bench` (or the **Benchmarks** page) runs every red agent against every
blue agent over the same seeds. Agents are registry entries
(`agents/registry.py`), so an LLM/MCP agent appears here the same way. Results
on `shop-01`, seeds 42 and 7, produced by the real harness:

| Red | Blue | Attacker win % | Mean resilience | Mean ticks-to-detect |
| --- | --- | ---: | ---: | ---: |
| Methodical | Real-time SOC | 0% | 88 | 1 |
| Methodical | Batch SOC | 0% | 78 | 2 |
| Methodical | Block-everything | 0% | 74 | - |
| Rush | Real-time SOC | 100% | 43 | 1 |
| Rush | Batch SOC | 100% | 40 | - |
| Rush | No defense | 100% | 40 | - |
| Rush | Block-everything | 100% | 31 | - |
| Methodical | No defense | 100% | 30 | - |

Read: the real-time defender stops the methodical attacker, but the **Rush**
attacker (recon, then straight for the flag) wins before any reactive defender
can respond. That gap is what the benchmark is for. The block-everything
defender is penalized for knocking real users offline.

## Watch it live

The **Next.js app** in `web/` is the main UI:

```bash
uv pip install -e ".[api]"
uvicorn sentinel_arena.api.server:app      # backend on :8000

cd web && npm install && npm run dev       # UI on http://localhost:3000
```

What it gives you:

- **Overview**: latest posture, mean resilience trend, attacker win rate,
  median time to detect, open findings, weaknesses by OWASP category.
- **Live arena**: pick scenario, attacker, defender, seed and pace, then watch
  the match. Agent panels show each agent's current intent and kill-chain
  progress; an interactive attack-surface graph lights up as red probes,
  finds weaknesses, gets blocked or breaches; live score, resilience and
  traffic charts; MITRE ATT&CK coverage; a filterable event log; and an
  **emergency stop** wired to the kill switch.
- **Engagements**: searchable history (persists across API restarts), CSV
  export, and a **compare** view (metric deltas, overlaid timelines, findings
  diff).
- **Engagement detail**: full **replay** with a scrubbable timeline and
  keyboard controls; findings with CWE, CVSS band, priority, fix SLA and
  indicative NIST CSF 2.0 / ISO 27001:2022 / PCI DSS 4.0 / SOC 2 mapping;
  SOC metrics (time to detect, time to contain, dwell) and a term-by-term
  "why this score" breakdown; the hash-chained **audit trail** with live
  verification; exports to **SARIF 2.1.0**, an **ATT&CK Navigator layer**,
  CSV, JSON and Markdown.
- **Benchmarks**: background job with progress, red x blue resilience heatmap,
  ranked matchups, per-seed results.
- **Remediation**: findings de-duplicated across runs into a backlog with
  status tracking and a per-control view.
- **Scenarios**, **Agents** and **Trust & safety** pages, a `Ctrl+K` command
  palette, and light/dark themes.

A zero-build single page is still served at `http://127.0.0.1:8000`.

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
- **Scripted agents** (`agents`) — methodical and rush attackers; real-time,
  batch, block-everything and no-op defenders, all resolved through one
  registry and all limited to the vetted action vocabulary.
- **Resilience report** (`report`) — HTML / Markdown / PDF, OWASP mapping,
  severity, mitigations, timeline, and the audit trail.
- **Live arena API** (`api`) — FastAPI + WebSocket: engagements (start, stop
  via kill switch, events, result, audit, exports), persisted history,
  cross-run findings, background benchmark jobs, agent and scenario catalogs.
- **Platform reporting** (`report/kpis.py`, `compliance.py`, `exports.py`) —
  SOC KPIs, compliance enrichment, SARIF / ATT&CK Navigator / CSV.
- **Next.js frontend** (`web/`) — React + React Flow live arena, leaderboard, and
  report pages. Builds and type-checks cleanly.
- **Leaderboard** (`leaderboard.py`) — real benchmark harness across agents + seeds.
- **LLM agents** (`agents/llm.py`) — provider-agnostic, plug into the same
  interface; Anthropic adapter behind the `llm` extra.
- **Docker-backed range** (`range/docker_runner.py` + `Dockerfile` + compose) —
  same `Range` interface, internal network, no docker.sock.
- **CLI** (`cli.py`), the **orchestrator** (`engagement.py`), and **CI** that runs
  the scripted-bot smoke tests + a safety-invariant gate.

**105 Python tests passing** + the Next.js app builds. See
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
