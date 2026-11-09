# Architecture

Sentinel Arena is a serious resilience-audit core wrapped in a watchable arena.
Everything an agent does flows through the authorization gate and the referee —
there is no path to the target that skips them.

## Data flow of one engagement

```
 scenario.yaml ──► randomizer(seed) ──► range (bundled vulnerable app, 127.0.0.1)
                                              │  serves /.well-known token
 authorization gate ◄── ownership proof ◄─────┘
     │  (verified scope, immutable consent, hash-chained audit log)
     ▼
 referee tick loop
   ├─ benign traffic (legit users)
   ├─ RED team  → propose ≤3 actions → gate.check → gated HTTP → detect findings
   ├─ BLUE team → propose ≤3 actions (whitelist only) → query logs / block_ip
   ├─ validate + execute + log + MITRE ATT&CK tag + score
   ▼
 event store (JSONL)  ──►  resilience report (HTML / Markdown / PDF)
                      └─►  live arena view (WebSocket)
```

## Packages (`sentinel_arena/`)

| Package | Role |
| --- | --- |
| `authz/` | **Built first.** Ownership verification, scope engine, consent, hash-chained audit log, the gate. |
| `range/` | Lifecycle for the bundled sandbox target (in-process `http.server`; Docker is a future swap-in behind the same `Range` interface). |
| `scenarios/` | Pydantic scenario schema + seeded randomizer + `shop-01` YAML. |
| `detect/` | Gated outbound client (the only way out), non-destructive checks, findings + OWASP catalog. |
| `telemetry/` | Append-only event store (replay source of truth) + benign traffic generator. |
| `engine/` | Referee tick loop, action models + blue whitelist, scoring, resilience score, ATT&CK map, kill switch. |
| `agents/` | Agent interface + scripted red / blue / no-op baselines (LLM teams are a later milestone). |
| `report/` | Resilience audit report generator (HTML / Markdown / PDF). |
| `api/` | Optional FastAPI + WebSocket live arena (`api` extra). |
| `cli.py` | Typer CLI: `run`, `replay`, `scenarios`, `verify-audit`. |
| `engagement.py` | The orchestrator that wires it all into one `run_engagement`. |

## Why the referee is the single authority

Agents only *propose* actions. The referee validates format and permission,
executes through trusted executors, logs every event, tags ATT&CK, and scores.
This keeps runs deterministic and replayable, and means an LLM agent (a later
milestone) can never do anything a scripted one can't — the vocabulary and the
gate bound them identically.

## Scoring, in one paragraph

Red earns points for *progress* (recon, paths, findings weighted by severity,
flag). Blue earns points for correct, fast detection, for blocking the attacker
before the flag, and for keeping services alive (SLA) and legitimate users
served — and loses points for blocking legitimate users. So the degenerate
"block everyone" defense scores badly, which is the intended incentive. The
0–100 resilience score is a transparent function of these terms (see
`engine/scoring.py`).

## Swapping the in-process range for Docker

`range/runner.py` exposes `bring_up(...) -> Range` and a `Range` with
`base_url`, `health_ok`, `block/unblock`, `shutdown`. A Docker-backed range
implements the same surface (compose up/down, internal network, no internet,
`docker exec` for blocks) without touching the engine, detection, or agents.
The in-process range is what makes the zero-dependency, no-Docker demo and CI
possible.
