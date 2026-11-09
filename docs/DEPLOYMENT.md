# Deployment & scale architecture

How Sentinel Arena goes from a single-node demo to a multi-tenant service that
can carry tens of thousands of users. This document is explicit about **what is
implemented today** versus **what is the recommended target architecture**, so
nobody mistakes a diagram for a shipped feature.

> The non-negotiable: *scale changes the plumbing, never the safety model.* The
> authorization gate (`sentinel_arena/authz/`) sits in front of every action at
> every tier. Caching, load balancing and sharding make it faster and bigger;
> they never give any tier a way to act against a host whose ownership is not
> proven. See [`SAFETY.md`](SAFETY.md).

---

## 1. Tiers

```
                         ┌───────────────────────────────┐
   Browser / MCP client  │   CDN + WAF  (static, DDoS)   │
        │                └───────────────┬───────────────┘
        ▼                                ▼
  ┌───────────┐   HTTPS/WSS   ┌─────────────────────┐
  │  Next.js  │──────────────▶│   Load balancer     │  sticky by engagement id
  │  web (SSR)│               │  (L7, TLS term.)    │
  └───────────┘               └──────────┬──────────┘
                                         ▼
                    ┌────────────────────────────────────────┐
                    │  API tier  (FastAPI, stateless, N pods) │
                    │  - auth / rate limit / scope enforcement │
                    │  - enqueue campaigns + engagements       │
                    └───────┬───────────────────────┬─────────┘
                            ▼                        ▼
                    ┌──────────────┐        ┌──────────────────┐
                    │  Redis       │        │  Postgres        │
                    │  cache +     │        │  (tenants, runs, │
                    │  queue +     │        │   findings,      │
                    │  pub/sub     │        │   audit chain)   │
                    └──────┬───────┘        └──────────────────┘
                           ▼
                    ┌──────────────────────────────────────────┐
                    │  Worker tier  (engagement runners)        │
                    │  - pull jobs, run the referee loop        │
                    │  - each target range in its OWN sandbox   │
                    │    (gVisor / Firecracker / per-job netns) │
                    └──────────────────────────────────────────┘
```

The web, API and worker tiers are **separate deployables** so each scales on its
own axis: the API on request volume, the workers on simulation volume.

---

## 2. What is implemented today

- **Pluggable persistence** (`sentinel_arena/store/`) — one `Store` interface,
  two interchangeable backends selected by env:
  - `FilesystemStore` — JSON under `$ARENA_DATA_DIR/store` (default, no deps).
  - `SqlStore` — SQLAlchemy models that run **unchanged on SQLite and Postgres**.
    Set `ARENA_DB_URL=postgresql+psycopg://…` (and install `.[db]` + a psycopg
    driver) to point every API replica at one shared database; `ARENA_STORE=sql`
    with no URL uses a local SQLite file. Both backends pass the same contract
    suite (`tests/test_store.py`). `/healthz` reports which one is live.
- **Multi-tenancy from the foundation** — every record (tenants, targets,
  campaigns, findings, engagement index) is scoped by `tenant_id` (default
  `default`); the API reads it from the `X-Tenant-Id` header. Postgres RLS then
  enforces the same boundary at the database (see §4).
- **Stateless API** (`sentinel_arena/api/server.py`) — durable state lives in the
  store, so a second replica serves the same history. Heavy per-engagement
  artifacts (events/audit JSONL, reports) stay as files; the store holds the
  metadata and a pointer — the standard blob pattern.
- **In-process job runner** — engagements and campaigns run on daemon threads
  with a concurrency cap (`MAX_CONCURRENT`). Each engagement stands up its **own
  ephemeral range** on its own port, so runs are already isolated from each other.
- **Campaign fan-out** (`sentinel_arena/campaign.py`) — one target → a matrix of
  engagements → one aggregated, de-duplicated, risk-ranked verdict. Supports a
  thread pool (`max_workers`).
- **Tamper-evident audit log** (`sentinel_arena/authz/audit.py`) — a hash-chained
  JSONL ledger; `arena verify-audit` checks the chain.
- **MCP surface** (`sentinel_arena/mcp/server.py`) — orchestration + reporting
  tools over stdio for any MCP client.

## 3. The seams that make the rest a config change, not a rewrite

Each external dependency is reached through a small interface, so swapping the
single-node implementation for a distributed one touches one file:

| Concern            | Interface / seam                              | Today (single node)        | At scale                                   |
| ------------------ | --------------------------------------------- | -------------------------- | ------------------------------------------ |
| Target range       | `range.Range` (`runner.py`, `docker_runner.py`) | in-process http.server   | per-job micro-VM / gVisor sandbox          |
| Persistence        | `$ARENA_DATA_DIR` reader/writer               | JSONL + JSON on disk       | Postgres (see §4)                          |
| Job scheduling     | `threading.Thread` launch in the API          | daemon threads             | Redis queue + worker pool (see §5)         |
| Live event stream  | `telemetry.EventStore` + WebSocket            | in-memory fan-out          | Redis pub/sub → WS gateway                 |
| Ownership proof    | `authz.OwnershipVerifier`                      | stdlib HTTP / DNS resolver | same, behind the API; proof cache in Redis |
| Secrets            | `secret=` passed into the gate                | env / per-process          | KMS / Vault (see §7)                        |

---

## 4. Database (Postgres)

The filesystem store is fine for one node; a fleet needs a shared transactional
store. The SQLAlchemy models in `sentinel_arena/store/sql.py` already define the
core of this schema (tenants, targets, campaigns, vulnerabilities, engagement
index) and run on Postgres today. Full target schema:

- `tenants`, `users`, `memberships` — multi-tenancy and RBAC.
- `targets` — one row per (tenant, host) with its **ownership-proof** state and
  expiry, so a worker can re-check "is this still proven?" in one indexed read.
- `campaigns`, `engagements` — the run records; `engagements.campaign_id` FKs up.
- `findings` — one row per detected weakness, keyed by `rule_id` for the
  campaign-level de-duplication that `campaign._dedup_vulnerabilities` does today
  in memory.
- `audit_entries` — the hash chain, **append-only**; `prev_hash`/`entry_hash`
  columns preserve the exact verification the JSONL log uses. Grant the app role
  `INSERT`/`SELECT` only — no `UPDATE`/`DELETE` — so the ledger is immutable at
  the database level, not just by convention.

**Security of the DB itself:** row-level security keyed by `tenant_id` so one
tenant can never read another's findings; TLS required; least-privilege roles
(migrations role ≠ app role); encryption at rest; PITR backups. No target
credentials are ever stored — Sentinel Arena only ever holds an *ownership
proof*, never a secret for the target.

---

## 5. Caching & queueing (Redis)

- **Ownership-proof cache** — proven `(user, host) → expiry` cached with a TTL
  matching the proof TTL, so the gate's hot path is a memory read, not a DNS/HTTP
  round-trip. A miss falls back to the verifier; a revocation deletes the key.
- **Read-through cache** for expensive aggregates (leaderboards, campaign
  verdicts) keyed by their inputs; campaign results are immutable once finished,
  so they cache indefinitely.
- **Job queue** — campaigns/engagements become queue entries; the worker tier
  consumes them. This is what lets "paste a target, run deep (hundreds of
  engagements)" not block an API thread.
- **Pub/sub** for the live arena: workers publish referee events; a thin
  WebSocket gateway relays them to subscribed browsers, so the WS tier scales
  independently of the workers.

Cache rule: the gate's **deny** path is never cached in a way that could turn
into an **allow** — only positive, time-boxed proofs are cached, and any doubt
re-verifies.

---

## 6. Load balancing & HA

- **L7 load balancer**, TLS terminated at the edge, HTTP/2 + WebSocket.
- **API tier** is stateless → round-robin, N replicas, horizontal autoscale on
  CPU/RPS. Health via `/healthz`.
- **WebSocket tier**: sticky routing by engagement id (consistent hashing) so a
  viewer stays pinned to the relay holding that stream.
- **Worker tier**: scale on queue depth. A worker failure re-queues its job
  (at-least-once); engagements are deterministic by seed, so a re-run reproduces.
- **Multi-AZ**: stateless tiers spread across zones; Postgres primary + sync
  standby with automatic failover; Redis in HA/cluster mode.

---

## 7. Security posture of the platform

Beyond the authorization gate (the product's core), the *service* is hardened:

- **Egress control** — the worker tier is the only thing that talks to targets,
  and only through the gated client. Network policy blocks all other egress, so a
  bug cannot reach an unintended host even in principle.
- **Sandbox isolation** — each target range runs in its own micro-VM / gVisor
  sandbox with no host mounts and no access to the Docker socket.
- **Secrets** in KMS/Vault; the gate secret and DB creds are never in images or
  env dumps. Rotation is supported by the token `rotation` epoch (see
  `authz/tokens.py`), which invalidates all outstanding proofs on bump.
- **AuthN/Z** — OIDC/SSO at the edge; RBAC per tenant; every API action is scope-
  and tenant-checked server-side, never trusting the client.
- **Rate limiting & abuse** — per-tenant quotas on campaigns and on verification
  attempts; WAF + CDN absorb volumetric attacks before the API.
- **Tenant isolation** — Postgres RLS + per-tenant cache namespaces + per-job
  sandboxes mean data, compute and network are all partitioned by tenant.
- **Supply chain** — pinned deps (`uv.lock`), SBOM, image signing, CI safety-gate
  (`.github/workflows/ci.yml` runs the safety-invariant suite on every push).

---

## 8. Observability

- **Metrics** (Prometheus): request/latency/error on the API; queue depth and
  job duration on workers; gate allow/deny counters (a spike in denies is a
  signal); cache hit ratio.
- **Tracing** (OpenTelemetry): a trace per campaign spanning its child
  engagements, so a slow deep run is debuggable end to end.
- **Logs**: structured JSON, shipped centrally. The **audit log is not logging** —
  it is a separate, verifiable ledger and must never be sampled or dropped.
- **SLOs**: assessment start latency, time-to-first-event on the live arena, and
  campaign completion time per depth tier.

---

## 9. Rollout sequence (suggested)

1. ~~Lift persistence behind a store seam; implement SQL (SQLite + Postgres).~~
   **Done** (`sentinel_arena/store/`). Production flips `ARENA_DB_URL` to Postgres
   and adds RLS; no application change.
2. Move job execution to a Redis queue + a separate worker image (API stops
   running engagements in-process).
3. Add the proof cache and the WS pub/sub relay.
4. Put each target range in a per-job sandbox (gVisor/Firecracker) with egress
   policy.
5. Multi-AZ, autoscaling, SSO/RBAC, per-tenant quotas.

Each step is independently shippable and leaves the safety invariants intact.
