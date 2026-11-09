# Sentinel Arena

An authorized, non-destructive multi-agent **security-resilience** platform. Two
agent teams — red (attacker) and blue (defender) — run a controlled engagement
against a target you own, the engagement is watchable live, and it produces a
resilience audit report.

> **This is an authorized security-testing platform, not an attack tool.** No
> component acts against any host until ownership of that exact host is
> cryptographically proven and the action falls inside an explicit, enforced
> scope. Demos and CI run only against self-deployed vulnerable apps in an
> isolated sandbox.

## Status

Early, built in milestone order. Shipped so far:

- **Authorization gate + scope engine** (`sentinel_arena.authz`) — the safety
  crux, built first. Ownership verification (DNS TXT / well-known file / meta
  tag), a frozen scope model with blocklist/allowlist/path/time-window
  enforcement and staging-first production caps, immutable consent records, and
  a tamper-evident hash-chained audit log. **50 tests, all passing.**
  See [`docs/authz.md`](docs/authz.md).

Not yet built: range control, scenarios, agents, referee/scoring, API, web
arena, reports. Per the build rule, **no attack logic is written until the gate
is in place** — which it now is, so those are next.

## Develop

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"
uv run pytest
```

## Safety invariants

The non-negotiable invariants (authorization gate before any action,
non-destructive only, sandbox-only demos, explicit enforced scope, no weaponized
chains, tamper-evident audit trail, kill switch + rate limiting + staging-first)
are tracked in [`docs/SAFETY.md`](docs/SAFETY.md). CI is intended to fail if any
is removed.
