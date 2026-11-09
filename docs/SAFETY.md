# Safety invariants

These are hard invariants. They must survive every refactor. CI should fail if
any is removed, and any feature that would violate one is refused in favor of
the authorized equivalent.

1. **Authorization gate before anything.** No scan, probe, or agent action runs
   against a target unless the user has cryptographically proven ownership of
   that exact host (DNS TXT record, `/.well-known/sentinel-arena.txt`, or a meta
   tag holding a per-user token) — never a checkbox or self-asserted claim.
2. **Non-destructive only.** Detect weaknesses and, at most, safely validate
   them against a staging environment the user provides. Never crash, DoS,
   deface, brute-force at harmful volume, or exfiltrate data from a live
   production target. Resilience is inferred from detection plus controlled
   validation, never from taking a target down.
3. **Sandbox-only demos/tests/CI.** These hit only self-deployed vulnerable apps
   (OWASP Juice Shop, DVWA, or a bundled vulnerable app) inside an isolated
   sandbox — never a third-party site.
4. **No "attack any URL" mode.** The target input stays inert until the gate
   passes for that specific host and scope. Scope is explicit and enforced on
   every request.
5. **No weaponized exploit chains against third parties.** Red-team techniques
   are a curated, non-destructive detection set, run only against owned or
   sandbox targets.
6. **Tamper-evident audit trail.** Every action is written append-only with the
   authorizing user, the verified scope, a timestamp, and a hash chain.
7. **Kill switch, rate limiting, and staging-first are mandatory.** One control
   halts all agents instantly.

## Where each is enforced today

| # | Enforced by | Covered by tests |
| --- | --- | --- |
| 1 | `authz.gate.AuthorizationGate` (ownership proof required before `check` passes) | ✅ `test_gate.py` |
| 2 | Design constraint; detection set is non-destructive (not yet built) | — |
| 3 | Design constraint for `range/` + CI (not yet built) | — |
| 4 | `authz.gate.check` raises `OwnershipNotProven` until authorized; `authz.scope` enforces scope per request | ✅ `test_gate.py`, `test_scope.py` |
| 5 | Design constraint (no attack logic exists yet) | — |
| 6 | `authz.audit.AuditLog` (append-only, SHA-256 hash chain) | ✅ `test_audit.py` |
| 7 | Staging-first caps in `authz.scope`; kill switch + rate limiting live in `engine/` (not yet built) | ✅ (staging caps) `test_scope.py` |

As later milestones land, fill in the remaining rows rather than relaxing any
invariant.
