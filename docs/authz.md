# Authorization gate + scope engine (`sentinel_arena.authz`)

This is the crux component and it ships before any attack logic. **Nothing in
the platform may touch a host until the gate has verified ownership of that
exact host and the action is inside the authorized scope.**

## The four steps

```python
from datetime import datetime, timedelta, timezone
from sentinel_arena.authz import (
    AuthorizationGate, AuditLog, OwnershipVerifier,
    Scope, RateCap, Environment, VerificationMethod,
)
from sentinel_arena.authz.verification_live import LiveDnsResolver, LiveHttpClient

now = datetime.now(timezone.utc)
secret = b"...load from a vault, never hard-code..."

gate = AuthorizationGate(
    secret=secret,
    verifier=OwnershipVerifier(dns=LiveDnsResolver(), http=LiveHttpClient()),
    audit=AuditLog("var/audit.jsonl"),
)

# 1. Issue a challenge — show the user what to publish.
ch = gate.issue_challenge("user1", "staging.example.com", VerificationMethod.DNS_TXT)
print(ch.dns_txt_name, "=>", ch.dns_txt_value)

# 2. User publishes the TXT record / well-known file / meta tag.

# 3. Authorize: verify the proof and record immutable consent.
scope = Scope(
    allowed_hosts=["staging.example.com"],
    allowed_paths=["/app", "/api"],
    blocklist=["admin.example.com"],
    rate_cap=RateCap(max_requests=100, per_seconds=60),
    environment=Environment.STAGING,
    not_before=now,
    not_after=now + timedelta(hours=8),
)
consent = gate.authorize("user1", "staging.example.com",
                         VerificationMethod.DNS_TXT, scope)

# 4. Per-request guard — every downstream action calls this first.
gate.check("user1", "staging.example.com", "/app/login", scope)  # raises if not allowed
```

## What each piece enforces

| Concern | Where | Rule |
| --- | --- | --- |
| Ownership proof | `verification.py`, `gate.authorize` | DNS TXT / well-known file / meta tag must carry the user's per-host token. Tokens are HMAC(secret, `user:host`) — stable, unforgeable without the secret, so one user cannot ride another's proof. |
| Scope | `scope.py` | Blocklist wins, then allowlist, then path prefix, then time window. Frozen Pydantic model. |
| Staging-first | `scope.py` validators | Production scopes are capped: ≤ 60 req/min and ≤ 4 h window, enforced at construction. |
| Proof expiry | `gate.Proof` | Proofs are time-boxed (default 24 h); `check` re-validates freshness every call. |
| Tamper-evidence | `audit.py` | Append-only JSONL, SHA-256 hash chain; `verify_chain()` detects any edit or deletion. |
| Inert until proven | `gate.check` | Raises `OwnershipNotProven` until `authorize` succeeds for that exact (user, host). |

Every step — including **every denial** — is written to the audit log.

## Testing

```
uv run pytest tests/authz
```

Network I/O is injected (`DnsResolver` / `HttpClient` protocols), so the suite
runs fully offline with in-memory fakes.
