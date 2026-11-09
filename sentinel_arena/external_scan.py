"""External posture assessment - the safe realization of "scan the site I own".

Unlike a campaign (a sandbox simulation), this touches a *real* host, so it is
fenced in hard:

1. Ownership is **re-verified live** against the host, right now, through the
   authorization gate - a stale "ownership_proven" flag is never trusted.
2. Every request goes through the gated client (proof + scope + rate cap), and
   the scan is observation-only: a single ``GET /`` whose headers are analyzed.
3. No red/blue arena, no payloads, no path fuzzing.

If verification fails, nothing is scanned. The result reuses ``CampaignResult``
so the store, API and UI treat an external assessment like any other verdict.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from .authz import (
    AuditLog,
    AuthorizationGate,
    Environment,
    OwnershipVerifier,
    RateCap,
    Scope,
    VerificationMethod,
    make_challenge,
)
from .authz.errors import VerificationFailed
from .campaign import CampaignResult, _dedup_vulnerabilities
from .detect.client import GatedHttpClient
from .detect.external import scan_external_headers
from .store.base import DEFAULT_TENANT

SCANNER = "sentinel-scanner"


def _grade_from_score(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def run_external_assessment(
    host: str,
    *,
    verifier: OwnershipVerifier,
    secret: bytes,
    method: VerificationMethod = VerificationMethod.DNS_TXT,
    user_id: str = SCANNER,
    tenant_id: str = DEFAULT_TENANT,
    base_url: str | None = None,
    audit_path: str | None = None,
    rate_cap: RateCap | None = None,
    label: str = "",
) -> CampaignResult:
    """Verify ownership of ``host`` live, then run the observation-only header
    scan. Raises :class:`VerificationFailed` if ownership cannot be proven.

    ``base_url`` defaults to ``https://<host>``; it is injectable so tests can
    point at a self-owned sandbox. ``verifier`` carries the live resolvers in
    production (``[verify]`` extra) or fakes in tests.
    """
    now = datetime.now(timezone.utc)
    audit = AuditLog(audit_path or f"var/external/{host}-audit.jsonl")
    scope = Scope(
        allowed_hosts=[host],
        allowed_paths=["/"],                      # root only; passive
        blocklist=[],
        rate_cap=rate_cap or RateCap(max_requests=10, per_seconds=60),
        environment=Environment.PRODUCTION,
        not_before=now - timedelta(minutes=1),
        not_after=now + timedelta(minutes=30),
    )
    gate = AuthorizationGate(secret=secret, verifier=verifier, audit=audit)

    # Live ownership proof, right now. Raises VerificationFailed if it fails.
    gate.authorize(user_id, host, method, scope)

    client = GatedHttpClient(
        gate=gate, user_id=user_id, host=host,
        base_url=base_url or f"https://{host}", scope=scope, actor="scanner",
    )
    findings = scan_external_headers(client)

    rows = [{"findings": [f.model_dump(mode="json") for f in findings]}]
    vulns = _dedup_vulnerabilities(rows)

    # Posture score from the weight of what was found (no arena here).
    weight = sum({"critical": 40, "high": 25, "medium": 12, "low": 5, "info": 1}
                 .get(v.severity, 5) for v in vulns)
    score = max(0, 100 - weight)
    severity_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    for v in vulns:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        owasp_counts[v.owasp] = owasp_counts.get(v.owasp, 0) + 1

    return CampaignResult(
        id=f"ext-{uuid.uuid4().hex[:10]}",
        target=host, label=label or host, depth="external",
        created_at=now.isoformat(), runs=1,
        scenarios=["external-posture"], reds=[], blues=[], seeds=[],
        posture_grade=_grade_from_score(score),
        mean_resilience=float(score), worst_resilience=score, best_resilience=score,
        attacker_win_rate=0.0,
        vulnerabilities=vulns, severity_counts=severity_counts,
        owasp_coverage=owasp_counts, matchups=[],
    )


def make_scanner_secret() -> bytes:
    import secrets as _s
    return _s.token_bytes(32)
