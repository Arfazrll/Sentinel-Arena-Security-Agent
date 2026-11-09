"""The authorization gate — the single entry point every component must pass.

Lifecycle:

1. ``issue_challenge(user, host, method)`` → hand the user the token + where to
   place it.
2. User publishes the proof (DNS / well-known / meta).
3. ``authorize(user, host, method, scope)`` → verify the proof, and if good,
   record an immutable :class:`ConsentRecord` plus a valid, time-boxed proof.
4. ``check(user, host, path)`` → the per-request guard. Downstream code
   (recon, detection, outbound HTTP) calls this before *every* action. It
   raises unless there is a current proof for that exact host **and** the
   host/path/time fall inside the authorized scope.

Every step writes to the tamper-evident :class:`AuditLog`, including — crucially
— every denial. Until ``authorize`` succeeds for a specific host, ``check``
raises :class:`OwnershipNotProven`, so the target stays inert.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .audit import AuditLog
from .consent import ConsentRecord
from .errors import InvalidScope, OutOfScope, OwnershipNotProven, VerificationFailed
from .scope import Scope
from .tokens import make_challenge
from .verification import (
    OwnershipVerifier,
    VerificationChallenge,
    VerificationMethod,
    VerificationResult,
)

DEFAULT_PROOF_TTL = timedelta(hours=24)


@dataclass
class Proof:
    """A verified-ownership fact with an expiry. Re-verification refreshes it."""

    user_id: str
    host: str
    method: VerificationMethod
    verified_at: datetime
    expires_at: datetime

    def is_valid(self, now: datetime) -> bool:
        return self.verified_at <= now < self.expires_at


class AuthorizationGate:
    def __init__(
        self,
        *,
        secret: bytes,
        verifier: OwnershipVerifier,
        audit: AuditLog,
        proof_ttl: timedelta = DEFAULT_PROOF_TTL,
        rotation: int = 0,
        clock=lambda: datetime.now(timezone.utc),
    ) -> None:
        if not secret:
            raise ValueError("gate secret must not be empty")
        self._secret = secret
        self._verifier = verifier
        self._audit = audit
        self._proof_ttl = proof_ttl
        self._rotation = rotation
        self._clock = clock
        # Keyed by (user_id, host). In-memory here; a persistent store is a
        # later concern, but the audit log already durably records every grant.
        self._proofs: dict[tuple[str, str], Proof] = {}

    # --- step 1: challenge ----------------------------------------------
    def issue_challenge(
        self, user_id: str, host: str, method: VerificationMethod
    ) -> VerificationChallenge:
        challenge = make_challenge(
            user_id, host, secret=self._secret, rotation=self._rotation
        )
        self._audit.append(
            actor=user_id,
            action="challenge_issued",
            host=challenge.host,
            outcome="info",
            detail={"method": method.value},
        )
        return challenge

    # --- step 3: authorize ----------------------------------------------
    def authorize(
        self,
        user_id: str,
        host: str,
        method: VerificationMethod,
        scope: Scope,
    ) -> ConsentRecord:
        """Verify ownership and, on success, record consent + a live proof.

        The scope must not authorize any host other than the one just verified
        in this call; multi-host scopes require a successful ``authorize`` per
        host before ``check`` will pass for them.
        """
        challenge = make_challenge(
            user_id, host, secret=self._secret, rotation=self._rotation
        )
        norm_host = challenge.host

        # Guard: the host being authorized must actually be in the scope, and
        # must not be blocklisted by that same scope.
        if norm_host not in scope.allowed_hosts:
            self._deny("authorize", user_id, norm_host, scope,
                       "host not present in scope.allowed_hosts")
            raise InvalidScope(f"{norm_host} is not in scope.allowed_hosts")
        if norm_host in scope.blocklist:
            self._deny("authorize", user_id, norm_host, scope,
                       "host is blocklisted by its own scope")
            raise InvalidScope(f"{norm_host} is blocklisted by its own scope")

        result: VerificationResult = self._verifier.verify(challenge, method)
        if not result.verified:
            self._deny("authorize", user_id, norm_host, scope,
                       f"ownership verification failed: {result.detail}")
            raise VerificationFailed(
                f"could not verify ownership of {norm_host}: {result.detail}"
            )

        now = self._clock()
        self._proofs[(user_id, norm_host)] = Proof(
            user_id=user_id,
            host=norm_host,
            method=method,
            verified_at=result.checked_at,
            expires_at=now + self._proof_ttl,
        )
        consent = ConsentRecord(
            user_id=user_id,
            scope=scope,
            method=method,
            verified_at=result.checked_at,
        )
        self._audit.append(
            actor=user_id,
            action="authorized",
            host=norm_host,
            scope_fingerprint=scope.fingerprint(),
            outcome="allow",
            detail={
                "method": method.value,
                "consent_id": consent.id,
                "environment": scope.environment.value,
                "expires_at": self._proofs[(user_id, norm_host)].expires_at.isoformat(),
            },
        )
        return consent

    # --- step 4: per-request guard --------------------------------------
    def check(
        self,
        user_id: str,
        host: str,
        path: str,
        scope: Scope,
        *,
        now: datetime | None = None,
    ) -> None:
        """Raise unless (user, host) has a live proof AND (host, path, time) are
        within ``scope``. Logs the outcome either way."""
        now = now or self._clock()
        from .tokens import _normalize_host

        try:
            norm_host = _normalize_host(host)
        except ValueError as e:
            self._deny("check", user_id, str(host), scope, f"invalid host: {e}")
            raise OutOfScope(f"invalid host: {e}") from e

        proof = self._proofs.get((user_id, norm_host))
        if proof is None or not proof.is_valid(now):
            reason = "no proof on record" if proof is None else "proof expired"
            self._deny("check", user_id, norm_host, scope, reason)
            raise OwnershipNotProven(f"{norm_host}: {reason}")

        # Scope enforcement (blocklist wins, then allowlist, path, window).
        try:
            scope.enforce(norm_host, path, now)
        except Exception as e:
            self._deny("check", user_id, norm_host, scope,
                       f"{type(e).__name__}: {e}", path=path)
            raise

        self._audit.append(
            actor=user_id,
            action="check",
            host=norm_host,
            scope_fingerprint=scope.fingerprint(),
            outcome="allow",
            detail={"path": path},
        )

    def is_authorized(self, user_id: str, host: str, now: datetime | None = None) -> bool:
        """Non-raising: does (user, host) currently hold a live proof?"""
        from .tokens import _normalize_host

        now = now or self._clock()
        try:
            norm_host = _normalize_host(host)
        except ValueError:
            return False
        proof = self._proofs.get((user_id, norm_host))
        return proof is not None and proof.is_valid(now)

    def revoke(self, user_id: str, host: str) -> None:
        from .tokens import _normalize_host

        norm_host = _normalize_host(host)
        self._proofs.pop((user_id, norm_host), None)
        self._audit.append(
            actor=user_id, action="revoked", host=norm_host, outcome="info"
        )

    # --- internal --------------------------------------------------------
    def _deny(self, action, user_id, host, scope, reason, path=None) -> None:
        detail = {"reason": reason}
        if path is not None:
            detail["path"] = path
        self._audit.append(
            actor=user_id,
            action=action,
            host=host,
            scope_fingerprint=scope.fingerprint() if scope else "",
            outcome="deny",
            detail=detail,
        )
