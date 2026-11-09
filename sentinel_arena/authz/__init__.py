"""Authorization gate + scope engine — the crux of Sentinel Arena.

This package ships before any attack logic. Nothing in the platform may act
against a host until :class:`AuthorizationGate` has verified ownership of that
exact host and the action is inside the authorized :class:`Scope`.
"""

from __future__ import annotations

from .audit import AuditEntry, AuditLog, ChainBroken
from .consent import ConsentRecord
from .errors import (
    AuthzError,
    Blocked,
    InvalidScope,
    OutOfScope,
    OwnershipNotProven,
    ScopeExpired,
    VerificationFailed,
)
from .gate import AuthorizationGate, Proof
from .scope import Environment, RateCap, Scope, ScopeDecision
from .tokens import VerificationChallenge, expected_token, make_challenge
from .verification import (
    OwnershipVerifier,
    StdlibHttpClient,
    VerificationMethod,
    VerificationResult,
)

__all__ = [
    "AuditEntry",
    "AuditLog",
    "ChainBroken",
    "ConsentRecord",
    "AuthzError",
    "Blocked",
    "InvalidScope",
    "OutOfScope",
    "OwnershipNotProven",
    "ScopeExpired",
    "VerificationFailed",
    "AuthorizationGate",
    "Proof",
    "Environment",
    "RateCap",
    "Scope",
    "ScopeDecision",
    "VerificationChallenge",
    "expected_token",
    "make_challenge",
    "OwnershipVerifier",
    "StdlibHttpClient",
    "VerificationMethod",
    "VerificationResult",
]
