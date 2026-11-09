"""Small process-wide configuration helpers.

The gate secret keys every verification token. In production it comes from a
vault via ``ARENA_GATE_SECRET`` so the same token is reproducible across replicas
and restarts; without it, a per-process random secret is used (fine for a single
dev node - tokens stay valid for the life of the process).
"""

from __future__ import annotations

import os
import secrets as _secrets

_EPHEMERAL: bytes | None = None


def gate_secret() -> bytes:
    global _EPHEMERAL
    env = os.environ.get("ARENA_GATE_SECRET")
    if env:
        return env.encode("utf-8")
    if _EPHEMERAL is None:
        _EPHEMERAL = _secrets.token_bytes(32)
    return _EPHEMERAL


def build_live_verifier():
    """An OwnershipVerifier wired with whatever live resolvers are installed.

    DNS needs the ``verify`` extra (dnspython); well-known/meta fall back to the
    stdlib HTTP client when httpx isn't present. Missing resolvers simply make
    that verification *method* unavailable, never unsafe.
    """
    from .authz import OwnershipVerifier, StdlibHttpClient

    dns = None
    http = None
    try:
        from .authz.verification_live import LiveDnsResolver
        dns = LiveDnsResolver()
    except Exception:
        dns = None
    try:
        from .authz.verification_live import LiveHttpClient
        http = LiveHttpClient()
    except Exception:
        http = StdlibHttpClient()
    return OwnershipVerifier(dns=dns, http=http)
