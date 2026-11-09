"""Small process-wide configuration helpers.

The gate secret keys every verification token. In production it comes from a
vault via ``ARENA_GATE_SECRET`` so the same token is reproducible across replicas
and restarts; without it, a per-process random secret is used (fine for a single
dev node - tokens stay valid for the life of the process).
"""

from __future__ import annotations

import os
import secrets as _secrets
from pathlib import Path

_CACHED: bytes | None = None


def gate_secret() -> bytes:
    """The secret that keys every verification token.

    Resolution order, so a published ownership proof survives a server restart:

    1. ``ARENA_GATE_SECRET`` (a vault value; required for multi-replica so every
       replica computes the same token).
    2. A persisted key file at ``$ARENA_DATA_DIR/.gate_secret`` - generated once,
       then reused. This is what keeps a token stable across restarts on one node.
    3. A per-process random secret, only if the data dir isn't writable (tokens
       then last for the life of the process).
    """
    global _CACHED
    if _CACHED is not None:
        return _CACHED

    env = os.environ.get("ARENA_GATE_SECRET")
    if env:
        _CACHED = env.encode("utf-8")
        return _CACHED

    path = Path(os.environ.get("ARENA_DATA_DIR", "var")) / ".gate_secret"
    try:
        if path.exists():
            _CACHED = bytes.fromhex(path.read_text(encoding="utf-8").strip())
            return _CACHED
        path.parent.mkdir(parents=True, exist_ok=True)
        sec = _secrets.token_bytes(32)
        path.write_text(sec.hex(), encoding="utf-8")
        try:
            os.chmod(path, 0o600)  # best-effort: readable only by the owner
        except Exception:
            pass
        _CACHED = sec
        return _CACHED
    except Exception:
        if _CACHED is None:
            _CACHED = _secrets.token_bytes(32)
        return _CACHED


def dns_verification_available() -> bool:
    """True only if dnspython is actually importable (the ``verify`` extra)."""
    try:
        import dns.resolver  # noqa: F401
        return True
    except Exception:
        return False


_SSL_CTX = None


def ssl_context():
    """A TLS context for outbound HTTPS. Prefers ``truststore`` so Python uses the
    OS trust store (Windows/macOS/Linux) - which does the intermediate-chain
    building browsers do, fixing "unable to get local issuer certificate" against
    sites that ship an incomplete chain. Falls back to the stdlib default.

    Cached and reused (contexts are thread-safe for client use). Never disables
    verification - a security tool must not normalize broken TLS."""
    global _SSL_CTX
    if _SSL_CTX is not None:
        return _SSL_CTX
    import ssl
    try:
        import truststore
        _SSL_CTX = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:
        _SSL_CTX = ssl.create_default_context()
    return _SSL_CTX


def verify_timeout() -> float:
    """Seconds to wait when fetching a well-known file / meta tag over the public
    internet. Generous by default - real sites behind a CDN/TLS can be slow to
    answer a cold request. Override with ``ARENA_VERIFY_TIMEOUT``."""
    try:
        return float(os.environ.get("ARENA_VERIFY_TIMEOUT", "20"))
    except ValueError:
        return 20.0


def build_live_verifier():
    """An OwnershipVerifier wired with whatever live resolvers are installed.

    DNS needs the ``verify`` extra (dnspython); if it is absent, the DNS *method*
    is simply unavailable (``verify`` returns a clear "resolver not configured"
    result instead of crashing). Well-known / meta-tag use httpx when present,
    else the stdlib client, so they always work.
    """
    from .authz import OwnershipVerifier, StdlibHttpClient

    t = verify_timeout()
    dns = None
    if dns_verification_available():
        from .authz.verification_live import LiveDnsResolver
        dns = LiveDnsResolver(timeout=t)

    try:
        import httpx  # noqa: F401
        from .authz.verification_live import LiveHttpClient
        http = LiveHttpClient(timeout=t)
    except Exception:
        http = StdlibHttpClient(timeout=t)
    return OwnershipVerifier(dns=dns, http=http)
