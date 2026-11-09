"""Live network resolvers for ownership verification.

Imported on demand (not at package load) because they need the optional
``verify`` extra: ``pip install 'sentinel-arena[verify]'`` (dnspython + httpx).

These satisfy the :class:`DnsResolver` / :class:`HttpClient` protocols in
``verification.py``. They are intentionally conservative: short timeouts, a
response size cap, and no redirects off the target host, so a verification
probe can never be turned into a heavy or redirected request.
"""

from __future__ import annotations

_MAX_BODY_BYTES = 256 * 1024  # a proof is tiny; never read more than this
_TIMEOUT_SECONDS = 5.0


class LiveDnsResolver:
    """TXT lookups via dnspython."""

    def __init__(self, timeout: float = _TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def txt_records(self, name: str) -> list[str]:
        import dns.resolver  # type: ignore

        try:
            answers = dns.resolver.resolve(name, "TXT", lifetime=self.timeout)
        except Exception:
            return []
        out: list[str] = []
        for rdata in answers:
            # TXT rdata is a sequence of byte strings; join and decode.
            parts = b"".join(getattr(rdata, "strings", []) or [])
            out.append(parts.decode("utf-8", "replace"))
        return out


class LiveHttpClient:
    """HTTPS GET via httpx, with hard timeout, size cap, and no cross-host redirects."""

    def __init__(self, timeout: float = _TIMEOUT_SECONDS) -> None:
        self.timeout = timeout

    def get_text(self, url: str) -> str:
        import httpx  # type: ignore

        from .verification import VERIFIER_USER_AGENT

        # Follow redirects: sites commonly send apex->www or http->https before
        # serving the well-known file.
        with httpx.Client(
            timeout=self.timeout, follow_redirects=True, http2=False
        ) as client:
            resp = client.get(url, headers={"User-Agent": VERIFIER_USER_AGENT})
            resp.raise_for_status()
            body = resp.content[:_MAX_BODY_BYTES]
            return body.decode(resp.encoding or "utf-8", "replace")
