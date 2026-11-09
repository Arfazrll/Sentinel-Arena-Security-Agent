"""Ownership verification: prove a user controls a specific host.

Three methods, matching the brief:

* **DNS TXT** — a ``TXT`` record at ``_sentinel-arena-site-verification.<host>``
  whose value contains the user's token.
* **Well-known file** — ``https://<host>/.well-known/sentinel-arena.txt`` whose
  body contains the token.
* **Meta tag** — a ``<meta name="sentinel-arena-site-verification" ...>`` tag on
  the host's home page whose ``content`` is the token.

The checking logic here is pure and synchronous. All network I/O is funneled
through two small injectable interfaces (:class:`DnsResolver`, :class:`HttpClient`)
so unit tests run fully offline and so the live implementations (which need
optional deps) never import at module load. Live implementations live in
``verification_live.py`` and are only imported on demand.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Protocol

from .tokens import (
    WELL_KNOWN_PATH,
    VerificationChallenge,
    _normalize_host,
    tokens_match,
)


class VerificationMethod(str, Enum):
    DNS_TXT = "dns_txt"
    WELL_KNOWN_FILE = "well_known_file"
    META_TAG = "meta_tag"


class DnsResolver(Protocol):
    def txt_records(self, name: str) -> list[str]:
        """Return TXT record strings for ``name`` (empty list if none/NXDOMAIN)."""
        ...


class HttpClient(Protocol):
    def get_text(self, url: str) -> str:
        """GET ``url`` and return the response body as text. Raise on failure."""
        ...


@dataclass(frozen=True)
class VerificationResult:
    verified: bool
    method: VerificationMethod
    host: str
    user_id: str
    checked_at: datetime
    detail: str = ""


_META_RE = re.compile(
    r"""<meta\b[^>]*\bname\s*=\s*["']sentinel-arena-site-verification["'][^>]*>""",
    re.IGNORECASE,
)
_CONTENT_RE = re.compile(r"""\bcontent\s*=\s*["']([^"']*)["']""", re.IGNORECASE)


def _extract_meta_tokens(html: str) -> list[str]:
    tokens: list[str] = []
    for tag in _META_RE.findall(html):
        m = _CONTENT_RE.search(tag)
        if m:
            tokens.append(m.group(1).strip())
    return tokens


# A browser-like User-Agent. Many CDNs/WAFs (Cloudflare et al.) stall or block
# requests from an obviously-automated agent, which makes a legitimate
# ownership-verification fetch time out even though the file is published. The
# fetch is still read-only, size-capped and short-lived.
VERIFIER_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


class StdlibHttpClient:
    """Dependency-free HTTP client (urllib) satisfying :class:`HttpClient`.

    Used for self-hosted verification where pulling in httpx is unnecessary.
    Bounded timeout and a small read cap; follows redirects (http->https, apex
    ->www) which is what urllib does by default.
    """

    def __init__(self, timeout: float = 5.0, max_bytes: int = 256 * 1024) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes

    def get_text(self, url: str) -> str:
        import urllib.request

        req = urllib.request.Request(
            url, headers={"User-Agent": VERIFIER_USER_AGENT,
                          "Accept": "text/plain,text/html;q=0.9,*/*;q=0.8"}
        )
        ctx = None
        if url.lower().startswith("https"):
            try:
                from ..config import ssl_context
                ctx = ssl_context()
            except Exception:
                ctx = None
        with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
            return resp.read(self.max_bytes).decode("utf-8", "replace")


class OwnershipVerifier:
    """Checks a placed proof against the expected token for (user, host).

    Resolvers are injected; pass ``None`` for a method you do not intend to use
    (attempting that method will then raise ``RuntimeError``).
    """

    def __init__(
        self,
        *,
        dns: DnsResolver | None = None,
        http: HttpClient | None = None,
        clock=lambda: datetime.now(timezone.utc),
    ) -> None:
        self._dns = dns
        self._http = http
        self._clock = clock

    def verify(
        self,
        challenge: VerificationChallenge,
        method: VerificationMethod,
    ) -> VerificationResult:
        host = _normalize_host(challenge.host)
        now = self._clock()
        if method is VerificationMethod.DNS_TXT:
            return self._verify_dns(challenge, host, now)
        if method is VerificationMethod.WELL_KNOWN_FILE:
            return self._verify_well_known(challenge, host, now)
        if method is VerificationMethod.META_TAG:
            return self._verify_meta(challenge, host, now)
        raise ValueError(f"unknown method: {method}")  # pragma: no cover

    # --- per-method ------------------------------------------------------
    def _result(self, verified, method, host, user_id, now, detail=""):
        return VerificationResult(
            verified=verified,
            method=method,
            host=host,
            user_id=user_id,
            checked_at=now,
            detail=detail,
        )

    def _verify_dns(self, ch, host, now) -> VerificationResult:
        if self._dns is None:
            raise RuntimeError("no DNS resolver configured")
        name = f"_sentinel-arena-site-verification.{host}"
        records = self._dns.txt_records(name)
        for rec in records:
            # TXT values may arrive quoted or as `label=token`; check both the
            # whole record and the part after '='.
            candidates = [rec.strip().strip('"')]
            if "=" in candidates[0]:
                candidates.append(candidates[0].split("=", 1)[1])
            if any(tokens_match(ch.token, c) for c in candidates):
                return self._result(True, VerificationMethod.DNS_TXT, host, ch.user_id, now,
                                    f"matched TXT at {name}")
        return self._result(False, VerificationMethod.DNS_TXT, host, ch.user_id, now,
                            f"no matching TXT at {name} ({len(records)} record(s) seen)")

    def _verify_well_known(self, ch, host, now) -> VerificationResult:
        if self._http is None:
            raise RuntimeError("no HTTP client configured")
        url = f"https://{host}{WELL_KNOWN_PATH}"
        try:
            body = self._http.get_text(url)
        except Exception as e:  # network/HTTP error => not verified, not a crash
            return self._result(False, VerificationMethod.WELL_KNOWN_FILE, host, ch.user_id,
                                now, f"fetch failed: {e}")
        for line in body.splitlines():
            if tokens_match(ch.token, line):
                return self._result(True, VerificationMethod.WELL_KNOWN_FILE, host,
                                    ch.user_id, now, f"matched body at {url}")
        return self._result(False, VerificationMethod.WELL_KNOWN_FILE, host, ch.user_id,
                            now, f"token not found at {url}")

    def _verify_meta(self, ch, host, now) -> VerificationResult:
        if self._http is None:
            raise RuntimeError("no HTTP client configured")
        url = f"https://{host}/"
        try:
            html = self._http.get_text(url)
        except Exception as e:
            return self._result(False, VerificationMethod.META_TAG, host, ch.user_id, now,
                                f"fetch failed: {e}")
        for tok in _extract_meta_tokens(html):
            if tokens_match(ch.token, tok):
                return self._result(True, VerificationMethod.META_TAG, host, ch.user_id,
                                    now, f"matched meta tag at {url}")
        return self._result(False, VerificationMethod.META_TAG, host, ch.user_id, now,
                            f"no matching meta tag at {url}")
