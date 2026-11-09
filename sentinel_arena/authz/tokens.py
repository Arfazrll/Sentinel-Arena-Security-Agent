"""Per-user, per-host verification tokens.

A token is a deterministic HMAC over ``user_id:host`` keyed by a server-side
secret. Properties this buys us:

* **Stable** — the same (user, host) always yields the same token, so a user
  places the proof once and we can re-verify on a schedule without asking them
  to re-publish it.
* **Unforgeable without the secret** — a third party cannot compute another
  user's token, so one user cannot ride on another's placed proof.
* **Stateless** — we never have to store the expected value; we recompute it.

A ``rotation`` epoch is included so an operator can invalidate all outstanding
proofs (e.g. after a secret rotation) by bumping it.

The secret is supplied by the caller (from a vault / env), never hard-coded.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
from dataclasses import dataclass

TOKEN_LABEL = "sentinel-arena-site-verification"
WELL_KNOWN_PATH = "/.well-known/sentinel-arena.txt"
_META_NAME = "sentinel-arena-site-verification"


def _normalize_host(host: str) -> str:
    """Lower-case and strip a bare hostname. Rejects anything that is not one.

    Accepts ``example.com``; rejects values carrying a scheme, path, port,
    whitespace, or wildcard. Kept strict on purpose: the token binds to an
    exact host, so the host must be unambiguous.
    """
    h = host.strip().lower().rstrip(".")
    if not h:
        raise ValueError("empty host")
    if "://" in h or "/" in h or ":" in h or " " in h or "*" in h:
        raise ValueError(f"not a bare hostname: {host!r}")
    return h


def expected_token(user_id: str, host: str, *, secret: bytes, rotation: int = 0) -> str:
    """Return the verification token string a user must publish for ``host``.

    Deterministic in (user_id, host, secret, rotation). URL-safe, no padding.
    """
    if not user_id:
        raise ValueError("empty user_id")
    if not secret:
        raise ValueError("empty secret")
    host = _normalize_host(host)
    msg = f"{rotation}:{user_id}:{host}".encode("utf-8")
    digest = hmac.new(secret, msg, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def tokens_match(expected: str, observed: str) -> bool:
    """Constant-time comparison of two token strings."""
    return hmac.compare_digest(expected.strip(), observed.strip())


@dataclass(frozen=True)
class VerificationChallenge:
    """Instructions for a user to prove ownership of ``host``.

    Carries the exact artifact to place for each supported method, so the UI /
    CLI can show copy-paste-ready text.
    """

    user_id: str
    host: str
    token: str

    @property
    def dns_txt_name(self) -> str:
        return f"_{TOKEN_LABEL}.{self.host}"

    @property
    def dns_txt_value(self) -> str:
        return f"{TOKEN_LABEL}={self.token}"

    @property
    def well_known_url(self) -> str:
        return f"https://{self.host}{WELL_KNOWN_PATH}"

    @property
    def well_known_body(self) -> str:
        return self.token

    @property
    def meta_tag(self) -> str:
        return f'<meta name="{_META_NAME}" content="{self.token}">'


def make_challenge(
    user_id: str, host: str, *, secret: bytes, rotation: int = 0
) -> VerificationChallenge:
    """Build a :class:`VerificationChallenge` for (user, host)."""
    host = _normalize_host(host)
    token = expected_token(user_id, host, secret=secret, rotation=rotation)
    return VerificationChallenge(user_id=user_id, host=host, token=token)
