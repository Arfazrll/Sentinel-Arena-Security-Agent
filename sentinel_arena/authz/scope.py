"""The scope engine.

A :class:`Scope` is the explicit, enforced boundary of an engagement: which
hosts and paths may be touched, how fast, during what window, and what is
hard-blocked. It is a frozen Pydantic model so it is hashable, comparable, and
safe to pass around as an immutable authorization fact.

Enforcement rule, applied on *every* request by :meth:`Scope.permits`:

1. The host must be on the allowlist (exact, normalized match).
2. The host must not be on the blocklist. **Blocklist always wins.**
3. The path must sit under one of the allowed path prefixes.
4. The current time must be inside ``[not_before, not_after]``.

Production targets are held to tighter defaults than staging and are validated
against hard ceilings, because the brief requires production to be the
exception, not the default.
"""

from __future__ import annotations

import posixpath
from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .errors import Blocked, OutOfScope, ScopeExpired


class Environment(str, Enum):
    STAGING = "staging"
    PRODUCTION = "production"


# Hard ceilings for production. Staging may be looser, but production is the
# exception and gets tight, non-negotiable caps.
PROD_MAX_REQUESTS_PER_MIN = 60
PROD_MAX_WINDOW_HOURS = 4


def _normalize_host(host: str) -> str:
    h = host.strip().lower().rstrip(".")
    if not h:
        raise ValueError("empty host")
    if "://" in h or "/" in h or ":" in h or " " in h or "*" in h:
        raise ValueError(f"not a bare hostname: {host!r}")
    return h


def _normalize_path(path: str) -> str:
    """Normalize a path prefix, rejecting traversal.

    Ensures a leading slash, collapses ``.`` / duplicate slashes, and rejects
    any ``..`` segment so a prefix cannot escape its intended subtree.
    """
    p = path.strip()
    if not p.startswith("/"):
        p = "/" + p
    # posixpath.normpath collapses // and /./ and resolves ..; we reject .. so
    # a would-be-escaping prefix is refused loudly rather than silently rebased.
    if ".." in p.split("/"):
        raise ValueError(f"path may not contain '..': {path!r}")
    norm = posixpath.normpath(p)
    # normpath strips a trailing slash and turns '/' into '/'; keep it simple.
    return norm if norm != "." else "/"


class RateCap(BaseModel):
    """A ceiling on request rate. Enforcement of counting lives in the caller
    (the referee / outbound client); this just carries the limit."""

    model_config = ConfigDict(frozen=True)

    max_requests: int = Field(gt=0)
    per_seconds: int = Field(gt=0)

    @property
    def per_minute(self) -> float:
        return self.max_requests * 60.0 / self.per_seconds


class ScopeDecision(BaseModel):
    """Result of a scope check — allowed, or allowed=False with a reason."""

    model_config = ConfigDict(frozen=True)

    allowed: bool
    reason: str = ""


class Scope(BaseModel):
    """The authorized boundary of an engagement. Immutable once constructed."""

    model_config = ConfigDict(frozen=True)

    allowed_hosts: tuple[str, ...]
    allowed_paths: tuple[str, ...] = ("/",)
    blocklist: tuple[str, ...] = ()
    rate_cap: RateCap
    environment: Environment = Environment.STAGING
    not_before: datetime
    not_after: datetime

    # --- normalizers -----------------------------------------------------
    @field_validator("allowed_hosts", "blocklist", mode="before")
    @classmethod
    def _norm_hosts(cls, v: object) -> tuple[str, ...]:
        if isinstance(v, str):
            v = [v]
        items = sorted({_normalize_host(h) for h in v})  # dedupe + deterministic
        return tuple(items)

    @field_validator("allowed_paths", mode="before")
    @classmethod
    def _norm_paths(cls, v: object) -> tuple[str, ...]:
        if isinstance(v, str):
            v = [v]
        items = sorted({_normalize_path(p) for p in v})
        return tuple(items) or ("/",)

    @field_validator("not_before", "not_after", mode="before")
    @classmethod
    def _aware(cls, v: object) -> object:
        # Require timezone-aware datetimes; assume nothing about local time.
        if isinstance(v, datetime) and v.tzinfo is None:
            raise ValueError("datetime must be timezone-aware (use UTC)")
        return v

    # --- cross-field invariants -----------------------------------------
    @model_validator(mode="after")
    def _check(self) -> "Scope":
        if not self.allowed_hosts:
            raise ValueError("scope must allow at least one host")
        if self.not_after <= self.not_before:
            raise ValueError("not_after must be after not_before")

        overlap = set(self.allowed_hosts) & set(self.blocklist)
        if overlap:
            raise ValueError(
                f"hosts are both allowed and blocked: {sorted(overlap)}"
            )

        if self.environment is Environment.PRODUCTION:
            if self.rate_cap.per_minute > PROD_MAX_REQUESTS_PER_MIN:
                raise ValueError(
                    "production rate cap exceeds ceiling of "
                    f"{PROD_MAX_REQUESTS_PER_MIN}/min"
                )
            window_h = (self.not_after - self.not_before).total_seconds() / 3600
            if window_h > PROD_MAX_WINDOW_HOURS:
                raise ValueError(
                    "production time window exceeds ceiling of "
                    f"{PROD_MAX_WINDOW_HOURS}h"
                )
        return self

    # --- enforcement -----------------------------------------------------
    def host_allowed(self, host: str) -> bool:
        return _normalize_host(host) in self.allowed_hosts

    def host_blocked(self, host: str) -> bool:
        return _normalize_host(host) in self.blocklist

    def path_allowed(self, path: str) -> bool:
        p = _normalize_path(path)
        for prefix in self.allowed_paths:
            if prefix == "/" or p == prefix or p.startswith(prefix.rstrip("/") + "/"):
                return True
        return False

    def within_window(self, now: datetime) -> bool:
        if now.tzinfo is None:
            raise ValueError("now must be timezone-aware")
        return self.not_before <= now <= self.not_after

    def permits(self, host: str, path: str, now: datetime | None = None) -> ScopeDecision:
        """Non-raising check. Blocklist wins; then allowlist, path, window."""
        now = now or datetime.now(timezone.utc)
        try:
            h = _normalize_host(host)
        except ValueError as e:
            return ScopeDecision(allowed=False, reason=f"invalid host: {e}")
        if h in self.blocklist:
            return ScopeDecision(allowed=False, reason="host is blocklisted")
        if h not in self.allowed_hosts:
            return ScopeDecision(allowed=False, reason="host not in allowlist")
        if not self.path_allowed(path):
            return ScopeDecision(allowed=False, reason="path outside allowed paths")
        if not self.within_window(now):
            return ScopeDecision(allowed=False, reason="outside authorized time window")
        return ScopeDecision(allowed=True)

    def enforce(self, host: str, path: str, now: datetime | None = None) -> None:
        """Raising check — the form downstream code uses as a guard.

        Raises the most specific error (:class:`Blocked`, :class:`OutOfScope`,
        :class:`ScopeExpired`) so callers and the audit log can record *why*.
        """
        now = now or datetime.now(timezone.utc)
        h = _normalize_host(host)
        if h in self.blocklist:
            raise Blocked(f"{h} is on the hard blocklist")
        if h not in self.allowed_hosts:
            raise OutOfScope(f"{h} is not in the allowed hosts")
        if not self.path_allowed(path):
            raise OutOfScope(f"path {path!r} is outside the allowed paths")
        if not self.within_window(now):
            raise ScopeExpired("current time is outside the authorized window")

    def fingerprint(self) -> str:
        """Stable, order-independent identifier of this scope for audit records."""
        import hashlib

        payload = self.model_dump_json()  # frozen + sorted fields => stable
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()
