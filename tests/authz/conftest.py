"""Shared fixtures and offline fakes for authz tests."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel_arena.authz import (
    AuthorizationGate,
    AuditLog,
    Environment,
    OwnershipVerifier,
    RateCap,
    Scope,
)

SECRET = b"test-secret-not-for-production"


class FakeDns:
    """In-memory TXT resolver. ``records[name] -> list[str]``."""

    def __init__(self, records: dict[str, list[str]] | None = None) -> None:
        self.records = records or {}

    def txt_records(self, name: str) -> list[str]:
        return list(self.records.get(name, []))


class FakeHttp:
    """In-memory HTTP client. ``pages[url] -> body`` or an Exception to raise."""

    def __init__(self, pages: dict[str, object] | None = None) -> None:
        self.pages = pages or {}

    def get_text(self, url: str) -> str:
        if url not in self.pages:
            raise ConnectionError(f"no route to {url}")
        val = self.pages[url]
        if isinstance(val, Exception):
            raise val
        return str(val)


@pytest.fixture
def now() -> datetime:
    return datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


@pytest.fixture
def staging_scope(now) -> Scope:
    return Scope(
        allowed_hosts=["staging.example.com"],
        allowed_paths=["/app", "/api"],
        blocklist=["admin.example.com"],
        rate_cap=RateCap(max_requests=100, per_seconds=60),
        environment=Environment.STAGING,
        not_before=now - timedelta(hours=1),
        not_after=now + timedelta(hours=8),
    )


@pytest.fixture
def audit(tmp_path) -> AuditLog:
    return AuditLog(tmp_path / "audit.jsonl")


def make_gate(audit, *, dns=None, http=None, clock=None) -> AuthorizationGate:
    verifier = OwnershipVerifier(
        dns=dns, http=http, clock=clock or (lambda: datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc))
    )
    return AuthorizationGate(
        secret=SECRET,
        verifier=verifier,
        audit=audit,
        clock=clock or (lambda: datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)),
    )
