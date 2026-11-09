from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel_arena.authz import Environment, RateCap, Scope
from sentinel_arena.authz.errors import Blocked, OutOfScope, ScopeExpired

NOW = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)


def _scope(**kw):
    base = dict(
        allowed_hosts=["staging.example.com"],
        allowed_paths=["/app"],
        rate_cap=RateCap(max_requests=100, per_seconds=60),
        not_before=NOW - timedelta(hours=1),
        not_after=NOW + timedelta(hours=1),
    )
    base.update(kw)
    return Scope(**base)


def test_allowed_host_and_path():
    s = _scope()
    assert s.permits("staging.example.com", "/app/login", NOW).allowed


def test_host_not_in_allowlist_rejected():
    s = _scope()
    d = s.permits("evil.example.com", "/app", NOW)
    assert not d.allowed and "allowlist" in d.reason


def test_blocklist_wins_over_allowlist():
    # Same host allowed AND blocked is rejected at construction...
    with pytest.raises(ValueError):
        _scope(allowed_hosts=["h.example.com"], blocklist=["h.example.com"])
    # ...and a blocklisted host is denied even though not in allow set.
    s = _scope(blocklist=["admin.example.com"])
    with pytest.raises(Blocked):
        s.enforce("admin.example.com", "/app", NOW)


def test_path_prefix_enforced():
    s = _scope(allowed_paths=["/api"])
    assert s.permits("staging.example.com", "/api/v1/users", NOW).allowed
    assert not s.permits("staging.example.com", "/admin", NOW).allowed


def test_path_traversal_rejected_at_construction():
    with pytest.raises(ValueError):
        _scope(allowed_paths=["/app/../admin"])


def test_time_window_enforced():
    s = _scope()
    with pytest.raises(ScopeExpired):
        s.enforce("staging.example.com", "/app", NOW + timedelta(days=1))


def test_enforce_raises_out_of_scope():
    s = _scope()
    with pytest.raises(OutOfScope):
        s.enforce("staging.example.com", "/nope", NOW)


def test_naive_datetime_rejected():
    with pytest.raises(ValueError):
        _scope(not_before=datetime(2026, 1, 1), not_after=datetime(2026, 1, 2))


def test_production_rate_ceiling():
    with pytest.raises(ValueError):
        _scope(
            environment=Environment.PRODUCTION,
            rate_cap=RateCap(max_requests=1000, per_seconds=60),
        )


def test_production_window_ceiling():
    with pytest.raises(ValueError):
        _scope(
            environment=Environment.PRODUCTION,
            rate_cap=RateCap(max_requests=10, per_seconds=60),
            not_before=NOW,
            not_after=NOW + timedelta(hours=12),
        )


def test_production_within_ceilings_ok():
    s = _scope(
        environment=Environment.PRODUCTION,
        rate_cap=RateCap(max_requests=30, per_seconds=60),
        not_before=NOW,
        not_after=NOW + timedelta(hours=2),
    )
    assert s.environment is Environment.PRODUCTION


def test_fingerprint_is_stable_and_order_independent():
    s1 = _scope(allowed_hosts=["a.example.com", "b.example.com"])
    s2 = _scope(allowed_hosts=["b.example.com", "a.example.com"])
    assert s1.fingerprint() == s2.fingerprint()


def test_scope_is_frozen():
    s = _scope()
    with pytest.raises(Exception):
        s.environment = Environment.PRODUCTION  # type: ignore[misc]


def test_empty_allowlist_rejected():
    with pytest.raises(ValueError):
        _scope(allowed_hosts=[])
