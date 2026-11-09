from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from sentinel_arena.authz import (
    VerificationMethod,
    make_challenge,
)
from sentinel_arena.authz.errors import (
    InvalidScope,
    OutOfScope,
    OwnershipNotProven,
    VerificationFailed,
    Blocked,
)
from conftest import FakeDns, FakeHttp, SECRET, make_gate

USER = "user1"
HOST = "staging.example.com"


def _dns_for(user, host):
    ch = make_challenge(user, host, secret=SECRET)
    return FakeDns({f"_sentinel-arena-site-verification.{host}": [ch.dns_txt_value]})


def test_check_before_authorize_is_denied(audit, staging_scope):
    gate = make_gate(audit)
    with pytest.raises(OwnershipNotProven):
        gate.check(USER, HOST, "/app", staging_scope)
    # The denial was logged.
    assert any(e.outcome == "deny" for e in audit)


def test_full_authorize_then_check_flow(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, HOST))
    consent = gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    assert consent.user_id == USER
    gate.check(USER, HOST, "/app/login", staging_scope)  # should not raise
    assert gate.is_authorized(USER, HOST)
    assert audit.verify_chain() is True


def test_authorize_fails_when_proof_absent(audit, staging_scope):
    gate = make_gate(audit, dns=FakeDns({}))
    with pytest.raises(VerificationFailed):
        gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    assert not gate.is_authorized(USER, HOST)


def test_authorize_rejects_host_not_in_scope(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, "other.example.com"))
    with pytest.raises(InvalidScope):
        gate.authorize(USER, "other.example.com", VerificationMethod.DNS_TXT, staging_scope)


def test_check_rejects_out_of_scope_path(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, HOST))
    gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    with pytest.raises(OutOfScope):
        gate.check(USER, HOST, "/secret", staging_scope)


def test_check_rejects_blocklisted_host(audit, staging_scope):
    # Blocklisted host can never get a proof (not in allowed_hosts), so check
    # is denied for ownership first; assert it never passes.
    gate = make_gate(audit, dns=_dns_for(USER, "admin.example.com"))
    with pytest.raises((OwnershipNotProven, Blocked, InvalidScope)):
        gate.check(USER, "admin.example.com", "/app", staging_scope)


def test_other_user_cannot_use_my_proof(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, HOST))
    gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    with pytest.raises(OwnershipNotProven):
        gate.check("user2", HOST, "/app", staging_scope)


def test_expired_proof_is_denied(audit, staging_scope):
    # Clock advances past the proof TTL between authorize and check.
    t0 = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
    gate = make_gate(audit, dns=_dns_for(USER, HOST), clock=lambda: t0)
    gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    later = t0 + timedelta(hours=48)
    with pytest.raises(OwnershipNotProven):
        gate.check(USER, HOST, "/app", staging_scope, now=later)


def test_revoke_removes_authorization(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, HOST))
    gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    gate.revoke(USER, HOST)
    assert not gate.is_authorized(USER, HOST)
    with pytest.raises(OwnershipNotProven):
        gate.check(USER, HOST, "/app", staging_scope)


def test_well_known_authorize_flow(audit, staging_scope):
    ch = make_challenge(USER, HOST, secret=SECRET)
    http = FakeHttp({ch.well_known_url: ch.token})
    gate = make_gate(audit, http=http)
    gate.authorize(USER, HOST, VerificationMethod.WELL_KNOWN_FILE, staging_scope)
    gate.check(USER, HOST, "/api/x", staging_scope)


def test_every_denial_is_audited(audit, staging_scope):
    gate = make_gate(audit, dns=_dns_for(USER, HOST))
    gate.authorize(USER, HOST, VerificationMethod.DNS_TXT, staging_scope)
    with pytest.raises(OutOfScope):
        gate.check(USER, HOST, "/secret", staging_scope)
    denies = [e for e in audit if e.outcome == "deny"]
    assert denies and denies[-1].detail.get("path") == "/secret"
    assert audit.verify_chain() is True
