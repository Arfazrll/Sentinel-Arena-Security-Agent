from __future__ import annotations

import secrets
from datetime import datetime, timedelta, timezone

import pytest

from sentinel_arena.authz import (
    AuditLog,
    AuthorizationGate,
    Environment,
    OwnershipVerifier,
    RateCap,
    Scope,
    VerificationMethod,
    make_challenge,
)
from sentinel_arena.detect.checks import build_checks
from sentinel_arena.detect.client import GatedHttpClient
from sentinel_arena.engagement import _BoundHttp
from sentinel_arena.range.vulnerable_app import AppConfig, start_app

HOST = "127.0.0.1"
USER = "op"


@pytest.fixture
def authorized_client(tmp_path):
    secret = secrets.token_bytes(32)
    ch = make_challenge(USER, HOST, secret=secret)
    cfg = AppConfig(token=ch.token, flag_path="/flagzone", admin_path="/zz-admin",
                    flag_value="FLAG{abc123}", credential="pw")
    server, base_url, _ = start_app(cfg)
    now = datetime.now(timezone.utc)
    scope = Scope(allowed_hosts=[HOST], allowed_paths=["/"],
                  rate_cap=RateCap(max_requests=1000, per_seconds=60),
                  environment=Environment.STAGING,
                  not_before=now - timedelta(minutes=1),
                  not_after=now + timedelta(hours=1))
    gate = AuthorizationGate(secret=secret,
                             verifier=OwnershipVerifier(http=_BoundHttp(base_url)),
                             audit=AuditLog(tmp_path / "audit.jsonl"))
    gate.authorize(USER, HOST, VerificationMethod.WELL_KNOWN_FILE, scope)
    client = GatedHttpClient(gate=gate, user_id=USER, host=HOST, base_url=base_url,
                             scope=scope, actor="red")
    yield client, cfg
    server.shutdown()
    server.server_close()


def test_all_checks_fire_against_vulnerable_app(authorized_client):
    client, cfg = authorized_client
    checks = build_checks(cfg.admin_path)
    fired = {name: check(client) for name, check in checks.items()}
    assert fired["security_headers"] is not None
    assert fired["reflected_xss"] is not None
    assert fired["exposed_admin"] is not None
    assert fired["verbose_errors"] is not None
    assert fired["sensitive_file"] is not None
    # Each finding carries an OWASP code and a mitigation.
    for f in fired.values():
        assert f.owasp.startswith("A")
        assert f.mitigation


def test_out_of_scope_request_is_blocked(authorized_client, tmp_path):
    client, cfg = authorized_client
    # Narrow the scope to /app only; a request to / must now be refused by the gate.
    from sentinel_arena.authz.errors import OutOfScope
    now = datetime.now(timezone.utc)
    client.scope = Scope(allowed_hosts=[HOST], allowed_paths=["/app"],
                         rate_cap=RateCap(max_requests=10, per_seconds=60),
                         environment=Environment.STAGING,
                         not_before=now - timedelta(minutes=1),
                         not_after=now + timedelta(hours=1))
    with pytest.raises(OutOfScope):
        client.get("/config.json")
