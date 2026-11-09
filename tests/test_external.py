"""External observation-only assessment: ownership is re-verified live before any
request, the scan is header-only, and a failed proof scans nothing.

Tests run against the bundled sandbox as a stand-in for "a host we own" (its
well-known token proves ownership for real), so no third party is ever touched."""

from __future__ import annotations

import secrets

import pytest

from sentinel_arena.authz import OwnershipVerifier, VerificationMethod, make_challenge
from sentinel_arena.authz.errors import VerificationFailed
from sentinel_arena.detect.client import Response
from sentinel_arena.detect.external import analyze_headers
from sentinel_arena.engagement import _BoundHttp
from sentinel_arena.external_scan import SCANNER, run_external_assessment
from sentinel_arena.range.vulnerable_app import AppConfig, start_app

HOST = "127.0.0.1"


# --- pure header analysis (no network) -------------------------------------
def test_analyze_headers_flags_missing_controls():
    resp = Response(status=200, headers={"Set-Cookie": "sid=abc; Path=/",
                                         "X-Powered-By": "Express/4.17.1"}, text="")
    findings = {f.title for f in analyze_headers(resp, "https://x")}
    assert "Missing security response headers" in findings
    assert "HSTS not enabled (Strict-Transport-Security missing)" in findings
    assert "Session cookie set without HttpOnly/Secure flags" in findings
    assert "Technology and version disclosed in response headers" in findings


def test_analyze_headers_clean_site_has_no_findings():
    resp = Response(status=200, headers={
        "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY",
        "Content-Security-Policy": "default-src 'self'",
        "Strict-Transport-Security": "max-age=63072000",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }, text="")
    assert analyze_headers(resp, "https://x") == []


# --- end-to-end against a self-owned sandbox host --------------------------
@pytest.fixture
def owned_host(tmp_path):
    secret = secrets.token_bytes(32)
    ch = make_challenge(SCANNER, HOST, secret=secret)
    cfg = AppConfig(token=ch.token, flag_path="/f", admin_path="/a",
                    flag_value="FLAG{x}", credential="pw")
    server, base_url, _ = start_app(cfg)
    yield secret, base_url, tmp_path
    server.shutdown()
    server.server_close()


def test_external_assessment_requires_and_uses_live_proof(owned_host):
    secret, base_url, tmp_path = owned_host
    # Verifier fetches the well-known token from the real base URL => genuine proof.
    verifier = OwnershipVerifier(http=_BoundHttp(base_url))
    res = run_external_assessment(
        HOST, verifier=verifier, secret=secret,
        method=VerificationMethod.WELL_KNOWN_FILE, base_url=base_url,
        audit_path=str(tmp_path / "audit.jsonl"), label="my site")
    assert res.depth == "external" and res.runs == 1
    titles = {v.title for v in res.vulnerabilities}
    # The sandbox serves content without protective headers -> this must surface.
    assert "Missing security response headers" in titles
    assert res.posture_grade in ("A", "B", "C", "D", "F")
    # Verdict carries fixes + an audited trail.
    assert all(v.mitigation for v in res.vulnerabilities)
    assert (tmp_path / "audit.jsonl").exists()


def test_external_assessment_refuses_when_ownership_unproven(owned_host):
    secret, base_url, tmp_path = owned_host
    # A verifier pointed at the wrong secret can't match the token -> no scan.
    wrong_secret = secrets.token_bytes(32)
    verifier = OwnershipVerifier(http=_BoundHttp(base_url))
    with pytest.raises(VerificationFailed):
        run_external_assessment(
            HOST, verifier=verifier, secret=wrong_secret,
            method=VerificationMethod.WELL_KNOWN_FILE, base_url=base_url,
            audit_path=str(tmp_path / "audit.jsonl"))


# --- API endpoints (offline: issue a challenge, list, and refuse to scan) ---
def test_api_target_verify_list_and_refuse(tmp_path, monkeypatch):
    monkeypatch.setenv("ARENA_DATA_DIR", str(tmp_path))
    from sentinel_arena import store as store_mod
    store_mod.reset_store()
    try:
        import sentinel_arena.api.server as srv

        issued = srv.target_verify(host="example.com", x_tenant_id="t1")
        assert len(issued["token"]) > 10
        assert issued["methods"]["dns_txt"]["name"].endswith("example.com")

        targets = srv.list_targets(x_tenant_id="t1")
        assert targets and targets[0]["host"] == "example.com"
        assert targets[0]["ownership_proven"] is False
        # Another tenant sees nothing.
        assert srv.list_targets(x_tenant_id="t2") == []

        # Scanning a host we can't prove must be refused (403), not run.
        from fastapi import HTTPException
        with pytest.raises(HTTPException) as ei:
            srv.assess_external(host="example.com", method="well_known_file",
                                x_tenant_id="t1")
        assert ei.value.status_code == 403
    finally:
        store_mod.reset_store()
