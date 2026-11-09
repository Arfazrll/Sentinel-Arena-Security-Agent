"""Store contract: the filesystem and SQL (SQLite) implementations must behave
identically. Every test runs against both via the ``store`` fixture."""

from __future__ import annotations

import pytest

from sentinel_arena.store.base import DEFAULT_TENANT
from sentinel_arena.store.filesystem import FilesystemStore
from sentinel_arena.store.sql import SqlStore


@pytest.fixture(params=["filesystem", "sql"])
def store(request, tmp_path):
    if request.param == "filesystem":
        yield FilesystemStore(tmp_path)
    else:
        s = SqlStore(f"sqlite:///{(tmp_path / 'db.sqlite').as_posix()}")
        yield s
        s.close()


def _campaign(cid="camp-1", tenant=DEFAULT_TENANT, grade="D", worst=40):
    return {
        "id": cid, "tenant_id": tenant, "target": "127.0.0.1", "label": "L",
        "depth": "quick", "status": "done", "created_at": "2026-01-01T00:00:00+00:00",
        "runs": 3, "posture_grade": grade, "mean_resilience": 60.0,
        "worst_resilience": worst, "best_resilience": 88, "attacker_win_rate": 0.5,
        "scenarios": ["shop-01"], "reds": ["scripted"], "blues": ["scripted"],
        "seeds": [42], "severity_counts": {"high": 1}, "owasp_coverage": {"A01": 1},
        "matchups": [{"red": "scripted", "blue": "scripted", "mean_resilience": 60.0}],
        "vulnerabilities": [
            {"rule_id": "SA-ACL-001", "title": "Admin reachable", "owasp": "A01",
             "owasp_title": "Broken Access Control", "severity": "high",
             "cwe": ["CWE-306"], "cvss_band": "7.0-8.9", "risk_score": 7.5,
             "priority": "P1", "fix_sla_days": 7, "effort": "M",
             "mitigation": "Require auth.", "controls": {"soc2": ["CC6.1"]},
             "occurrences": 2, "example_evidence": "GET /admin 200", "example_url": "u"},
            {"rule_id": "SA-HDR-001", "title": "Missing headers", "owasp": "A05",
             "owasp_title": "Security Misconfiguration", "severity": "medium",
             "cwe": ["CWE-693"], "cvss_band": "4.0-6.9", "risk_score": 5.3,
             "priority": "P2", "fix_sla_days": 30, "effort": "S",
             "mitigation": "Set headers.", "controls": {}, "occurrences": 1,
             "example_evidence": "", "example_url": ""},
        ],
    }


def test_tenant_crud(store):
    store.ensure_tenant("acme", "Acme Inc")
    assert store.get_tenant("acme")["name"] == "Acme Inc"
    # Idempotent: a second ensure doesn't overwrite or duplicate.
    store.ensure_tenant("acme", "Ignored")
    assert store.get_tenant("acme")["name"] == "Acme Inc"
    assert any(t["id"] == "acme" for t in store.list_tenants())


def test_target_ownership_roundtrip(store):
    store.upsert_target("acme", "app.acme.com", ownership_proven=False)
    assert store.get_target("acme", "app.acme.com")["ownership_proven"] is False
    store.upsert_target("acme", "app.acme.com", ownership_proven=True,
                        proof_method="dns_txt", proof_expires_at="2026-02-01T00:00:00+00:00")
    t = store.get_target("acme", "app.acme.com")
    assert t["ownership_proven"] is True and t["proof_method"] == "dns_txt"
    # No duplicate row for the same (tenant, host).
    assert len(store.list_targets("acme")) == 1


def test_campaign_roundtrip_with_vulnerabilities(store):
    store.save_campaign(_campaign())
    got = store.get_campaign("camp-1")
    assert got["posture_grade"] == "D"
    assert got["scenarios"] == ["shop-01"]
    assert [v["rule_id"] for v in got["vulnerabilities"]] == ["SA-ACL-001", "SA-HDR-001"]
    assert got["vulnerabilities"][0]["cwe"] == ["CWE-306"]
    assert got["vulnerabilities"][0]["controls"] == {"soc2": ["CC6.1"]}


def test_campaign_replace_is_idempotent(store):
    store.save_campaign(_campaign())
    store.save_campaign(_campaign(grade="A", worst=95))  # same id, new data
    got = store.get_campaign("camp-1")
    assert got["posture_grade"] == "A" and got["worst_resilience"] == 95
    # Vulnerabilities replaced, not appended.
    assert len(got["vulnerabilities"]) == 2
    assert len(store.list_campaigns(DEFAULT_TENANT)) == 1


def test_campaign_tenant_isolation(store):
    store.save_campaign(_campaign("camp-a", tenant="t1"))
    store.save_campaign(_campaign("camp-b", tenant="t2"))
    assert {c["id"] for c in store.list_campaigns("t1")} == {"camp-a"}
    assert {c["id"] for c in store.list_campaigns("t2")} == {"camp-b"}
    # Cross-tenant listing sees both.
    assert {c["id"] for c in store.list_campaigns(None)} == {"camp-a", "camp-b"}


def test_engagement_index(store):
    store.save_engagement({"id": "eng-1", "tenant_id": "t1", "scenario": "shop-01",
                           "seed": 42, "red": "scripted", "blue": "noop",
                           "status": "done", "resilience": 30, "flag_captured": True,
                           "created_at": "2026-01-01T00:00:00+00:00",
                           "artifacts_dir": "/var/engagements/eng-1"})
    e = store.get_engagement("eng-1")
    assert e["resilience"] == 30 and e["flag_captured"] is True
    assert store.list_engagements("t1")[0]["id"] == "eng-1"
    assert store.list_engagements("other") == []
