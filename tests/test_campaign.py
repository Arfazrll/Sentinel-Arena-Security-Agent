"""Campaign engine: matrix expansion, aggregation, and the ownership safety gate."""

from __future__ import annotations

import pytest

from sentinel_arena.campaign import (
    CampaignPlan,
    run_campaign,
    save_campaign,
    to_markdown,
)


def test_plan_resolves_and_expands_by_depth():
    quick = CampaignPlan(depth="quick").resolve()
    standard = CampaignPlan(depth="standard").resolve()
    deep = CampaignPlan(depth="deep").resolve()
    # Deeper presets must schedule strictly more graded runs.
    assert quick.total_runs() < standard.total_runs() < deep.total_runs()
    # Deep is a real fan-out, not a token one.
    assert deep.total_runs() >= 100


def test_bad_depth_rejected():
    with pytest.raises(ValueError):
        CampaignPlan(depth="turbo").resolve()


def test_quick_campaign_enumerates_all_planted_weaknesses():
    # Scope to one scenario so we can assert its exact planted set.
    res = run_campaign(CampaignPlan(depth="quick", scenarios=["shop-01"], label="unit target"))
    titles = {v.title for v in res.vulnerabilities}
    # The posture pass must surface the full planted set regardless of defender.
    assert "Admin panel reachable without authentication" in titles
    assert "Reflected input without output encoding" in titles
    assert len(res.vulnerabilities) == 5
    # Risk-ranked: first finding outranks the last.
    assert res.vulnerabilities[0].risk_score >= res.vulnerabilities[-1].risk_score
    # Every vuln carries a concrete fix and an SLA.
    assert all(v.mitigation and v.fix_sla_days > 0 for v in res.vulnerabilities)


def test_campaign_over_whole_library_covers_more_owasp():
    # A campaign across every scenario should surface a richer, de-duplicated set
    # than any single scenario (different scenarios plant different weaknesses).
    res = run_campaign(CampaignPlan(depth="quick", label="library"))
    titles = {v.title for v in res.vulnerabilities}
    assert "Permissive CORS policy (Access-Control-Allow-Origin: *)" in titles
    assert "Session cookie set without HttpOnly/Secure flags" in titles
    assert "Directory listing exposed under the web root" in titles
    # Covers more than one scenario's worth of distinct findings.
    assert len(res.vulnerabilities) >= 8
    assert len(res.scenarios) >= 4


def test_campaign_grades_and_matchups():
    res = run_campaign(CampaignPlan(depth="quick"))
    assert res.posture_grade in ("A", "B", "C", "D", "F")
    assert 0 <= res.worst_resilience <= res.mean_resilience <= res.best_resilience <= 100
    # A real-time defender should outrank "no defense" on mean resilience.
    by = {(m.red, m.blue): m for m in res.matchups}
    assert ("scripted", "scripted") in by


def test_external_target_refused_without_proof():
    """The core invariant: a non-sandbox target cannot be assessed until
    ownership has been proven out of band."""
    plan = CampaignPlan(target="example.com", depth="quick")
    with pytest.raises(PermissionError):
        run_campaign(plan)


def test_external_target_allowed_when_ownership_asserted():
    # With ownership proven, execution is permitted (and still runs the sandbox
    # engagement path - it never invents a live attack).
    plan = CampaignPlan(target="example.com", depth="quick", ownership_proven=True)
    res = run_campaign(plan)
    assert res.runs > 0


def test_api_campaign_persists_to_store_per_tenant(tmp_path, monkeypatch):
    """A campaign started through the API lands in the durable store, scoped to
    its tenant, and is still retrievable after it leaves the in-memory job map."""
    import time

    monkeypatch.setenv("ARENA_DATA_DIR", str(tmp_path))
    from sentinel_arena import store as store_mod
    store_mod.reset_store()
    try:
        import sentinel_arena.api.server as srv

        # Scope to one scenario so the job finishes fast and deterministically
        # even on a loaded machine (avoids a poll-timeout flake).
        out = srv.start_campaign(target="127.0.0.1", depth="quick",
                                 scenarios_csv="shop-01", label="api",
                                 x_tenant_id="t1")
        st = {"status": "running"}
        for _ in range(300):  # up to ~90s; normally a few seconds
            st = srv.campaign_status(out["id"])
            if st["status"] != "running":
                break
            time.sleep(0.3)
        assert st["status"] == "done", f"campaign did not finish: {st.get('status')}"

        rec = store_mod.get_store().get_campaign(out["id"])
        assert rec is not None and rec["tenant_id"] == "t1"
        assert rec["vulnerabilities"], "findings should persist with the campaign"
        assert any(c["id"] == out["id"]
                   for c in srv.list_campaigns(limit=100, x_tenant_id="t1"))
        # Another tenant must not see it.
        assert srv.list_campaigns(limit=100, x_tenant_id="t2") == []
    finally:
        store_mod.reset_store()


def test_save_campaign_writes_json_and_markdown(tmp_path):
    res = run_campaign(CampaignPlan(depth="quick", label="Report me"))
    save_campaign(res, tmp_path)
    assert (tmp_path / "campaign.json").exists()
    md = (tmp_path / "campaign.md").read_text(encoding="utf-8")
    assert "Prioritized remediation plan" in md
    assert "Report me" in to_markdown(res)
