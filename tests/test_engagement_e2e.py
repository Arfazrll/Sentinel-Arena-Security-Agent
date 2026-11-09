"""End-to-end engagement smoke tests — the milestone-1 done criteria.

* Scripted red reaches the flag against a passive defender (scenario solvable).
* Scripted blue stops the flag (defender works), with the audit chain intact.
"""

from __future__ import annotations

from sentinel_arena.authz.audit import AuditLog
from sentinel_arena.engagement import run_engagement


def test_scripted_red_captures_flag_against_noop_blue(tmp_path):
    art = run_engagement("shop-01", seed=42, blue_name="noop",
                         out_dir=tmp_path / "noop")
    r = art.result
    assert r.scoreboard.red.flag_captured is True
    assert r.ended_reason == "flag_captured"
    assert len(r.findings.findings) >= 4  # a passive target leaks plenty


def test_scripted_blue_stops_the_flag(tmp_path):
    art = run_engagement("shop-01", seed=42, blue_name="scripted",
                         out_dir=tmp_path / "blue")
    r = art.result
    assert r.scoreboard.red.flag_captured is False
    assert r.scoreboard.blue.blocked_attacker_before_flag is True
    assert r.scoreboard.resilience >= 60


def test_engagement_authorizes_before_acting_and_audit_is_intact(tmp_path):
    art = run_engagement("shop-01", seed=7, blue_name="scripted",
                         out_dir=tmp_path / "audit")
    audit = AuditLog(art.audit_path)
    assert audit.verify_chain() is True
    actions = [e.action for e in audit]
    # The very first authorization-relevant action is the ownership grant,
    # and it precedes any per-request check.
    assert "authorized" in actions
    assert actions.index("authorized") < actions.index("check")


def test_report_artifacts_written(tmp_path):
    art = run_engagement("shop-01", seed=42, blue_name="scripted",
                         out_dir=tmp_path / "rep")
    assert art.report_html.exists()
    assert art.report_md.exists()
    html = art.report_html.read_text(encoding="utf-8")
    assert "Resilience Audit" in html
    assert "OWASP" in html
    assert (art.out_dir / "result.json").exists()
    assert (art.out_dir / "events.jsonl").exists()


def test_resilience_higher_with_active_defender(tmp_path):
    passive = run_engagement("shop-01", seed=101, blue_name="noop",
                             out_dir=tmp_path / "p").result.scoreboard.resilience
    active = run_engagement("shop-01", seed=101, blue_name="scripted",
                            out_dir=tmp_path / "a").result.scoreboard.resilience
    assert active > passive
