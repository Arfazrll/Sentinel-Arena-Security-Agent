from __future__ import annotations

import pytest

from sentinel_arena.detect.findings import Finding, FindingList, Severity
from sentinel_arena.engine import (
    Action,
    BlueScore,
    RedScore,
    compute_resilience,
    technique_for,
    validate_action,
)
from sentinel_arena.engine.actions import validate_action as _va


def test_blue_whitelist_rejects_free_actions():
    with pytest.raises(ValueError):
        validate_action(Action(team="blue", kind="run_shell"))
    # Whitelisted ones pass.
    validate_action(Action(team="blue", kind="block_ip", params={"actor": "x"}))


def test_red_vocabulary_is_limited():
    with pytest.raises(ValueError):
        validate_action(Action(team="red", kind="exploit_rce"))
    validate_action(Action(team="red", kind="recon"))


def test_unknown_team_rejected():
    with pytest.raises(ValueError):
        _va(Action(team="green", kind="whatever"))


def test_red_score_rewards_progress_and_flag():
    s = RedScore(recon=1, paths_found=3, findings_weight=10, flag_captured=True)
    assert s.total == 5 + 6 + 10 + 25


def test_blue_penalized_for_false_blocks():
    good = BlueScore(true_positive_detections=2, ticks_to_first_detection=1,
                     blocked_attacker_before_flag=True, sla_uptime=1.0,
                     legit_availability=1.0, false_blocks=0)
    bad = good.model_copy(update={"false_blocks": 3, "legit_availability": 0.4})
    assert bad.total < good.total


def test_resilience_is_bounded_and_drops_on_flag():
    findings = FindingList()
    findings.add(Finding(id="x", title="t", owasp="A01", severity=Severity.HIGH,
                         description="d", evidence="e", mitigation="m"))
    held = compute_resilience(
        RedScore(flag_captured=False),
        BlueScore(true_positive_detections=2, blocked_attacker_before_flag=True),
        findings)
    lost = compute_resilience(
        RedScore(flag_captured=True),
        BlueScore(true_positive_detections=0, sla_uptime=1.0, legit_availability=1.0),
        findings)
    assert 0 <= lost <= held <= 100


def test_attack_mapping_present():
    assert technique_for("recon").technique_id == "T1595"
    assert technique_for("block_ip") is not None
