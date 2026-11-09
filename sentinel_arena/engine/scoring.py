"""Scoring + resilience score.

Design goals from the brief:
* Reward red for *progress* — foothold, escalation, flag — not for damage.
* Reward blue for correct, fast detection and for keeping services alive (SLA).
* Penalize blue for downing its own services or blocking legitimate users, so
  the degenerate "block everything" defense scores badly.

Every term is explicit so a run is explainable in the audit report.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

from ..detect.findings import FindingList, Severity


class RedScore(BaseModel):
    recon: int = 0
    paths_found: int = 0
    findings_weight: int = 0
    flag_captured: bool = False

    @property
    def total(self) -> int:
        return (
            (5 if self.recon else 0)
            + 2 * self.paths_found
            + self.findings_weight
            + (25 if self.flag_captured else 0)
        )


class BlueScore(BaseModel):
    true_positive_detections: int = 0
    ticks_to_first_detection: int | None = None
    blocked_attacker_before_flag: bool = False
    sla_uptime: float = 1.0           # fraction of health checks that passed
    legit_availability: float = 1.0   # fraction of legit requests that succeeded
    false_blocks: int = 0

    @property
    def speed_bonus(self) -> int:
        if self.ticks_to_first_detection is None:
            return 0
        return max(0, 10 - self.ticks_to_first_detection)

    @property
    def total(self) -> int:
        return int(
            4 * self.true_positive_detections
            + self.speed_bonus
            + (15 if self.blocked_attacker_before_flag else 0)
            + 10 * self.sla_uptime
            + 10 * self.legit_availability
            - 5 * self.false_blocks
        )


class ScoreBoard(BaseModel):
    red: RedScore = Field(default_factory=RedScore)
    blue: BlueScore = Field(default_factory=BlueScore)
    resilience: int = 0

    def summary(self) -> str:
        return (
            f"red={self.red.total} blue={self.blue.total} "
            f"resilience={self.resilience}/100 "
            f"(flag {'captured' if self.red.flag_captured else 'not captured'})"
        )


def findings_weight(findings: FindingList) -> int:
    return sum(Severity(f.severity).weight for f in findings.findings)


def compute_resilience(red: RedScore, blue: BlueScore, findings: FindingList) -> int:
    """A 0–100 resilience score: how well the defender held up.

    Starts at a neutral 50 and moves on defensive quality and attacker success.
    """
    score = 50.0
    # Defensive quality raises resilience.
    score += 12 * blue.sla_uptime
    score += 8 * blue.legit_availability
    if blue.blocked_attacker_before_flag:
        score += 15
    if blue.true_positive_detections > 0:
        score += min(10, 3 * blue.true_positive_detections)
    # Attacker success and unmitigated severity lower it.
    if red.flag_captured:
        score -= 30
    high = sum(
        1 for f in findings.findings
        if Severity(f.severity) in (Severity.HIGH, Severity.CRITICAL)
    )
    score -= 5 * high
    score -= 3 * blue.false_blocks
    return max(0, min(100, int(round(score))))
