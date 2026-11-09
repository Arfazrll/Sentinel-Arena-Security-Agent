"""The referee / game engine: tick loop, action validation, scoring, ATT&CK."""

from .actions import (
    BLUE_ACTIONS,
    MAX_ACTIONS_PER_TICK,
    RED_ACTIONS,
    Action,
    ActionResult,
    validate_action,
)
from .attack_map import ATTACK_MAP, technique_for
from .context import EngagementContext, SharedState
from .killswitch import KillSwitch
from .referee import EngagementResult, Referee
from .scoring import BlueScore, RedScore, ScoreBoard, compute_resilience

__all__ = [
    "BLUE_ACTIONS",
    "RED_ACTIONS",
    "MAX_ACTIONS_PER_TICK",
    "Action",
    "ActionResult",
    "validate_action",
    "ATTACK_MAP",
    "technique_for",
    "EngagementContext",
    "SharedState",
    "KillSwitch",
    "EngagementResult",
    "Referee",
    "BlueScore",
    "RedScore",
    "ScoreBoard",
    "compute_resilience",
]
