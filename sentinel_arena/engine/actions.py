"""Action models and the hard whitelist of blue defensive actions.

Every action an agent proposes is a validated Pydantic object. The referee
rejects anything malformed, out of the allowed set, or (for blue) outside the
defensive whitelist. Blue has **no free shell** — only these actions exist.
"""

from __future__ import annotations

from pydantic import BaseModel, Field

# Red is limited to non-destructive, detection-oriented actions. There is no
# "exploit" or "escalate-destructively" action in the vocabulary at all.
RED_ACTIONS = {"recon", "enumerate_paths", "detect", "capture_flag"}

# Blue's whitelist — the only defensive actions that exist (brief §7).
BLUE_ACTIONS = {
    "query_logs",
    "block_ip",
    "kill_process",
    "rotate_password",
    "restart_service",
    "isolate_host",
}

MAX_ACTIONS_PER_TICK = 3


class Action(BaseModel):
    team: str  # "red" | "blue"
    kind: str
    params: dict = Field(default_factory=dict)
    rationale: str = ""


class ActionResult(BaseModel):
    action: Action
    ok: bool
    detail: str = ""
    data: dict = Field(default_factory=dict)


def validate_action(action: Action) -> None:
    """Raise ValueError if the action is not permitted by its team's vocabulary."""
    if action.team == "red":
        if action.kind not in RED_ACTIONS:
            raise ValueError(f"red action not permitted: {action.kind!r}")
    elif action.team == "blue":
        if action.kind not in BLUE_ACTIONS:
            raise ValueError(
                f"blue action not in defensive whitelist: {action.kind!r}"
            )
    else:
        raise ValueError(f"unknown team: {action.team!r}")
