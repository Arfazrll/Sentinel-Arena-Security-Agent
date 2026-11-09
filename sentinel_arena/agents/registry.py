"""Agent registry - one place that names every red and blue agent.

The CLI, the API, and the leaderboard all resolve agents here, so adding an
agent is one entry. Each entry carries display metadata for the web app.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Callable

from ..engine.actions import BLUE_ACTIONS, RED_ACTIONS
from .scripted.blue import NoOpBlue, ScriptedBlue
from .scripted.red import ScriptedRed
from .scripted.variants import ParanoidBlue, RushRed, SweeperBlue


def _llm_red():
    from .llm import LLMRed, default_anthropic_client
    return LLMRed(default_anthropic_client())


def _llm_blue():
    from .llm import LLMBlue, default_anthropic_client
    return LLMBlue(default_anthropic_client())


def _llm_ready() -> bool:
    return bool(os.environ.get("ANTHROPIC_API_KEY"))


@dataclass(frozen=True)
class AgentSpec:
    name: str
    team: str  # "red" | "blue"
    label: str
    kind: str  # "scripted" | "llm" | "baseline"
    description: str
    strategy: list[str]
    factory: Callable[[], object] = field(repr=False, compare=False)
    benchmark: bool = True  # included in the default leaderboard run
    availability: Callable[[], bool] = field(default=lambda: True, repr=False,
                                             compare=False)

    def available(self) -> bool:
        return self.availability()

    def build(self):
        return self.factory()

    def to_dict(self) -> dict:
        return {
            "name": self.name, "team": self.team, "label": self.label,
            "kind": self.kind, "description": self.description,
            "strategy": self.strategy, "benchmark": self.benchmark,
            "available": self.available(),
            "actions": sorted(RED_ACTIONS if self.team == "red" else BLUE_ACTIONS),
        }


RED: dict[str, AgentSpec] = {
    "scripted": AgentSpec(
        name="scripted", team="red", label="Methodical", kind="scripted",
        description="Full kill chain: recon, enumerate, detect weaknesses, then "
                    "capture the flag. The baseline attacker.",
        strategy=["recon", "enumerate_paths", "detect", "capture_flag"],
        factory=ScriptedRed),
    "rush": AgentSpec(
        name="rush", team="red", label="Rush", kind="scripted",
        description="Skips enumeration and goes straight for the admin-to-flag "
                    "chain. Tests whether the defender is fast enough.",
        strategy=["recon", "capture_flag"],
        factory=RushRed),
    "llm": AgentSpec(
        name="llm", team="red", label="LLM attacker", kind="llm",
        description="Model-driven attacker over the same gated vocabulary. "
                    "Needs ANTHROPIC_API_KEY.",
        strategy=["model-chosen"], factory=_llm_red, benchmark=False,
        availability=_llm_ready),
}

BLUE: dict[str, AgentSpec] = {
    "scripted": AgentSpec(
        name="scripted", team="blue", label="Real-time SOC", kind="scripted",
        description="Reviews the request log every tick and blocks any actor "
                    "that touches attacker-only endpoints.",
        strategy=["query_logs", "block_ip"], factory=ScriptedBlue),
    "sweeper": AgentSpec(
        name="sweeper", team="blue", label="Batch SOC", kind="scripted",
        description="Same evidence-based blocking, but the log is only reviewed "
                    "every third tick. Slower to detect.",
        strategy=["query_logs (every 3 ticks)", "block_ip"], factory=SweeperBlue),
    "paranoid": AgentSpec(
        name="paranoid", team="blue", label="Block-everything", kind="baseline",
        description="Blocks every actor it sees, including real users. Shows "
                    "why the scoring penalizes false blocks.",
        strategy=["block_ip (everyone)"], factory=ParanoidBlue),
    "noop": AgentSpec(
        name="noop", team="blue", label="No defense", kind="baseline",
        description="Does nothing. Proves the scenario is solvable.",
        strategy=["none"], factory=NoOpBlue),
    "llm": AgentSpec(
        name="llm", team="blue", label="LLM defender", kind="llm",
        description="Model-driven defender limited to the defensive whitelist. "
                    "Needs ANTHROPIC_API_KEY.",
        strategy=["model-chosen"], factory=_llm_blue, benchmark=False,
        availability=_llm_ready),
}


def get(team: str, name: str) -> AgentSpec:
    table = RED if team == "red" else BLUE
    if name not in table:
        raise KeyError(f"unknown {team} agent {name!r}; "
                       f"choose one of {sorted(table)}")
    return table[name]


def benchmark_names(team: str) -> list[str]:
    table = RED if team == "red" else BLUE
    return [n for n, s in table.items() if s.benchmark]


def all_agents() -> list[dict]:
    return [s.to_dict() for s in RED.values()] + [s.to_dict() for s in BLUE.values()]
