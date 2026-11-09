"""Agent interface.

An agent only *proposes* actions for the current tick; the referee validates,
executes, logs, and scores. This keeps the referee the single authority and
lets LLM agents (a later milestone) and scripted baseline bots share one
interface. Bring-your-own-agent (MCP) plugs in here.
"""

from __future__ import annotations

from typing import Protocol

from ..engine.actions import Action
from ..engine.context import EngagementContext


class Agent(Protocol):
    name: str
    team: str

    def propose(self, ctx: EngagementContext) -> list[Action]:
        ...
