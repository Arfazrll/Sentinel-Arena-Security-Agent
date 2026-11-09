"""Scripted blue team — the non-LLM baseline defender.

Each tick it monitors the engagement log, and the moment an actor produces an
attacker-only signal (accessing admin / sensitive / flag / error-leak
endpoints) it blocks that actor. It only ever acts through the defensive
whitelist, and it blocks by *evidence*, so it does not touch the legitimate
background users — which is what keeps its legit-availability score high.

``NoOpBlue`` does nothing; it exists to prove the scenario is solvable (red
should reach the flag against a passive defender).
"""

from __future__ import annotations

from ...engine.actions import Action
from ...engine.context import EngagementContext
from ...engine.referee import MALICIOUS_MARKERS


class ScriptedBlue:
    name = "scripted-blue"
    team = "blue"

    def propose(self, ctx: EngagementContext) -> list[Action]:
        actions = [Action(team="blue", kind="query_logs",
                         rationale="monitor request log for attacker signals")]
        # Inspect the log ourselves to decide whom to block.
        suspects = set()
        for e in ctx.events.query(kind="request"):
            if e.data.get("marker") in MALICIOUS_MARKERS:
                suspects.add(e.actor)
        for actor in sorted(suspects):
            if actor not in ctx.state.blocked_actors:
                actions.append(Action(team="blue", kind="block_ip",
                                     params={"actor": actor},
                                     rationale=f"{actor} hit attacker-only endpoints"))
        return actions


class NoOpBlue:
    name = "noop-blue"
    team = "blue"

    def propose(self, ctx: EngagementContext) -> list[Action]:
        return []
