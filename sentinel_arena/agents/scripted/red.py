"""Scripted red team — the non-LLM baseline attacker.

A deterministic kill-chain that proves the scenario is solvable and sets the bar
the LLM red team must beat:

    recon -> enumerate -> detect -> capture flag

Every request it makes goes through the gated client, so it cannot act outside
the authorized scope. It is non-destructive: it reads, it does not break.
"""

from __future__ import annotations

from ...engine.actions import Action
from ...engine.context import EngagementContext


class ScriptedRed:
    name = "scripted-red"
    team = "red"

    def propose(self, ctx: EngagementContext) -> list[Action]:
        st = ctx.state
        if st.flag_captured:
            return []
        tick = ctx.tick
        if tick == 0:
            return [Action(team="red", kind="recon",
                          rationale="map the site, look for leaked hints")]
        if tick == 1:
            return [Action(team="red", kind="enumerate_paths",
                          rationale="probe common endpoints")]
        if tick == 2:
            return [Action(team="red", kind="detect",
                          rationale="run non-destructive weakness checks")]
        # From tick 3 on, keep trying to reach the flag (until blocked or done).
        return [Action(team="red", kind="capture_flag",
                      rationale="follow the admin -> archive -> flag chain")]
