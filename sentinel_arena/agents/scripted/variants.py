"""Extra scripted agents that widen the benchmark.

Each one is a different *policy* over the same vetted action vocabulary
(``engine.actions.RED_ACTIONS`` / ``BLUE_ACTIONS``). None of them adds a new
capability: red still only reaches the target through the referee's gated
client, and blue still only acts through the defensive whitelist.

* ``RushRed`` - skips enumeration and goes straight for the admin -> flag
  chain. It shows that a purely reactive defender can lose to a fast attacker.
* ``SweeperBlue`` - reviews the log only every third tick (a batch SOC
  workflow). Same evidence-based blocking, slower mean time to detect.
* ``ParanoidBlue`` - blocks every actor it sees. This is the degenerate
  "block everything" defense the scoring is built to penalize: it knocks
  legitimate users and the health check offline.
"""

from __future__ import annotations

from ...engine.actions import Action
from ...engine.context import EngagementContext
from ...engine.referee import MALICIOUS_MARKERS


class RushRed:
    name = "rush-red"
    team = "red"

    def propose(self, ctx: EngagementContext) -> list[Action]:
        if ctx.state.flag_captured:
            return []
        if ctx.tick == 0:
            return [Action(team="red", kind="recon",
                          rationale="read the landing page for leaked hints")]
        return [Action(team="red", kind="capture_flag",
                      rationale="go straight for admin -> flag before blue reacts")]


class SweeperBlue:
    name = "sweeper-blue"
    team = "blue"
    interval = 3

    def propose(self, ctx: EngagementContext) -> list[Action]:
        if ctx.tick % self.interval != self.interval - 1:
            return []
        actions = [Action(team="blue", kind="query_logs",
                         rationale=f"scheduled log sweep (every {self.interval} ticks)")]
        suspects = {e.actor for e in ctx.events.query(kind="request")
                    if e.data.get("marker") in MALICIOUS_MARKERS}
        for actor in sorted(suspects - ctx.state.blocked_actors)[:2]:
            actions.append(Action(team="blue", kind="block_ip",
                                 params={"actor": actor},
                                 rationale=f"{actor} hit attacker-only endpoints"))
        return actions


class ParanoidBlue:
    name = "paranoid-blue"
    team = "blue"

    def propose(self, ctx: EngagementContext) -> list[Action]:
        seen = {e.actor for e in ctx.events.query(kind="request") if e.actor}
        fresh = sorted(seen - ctx.state.blocked_actors)
        return [Action(team="blue", kind="block_ip", params={"actor": a},
                       rationale="block everything that moves")
                for a in fresh[:3]]
