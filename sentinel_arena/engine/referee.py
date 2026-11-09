"""The referee — the single authority over an engagement.

Turn-based tick loop. Each tick, each team proposes at most three actions. For
every action the referee: validates its format and permission, executes it
through a trusted executor, logs the event, tags it with MITRE ATT&CK, and
updates the score. Agents never touch authoritative state directly — they only
propose; the referee decides. This determinism makes runs replayable.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field

from ..detect.checks import build_checks
from ..detect.findings import FindingList
from ..telemetry.events import EventStore
from .actions import MAX_ACTIONS_PER_TICK, Action, ActionResult, validate_action
from .attack_map import technique_for
from .context import EngagementContext
from .killswitch import KillSwitch
from .scoring import (
    BlueScore,
    RedScore,
    ScoreBoard,
    compute_resilience,
    findings_weight,
)

_ADMIN_HINT = re.compile(r"admin console at (\S+?)\s*-->")
_FLAG_HREF = re.compile(r"href='([^']+)'")

# Request markers that only an attacker produces — the blue team's signal.
MALICIOUS_MARKERS = {"sensitive", "admin", "flag", "verbose_error"}


@dataclass
class EngagementResult:
    scenario_id: str
    seed: int
    scoreboard: ScoreBoard
    findings: FindingList
    ticks_run: int
    ended_reason: str
    duration_s: float
    events_path: str
    audit_path: str


# ---------------------------------------------------------------------------
# Red executors
# ---------------------------------------------------------------------------
def _exec_red(ctx: EngagementContext, action: Action) -> ActionResult:
    kind = action.kind
    st = ctx.state
    if kind == "recon":
        r = ctx.red_client.get("/")
        found = []
        m = _ADMIN_HINT.search(r.text)
        if m:
            st.discovered_admin_path = m.group(1)
            st.discovered_paths.add(m.group(1))
            found.append(m.group(1))
        st.recon_done = True
        return ActionResult(action=action, ok=True,
                           detail=f"mapped site; hints={found}",
                           data={"admin_path": st.discovered_admin_path})

    if kind == "enumerate_paths":
        candidates = ["/config.json", "/error", "/search?q=hi", "/health"]
        hits = []
        for p in candidates:
            resp = ctx.red_client.get(p)
            if resp.status == 200:
                st.discovered_paths.add(p.split("?")[0])
                hits.append(p)
        return ActionResult(action=action, ok=True, detail=f"enumerated {hits}",
                           data={"hits": hits})

    if kind == "detect":
        admin_path = st.discovered_admin_path or ctx.scenario.admin_path
        checks = build_checks(admin_path)
        new = []
        for key, check in checks.items():
            finding = check(ctx.red_client)
            if finding is not None:
                finding.tick = ctx.tick
                before = len(st.findings.findings)
                st.findings.add(finding)
                if len(st.findings.findings) > before:
                    new.append(finding.title)
                    ctx.events.emit(kind="finding", team="red", actor="red",
                                   tick=ctx.tick, summary=finding.title,
                                   data={"owasp": finding.owasp,
                                         "severity": finding.severity.value,
                                         "url": finding.url})
        return ActionResult(action=action, ok=bool(new),
                           detail=f"found {len(new)} new finding(s)",
                           data={"new": new})

    if kind == "capture_flag":
        admin_path = st.discovered_admin_path or ctx.scenario.admin_path
        admin_resp = ctx.red_client.get(admin_path)
        if admin_resp.status != 200:
            return ActionResult(action=action, ok=False,
                               detail=f"admin unreachable ({admin_resp.status})")
        m = _FLAG_HREF.search(admin_resp.text)
        if not m:
            return ActionResult(action=action, ok=False, detail="no flag link found")
        flag_path = m.group(1)
        st.discovered_flag_path = flag_path
        flag_resp = ctx.red_client.get(flag_path)
        if flag_resp.status == 200 and flag_resp.text.startswith("FLAG{"):
            st.flag_captured = True
            return ActionResult(action=action, ok=True, detail="flag captured",
                               data={"flag_path": flag_path})
        return ActionResult(action=action, ok=False,
                           detail=f"flag unreachable ({flag_resp.status})")

    return ActionResult(action=action, ok=False, detail="unknown red action")


# ---------------------------------------------------------------------------
# Blue executors (whitelist only)
# ---------------------------------------------------------------------------
def _exec_blue(ctx: EngagementContext, action: Action) -> ActionResult:
    kind = action.kind
    st = ctx.state

    if kind == "query_logs":
        # Inspect request events; flag actors that produced attacker-only markers.
        suspects = set()
        for e in ctx.events.query(kind="request"):
            if e.data.get("marker") in MALICIOUS_MARKERS:
                suspects.add(e.actor)
        newly = suspects - st.detected_attackers
        st.detected_attackers |= suspects
        if suspects and st.ticks_to_first_detection is None:
            st.ticks_to_first_detection = ctx.tick
        return ActionResult(action=action, ok=True,
                           detail=f"suspects={sorted(suspects)}",
                           data={"suspects": sorted(suspects),
                                 "new": sorted(newly)})

    if kind == "block_ip":
        actor = action.params.get("actor", "")
        if not actor:
            return ActionResult(action=action, ok=False, detail="no actor given")
        ctx.range.block(actor)
        st.blocked_actors.add(actor)
        return ActionResult(action=action, ok=True, detail=f"blocked {actor}",
                           data={"actor": actor})

    if kind == "isolate_host":
        # Simulated containment: block every known actor that is a suspect.
        for actor in sorted(ctx.state.detected_attackers):
            ctx.range.block(actor)
            st.blocked_actors.add(actor)
        return ActionResult(action=action, ok=True, detail="isolated suspects")

    if kind in {"kill_process", "rotate_password", "restart_service"}:
        # Benign, logged simulated responses — the whitelist is real and callable.
        return ActionResult(action=action, ok=True, detail=f"{kind} (simulated)")

    return ActionResult(action=action, ok=False, detail="unknown blue action")


def _execute(ctx: EngagementContext, action: Action) -> ActionResult:
    if action.team == "red":
        return _exec_red(ctx, action)
    return _exec_blue(ctx, action)


# ---------------------------------------------------------------------------
# The loop
# ---------------------------------------------------------------------------
class Referee:
    def __init__(
        self,
        ctx: EngagementContext,
        red_agent,
        blue_agent,
        *,
        killswitch: KillSwitch | None = None,
        traffic=None,
        tick_delay_s: float = 0.0,
    ) -> None:
        self.ctx = ctx
        self.red = red_agent
        self.blue = blue_agent
        self.kill = killswitch or KillSwitch()
        self.traffic = traffic  # optional benign traffic generator
        self._sla_samples: list[bool] = []
        # Optional pacing so a live viewer can follow the match. The wait is
        # interruptible: tripping the kill switch wakes it immediately.
        self.tick_delay_s = max(0.0, float(tick_delay_s))

    def _run_team(self, agent, team: str) -> None:
        proposed = agent.propose(self.ctx) or []
        if len(proposed) > MAX_ACTIONS_PER_TICK:
            self.ctx.events.emit(kind="rejected", team=team, tick=self.ctx.tick,
                                summary="too many actions proposed",
                                data={"proposed": len(proposed),
                                      "cap": MAX_ACTIONS_PER_TICK})
            proposed = proposed[:MAX_ACTIONS_PER_TICK]
        for action in proposed:
            if self.kill.tripped:
                return
            try:
                validate_action(action)
            except ValueError as e:
                self.ctx.events.emit(kind="rejected", team=team, tick=self.ctx.tick,
                                    summary=f"invalid action: {e}",
                                    data={"kind": action.kind})
                continue
            result = _execute(self.ctx, action)
            tech = technique_for(action.kind)
            self.ctx.events.emit(
                kind="action", team=team, actor=team, tick=self.ctx.tick,
                summary=f"{action.kind}: {result.detail}",
                data={"kind": action.kind, "ok": result.ok,
                      "attack_technique": tech.technique_id if tech else None,
                      "technique_name": tech.name if tech else None,
                      "tactic": tech.tactic if tech else None,
                      "rationale": action.rationale,
                      "params": action.params,
                      **result.data},
            )

    def run(self) -> EngagementResult:
        ctx = self.ctx
        start = time.monotonic()
        scenario = ctx.scenario
        ended = "max_ticks"

        ctx.events.emit(kind="engagement_start", team="system",
                       summary=f"{scenario.id} seed run start",
                       data={"max_ticks": scenario.max_ticks})

        tick = 0
        for tick in range(scenario.max_ticks):
            if self.kill.tripped:
                ended = f"killswitch: {self.kill.reason}"
                break
            ctx.tick = tick

            # SLA sample: is the service alive this tick?
            self._sla_samples.append(ctx.range.health_ok(scenario))

            # Background legitimate traffic (blue must not block these).
            if self.traffic is not None:
                self.traffic.generate(ctx.range, tick=tick)

            self.ctx.events.emit(kind="tick", team="system", tick=tick,
                                summary=f"tick {tick} begin")

            self._run_team(self.red, "red")
            if self.kill.tripped:
                ended = f"killswitch: {self.kill.reason}"
                break
            self._run_team(self.blue, "blue")

            self._emit_tick_score(tick)

            if ctx.state.flag_captured:
                ended = "flag_captured"
                break

            if self.tick_delay_s and tick < scenario.max_ticks - 1:
                if self.kill.wait(self.tick_delay_s):
                    ended = f"killswitch: {self.kill.reason}"
                    break

        ticks_run = tick + 1
        result = self._finalize(ticks_run, ended, time.monotonic() - start,
                               events_path=str(ctx.events.path))
        return result

    def _emit_tick_score(self, tick: int) -> None:
        """Running scoreboard after this tick - feeds the live charts."""
        board = self._board()
        st = self.ctx.state
        self.ctx.events.emit(
            kind="score_tick", team="system", tick=tick,
            summary=f"tick {tick}: resilience {board.resilience}",
            data={"red": board.red.total, "blue": board.blue.total,
                  "resilience": board.resilience,
                  "findings": len(st.findings.findings),
                  "blocked": sorted(st.blocked_actors),
                  "detected": sorted(st.detected_attackers),
                  "paths": sorted(st.discovered_paths),
                  "flag_captured": st.flag_captured,
                  "sla_ok": bool(self._sla_samples[-1]) if self._sla_samples else True},
        )

    def _finalize(self, ticks_run, ended, duration, events_path) -> EngagementResult:
        ctx = self.ctx
        board = self._board()
        red, blue, resilience = board.red, board.blue, board.resilience
        ctx.events.emit(kind="score", team="system", tick=ticks_run - 1,
                       summary=board.summary(),
                       data={"red": red.total, "blue": blue.total,
                             "resilience": resilience, "ended": ended})

        return EngagementResult(
            scenario_id=ctx.scenario.id,
            seed=ctx.seed,
            scoreboard=board,
            findings=ctx.state.findings,
            ticks_run=ticks_run,
            ended_reason=ended,
            duration_s=round(duration, 3),
            events_path=events_path,
            audit_path="",  # filled in by the orchestrator
        )

    def _board(self) -> ScoreBoard:
        ctx = self.ctx
        st = ctx.state

        red = RedScore(
            recon=1 if st.recon_done else 0,
            paths_found=len(st.discovered_paths),
            findings_weight=findings_weight(st.findings),
            flag_captured=st.flag_captured,
        )

        # Legit availability + false blocks from the request log.
        legit_total = legit_ok = 0
        blocked_legit: set[str] = set()
        for e in ctx.events.query(kind="request"):
            if e.actor.startswith("legit"):
                legit_total += 1
                if e.data.get("status") == 200:
                    legit_ok += 1
                elif e.data.get("marker") == "blocked":
                    blocked_legit.add(e.actor)
        legit_availability = (legit_ok / legit_total) if legit_total else 1.0
        sla_uptime = (sum(self._sla_samples) / len(self._sla_samples)
                      if self._sla_samples else 1.0)

        # True positives: suspects that really are attackers (actor "red").
        true_positives = sum(1 for a in st.detected_attackers if a == "red")
        blocked_before_flag = ("red" in st.blocked_actors) and not st.flag_captured

        blue = BlueScore(
            true_positive_detections=true_positives,
            ticks_to_first_detection=st.ticks_to_first_detection,
            blocked_attacker_before_flag=blocked_before_flag,
            sla_uptime=sla_uptime,
            legit_availability=legit_availability,
            false_blocks=len(blocked_legit),
        )

        resilience = compute_resilience(red, blue, st.findings)
        return ScoreBoard(red=red, blue=blue, resilience=resilience)
