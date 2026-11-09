"""Model/agent leaderboard across many seeded runs.

Runs a cross-product of red x blue agents over a set of seeds and aggregates the
outcomes into a comparable table: attacker win rate (flag capture), mean
resilience, mean scores, and mean time-to-detection. This is how the platform
answers "which agent defends better?" — the brief's leaderboard, framed around
the :class:`Agent` interface so an LLM agent is just another registry entry.

Agents are looked up by name in a registry, so adding a new attacker or defender
(scripted, or a future LLM/MCP agent) is a one-line registration — the harness
does not change.
"""

from __future__ import annotations

import tempfile
from statistics import mean

from pydantic import BaseModel

from .agents.scripted.blue import NoOpBlue, ScriptedBlue
from .agents.scripted.red import ScriptedRed
from .engagement import run_engagement

# name -> factory. Extend these to compare more agents (incl. LLM later).
RED_AGENTS = {
    "scripted": ScriptedRed,
}
BLUE_AGENTS = {
    "scripted": ScriptedBlue,
    "noop": NoOpBlue,
}


class MatchupStats(BaseModel):
    red: str
    blue: str
    runs: int
    flag_capture_rate: float   # attacker win rate
    mean_resilience: float
    mean_red_score: float
    mean_blue_score: float
    mean_ticks_to_detection: float | None
    mean_duration_s: float


def run_benchmark(
    *,
    seeds: list[int],
    reds: list[str] | None = None,
    blues: list[str] | None = None,
    scenario: str = "shop-01",
) -> list[MatchupStats]:
    reds = reds or list(RED_AGENTS)
    blues = blues or list(BLUE_AGENTS)
    out: list[MatchupStats] = []

    with tempfile.TemporaryDirectory(prefix="arena-bench-") as tmp:
        for red in reds:
            for blue in blues:
                res = []
                for seed in seeds:
                    art = run_engagement(
                        scenario, seed=seed,
                        red_agent=RED_AGENTS[red](),
                        blue_agent=BLUE_AGENTS[blue](),
                        out_dir=f"{tmp}/{red}-{blue}-{seed}",
                        generate_report=False,
                    )
                    res.append(art.result)
                caps = [1 for r in res if r.scoreboard.red.flag_captured]
                ttds = [r.scoreboard.blue.ticks_to_first_detection for r in res
                        if r.scoreboard.blue.ticks_to_first_detection is not None]
                out.append(MatchupStats(
                    red=red, blue=blue, runs=len(res),
                    flag_capture_rate=round(len(caps) / len(res), 3),
                    mean_resilience=round(mean(r.scoreboard.resilience for r in res), 1),
                    mean_red_score=round(mean(r.scoreboard.red.total for r in res), 1),
                    mean_blue_score=round(mean(r.scoreboard.blue.total for r in res), 1),
                    mean_ticks_to_detection=round(mean(ttds), 2) if ttds else None,
                    mean_duration_s=round(mean(r.duration_s for r in res), 3),
                ))
    # Rank by resilience (defender efficacy) descending.
    out.sort(key=lambda s: s.mean_resilience, reverse=True)
    return out


def to_markdown(stats: list[MatchupStats], seeds: list[int]) -> str:
    lines = [
        f"## Benchmark - {len(seeds)} seed(s): {', '.join(map(str, seeds))}",
        "",
        "| Red | Blue | Runs | Attacker win % | Mean resilience | "
        "Mean red | Mean blue | Mean ticks-to-detect |",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for s in stats:
        ttd = "-" if s.mean_ticks_to_detection is None else f"{s.mean_ticks_to_detection}"
        lines.append(
            f"| {s.red} | {s.blue} | {s.runs} | {s.flag_capture_rate*100:.0f}% | "
            f"{s.mean_resilience} | {s.mean_red_score} | {s.mean_blue_score} | {ttd} |"
        )
    return "\n".join(lines)
