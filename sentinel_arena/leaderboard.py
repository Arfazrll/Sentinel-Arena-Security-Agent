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

from .agents import registry
from .engagement import run_engagement

# name -> factory, resolved from the shared registry (benchmarkable agents only;
# LLM agents need an API key and are opt-in via ``reds=[...]`` / ``blues=[...]``).
RED_AGENTS = {n: registry.RED[n].factory for n in registry.benchmark_names("red")}
BLUE_AGENTS = {n: registry.BLUE[n].factory for n in registry.benchmark_names("blue")}


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
    red_label: str = ""
    blue_label: str = ""
    resilience_runs: list[int] = []
    mean_false_blocks: float = 0.0
    mean_sla_uptime: float = 1.0
    mean_ticks_run: float = 0.0


def run_benchmark(
    *,
    seeds: list[int],
    reds: list[str] | None = None,
    blues: list[str] | None = None,
    scenario: str = "shop-01",
    on_progress=None,
) -> list[MatchupStats]:
    """Run every red x blue x seed combination. ``on_progress(done, total, label)``
    is called after each run (used by the API's background benchmark jobs)."""
    reds = reds or list(RED_AGENTS)
    blues = blues or list(BLUE_AGENTS)
    out: list[MatchupStats] = []
    total = len(reds) * len(blues) * len(seeds)
    done = 0

    with tempfile.TemporaryDirectory(prefix="arena-bench-") as tmp:
        for red in reds:
            for blue in blues:
                res = []
                for seed in seeds:
                    art = run_engagement(
                        scenario, seed=seed,
                        red_agent=registry.get("red", red).build(),
                        blue_agent=registry.get("blue", blue).build(),
                        out_dir=f"{tmp}/{red}-{blue}-{seed}",
                        generate_report=False,
                    )
                    res.append(art.result)
                    done += 1
                    if on_progress is not None:
                        on_progress(done, total, f"{red} vs {blue} seed {seed}")
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
                    red_label=registry.get("red", red).label,
                    blue_label=registry.get("blue", blue).label,
                    resilience_runs=[r.scoreboard.resilience for r in res],
                    mean_false_blocks=round(mean(r.scoreboard.blue.false_blocks for r in res), 2),
                    mean_sla_uptime=round(mean(r.scoreboard.blue.sla_uptime for r in res), 3),
                    mean_ticks_run=round(mean(r.ticks_run for r in res), 1),
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
