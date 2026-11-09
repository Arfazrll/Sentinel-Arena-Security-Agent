from __future__ import annotations

from sentinel_arena.leaderboard import run_benchmark, to_markdown

SEEDS = [42, 7, 101]


def test_benchmark_compares_two_defenders():
    stats = run_benchmark(seeds=SEEDS, blues=["scripted", "noop"])
    by_blue = {s.blue: s for s in stats}
    assert set(by_blue) == {"scripted", "noop"}

    # A passive defender lets the attacker win every time; the scripted defender
    # stops it. This is the whole point of the leaderboard.
    assert by_blue["noop"].flag_capture_rate == 1.0
    assert by_blue["scripted"].flag_capture_rate == 0.0
    assert by_blue["scripted"].mean_resilience > by_blue["noop"].mean_resilience


def test_markdown_table_renders():
    stats = run_benchmark(seeds=SEEDS)
    md = to_markdown(stats, SEEDS)
    assert "Attacker win %" in md
    assert "scripted" in md and "noop" in md
