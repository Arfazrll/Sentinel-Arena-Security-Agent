"""Sentinel Arena command-line interface.

    arena run --scenario shop-01 --red scripted --blue scripted --seed 42
    arena scenarios
    arena replay var/engagements/shop-01-42
    arena verify-audit var/engagements/shop-01-42/audit.jsonl
    arena agents
    arena export var/engagements/shop-01-42 --format sarif
"""

from __future__ import annotations

import json
from pathlib import Path

import typer

from .authz.audit import AuditLog
from .scenarios.loader import list_scenarios
from .telemetry.events import EventStore

app = typer.Typer(add_completion=False, help="Sentinel Arena — authorized "
                  "security-resilience engagements.")


@app.command()
def run(
    scenario: str = typer.Option("shop-01", help="Scenario id."),
    seed: int = typer.Option(42, help="Randomizer seed."),
    red: str = typer.Option("scripted", help="Red agent (see `arena agents`)."),
    blue: str = typer.Option("scripted", help="Blue agent (see `arena agents`)."),
    out: str = typer.Option("", help="Output directory (default under var/)."),
):
    """Run one full engagement end to end against the bundled sandbox app."""
    from .engagement import run_engagement

    typer.echo(f"Running {scenario} (seed {seed}, red={red}, blue={blue}) ...")
    art = run_engagement(
        scenario, seed=seed, red_name=red, blue_name=blue,
        out_dir=out or None,
    )
    r = art.result
    sb = r.scoreboard
    typer.echo("")
    typer.secho(f"  Resilience: {sb.resilience}/100", fg="green" if sb.resilience >= 70
                else "yellow" if sb.resilience >= 40 else "red", bold=True)
    typer.echo(f"  Outcome:    {r.ended_reason} after {r.ticks_run} tick(s)")
    typer.echo(f"  Red {sb.red.total}  |  Blue {sb.blue.total}  |  "
               f"flag {'captured' if sb.red.flag_captured else 'not captured'}")
    typer.echo(f"  Findings:   {len(r.findings.findings)} "
               f"({', '.join(f.severity.value for f in r.findings.findings) or 'none'})")
    typer.echo("")
    typer.echo(f"  Report:  {art.report_html}")
    typer.echo(f"  Events:  {art.events_path}")
    typer.echo(f"  Audit:   {art.audit_path}"
               + ("  (PDF: " + str(art.report_pdf) + ")" if art.report_pdf else ""))


@app.command()
def scenarios():
    """List available scenarios."""
    for s in list_scenarios():
        typer.echo(s)


@app.command()
def bench(
    seeds: str = typer.Option("42,7,101,2,5", help="Comma-separated seeds."),
    scenario: str = typer.Option("shop-01"),
    out: str = typer.Option("var/bench", help="Output directory."),
):
    """Run a leaderboard benchmark across red x blue agents and seeds."""
    from .leaderboard import run_benchmark, to_markdown

    seed_list = [int(x) for x in seeds.split(",") if x.strip()]
    typer.echo(f"Benchmarking {scenario} over {len(seed_list)} seed(s) ...")
    stats = run_benchmark(seeds=seed_list, scenario=scenario)
    md = to_markdown(stats, seed_list)
    out_dir = Path(out)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "leaderboard.md").write_text(md, encoding="utf-8")
    (out_dir / "leaderboard.json").write_text(
        json.dumps([s.model_dump() for s in stats], indent=2), encoding="utf-8")
    typer.echo("")
    typer.echo(md)
    typer.echo("")
    typer.echo(f"  Written: {out_dir / 'leaderboard.md'}")


@app.command()
def campaign(
    target: str = typer.Option("127.0.0.1", help="Target label. External hosts "
                               "require proven ownership (see --i-own-this)."),
    depth: str = typer.Option("standard", help="quick | standard | deep. "
                              "deep runs into the hundreds of engagements."),
    scenarios_opt: str = typer.Option("", "--scenarios", help="Comma-separated "
                                      "scenario ids (default: all)."),
    label: str = typer.Option("", help="Human label for the assessment."),
    out: str = typer.Option("var/campaigns", help="Output directory."),
    workers: int = typer.Option(1, help="Parallel engagements (each is isolated)."),
    i_own_this: bool = typer.Option(False, "--i-own-this", help="Assert ownership "
                                    "of a non-sandbox target has been proven."),
):
    """Assess a target across a whole matrix of scenarios and produce one
    prioritized vulnerabilities-and-mitigations verdict."""
    from .campaign import CampaignPlan, run_campaign, save_campaign

    sel = [s.strip() for s in scenarios_opt.split(",") if s.strip()]
    plan = CampaignPlan(target=target, depth=depth, scenarios=sel, label=label,
                        ownership_proven=i_own_this)
    total = plan.total_runs()
    typer.echo(f"Campaign on {target!r} ({depth}): planning ~{total} graded runs "
               f"+ a posture scan ...")

    state = {"n": 0}

    def _progress(done, tot, lbl):
        state["n"] = done
        if done == tot or done % 5 == 0:
            typer.echo(f"  [{done:>3}/{tot}] {lbl}")

    res = run_campaign(plan, on_progress=_progress, max_workers=workers)
    out_dir = Path(out) / res.id
    save_campaign(res, out_dir)

    typer.echo("")
    typer.secho(f"  Posture grade: {res.posture_grade}", bold=True,
                fg="green" if res.posture_grade in ("A", "B")
                else "yellow" if res.posture_grade == "C" else "red")
    typer.echo(f"  Resilience:    worst {res.worst_resilience} / mean "
               f"{res.mean_resilience:.0f} / best {res.best_resilience} (of 100)")
    typer.echo(f"  Attacker win:  {res.attacker_win_rate*100:.0f}% of graded runs")
    typer.echo(f"  Runs:          {res.runs}")
    typer.echo("")
    typer.echo("  Prioritized remediation plan:")
    for i, v in enumerate(res.vulnerabilities, 1):
        typer.echo(f"   {i:>2}. [{v.priority}] {v.severity:<8} {v.title}  "
                   f"(fix <= {v.fix_sla_days}d, seen {v.occurrences}x)")
    if not res.vulnerabilities:
        typer.echo("    (no findings surfaced)")
    typer.echo("")
    typer.echo(f"  Report:  {out_dir / 'campaign.md'}")
    typer.echo(f"  JSON:    {out_dir / 'campaign.json'}")


@app.command()
def replay(engagement_dir: str):
    """Replay an engagement's timeline and score from its stored events."""
    d = Path(engagement_dir)
    result_file = d / "result.json"
    if result_file.exists():
        data = json.loads(result_file.read_text(encoding="utf-8"))
        typer.secho(f"Scenario {data['scenario']} seed {data['seed']} - "
                    f"resilience {data['scoreboard']['resilience']}/100 "
                    f"({data['ended']})", bold=True)
    typer.echo("")
    for e in EventStore(d / "events.jsonl"):
        if e.kind in {"action", "finding", "score", "tick"}:
            tag = f"[{e.tick:>2}] {e.team:<6}" if e.tick >= 0 else "       "
            typer.echo(f"{tag} {e.kind:<8} {e.summary}")


@app.command()
def agents():
    """List the registered red and blue agents."""
    from .agents.registry import BLUE, RED

    for team, table in (("red", RED), ("blue", BLUE)):
        for name, spec in table.items():
            flag = "" if spec.available() else "  (unavailable: needs API key)"
            typer.echo(f"{team:<5} {name:<10} {spec.label:<18} {spec.description}{flag}")


@app.command()
def export(
    engagement_dir: str,
    format: str = typer.Option("sarif", help="sarif | navigator | csv"),
    out: str = typer.Option("", help="Output file (default next to result.json)."),
):
    """Export an engagement's findings as SARIF, an ATT&CK Navigator layer, or CSV."""
    from .report.compliance import enrich
    from .report.exports import to_csv, to_navigator_layer, to_sarif

    d = Path(engagement_dir)
    res = json.loads((d / "result.json").read_text(encoding="utf-8"))
    res["findings"] = [f if "rule_id" in f else enrich(f) for f in res["findings"]]
    if format == "sarif":
        body, ext = json.dumps(to_sarif(res), indent=2), "sarif"
    elif format == "navigator":
        events = [e.model_dump() for e in EventStore(d / "events.jsonl")]
        body, ext = json.dumps(to_navigator_layer(res, events), indent=2), "layer.json"
    elif format == "csv":
        body, ext = to_csv(res), "csv"
    else:
        raise typer.BadParameter("format must be sarif, navigator or csv")
    target = Path(out) if out else d / f"findings.{ext}"
    target.write_text(body, encoding="utf-8")
    typer.echo(f"  Written: {target}")


@app.command("verify-audit")
def verify_audit(audit_path: str):
    """Verify the tamper-evident hash chain of an audit log."""
    from .authz.audit import ChainBroken

    log = AuditLog(audit_path)
    try:
        log.verify_chain()
        typer.secho("audit chain intact [OK]", fg="green")
    except ChainBroken as e:
        typer.secho(f"audit chain BROKEN: {e}", fg="red")
        raise typer.Exit(code=1)


if __name__ == "__main__":
    app()
