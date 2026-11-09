"""Sentinel Arena command-line interface.

    arena run --scenario shop-01 --red scripted --blue scripted --seed 42
    arena scenarios
    arena replay var/engagements/shop-01-42
    arena verify-audit var/engagements/shop-01-42/audit.jsonl
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
    red: str = typer.Option("scripted", help="Red agent (scripted)."),
    blue: str = typer.Option("scripted", help="Blue agent (scripted|noop)."),
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
