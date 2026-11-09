"""End-to-end engagement orchestrator.

Wires every component together for one run:

    load scenario + randomize (seed)
      -> stand up the bundled range (our own target)
      -> AUTHORIZE: prove ownership of 127.0.0.1 via the gate (for real)
      -> run the referee tick loop (red vs blue, scored, logged)
      -> emit the resilience audit report

The authorization gate is exercised, never bypassed: the range serves the
well-known token the gate expects, so ``gate.authorize`` performs a genuine
ownership check before the red team is allowed to act. Everything runs on
127.0.0.1 with no third party involved.
"""

from __future__ import annotations

import json
import secrets as _secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path

from .agents import registry
from .authz import (
    AuditLog,
    AuthorizationGate,
    Environment,
    OwnershipVerifier,
    RateCap,
    Scope,
    StdlibHttpClient,
    VerificationMethod,
    make_challenge,
)
from .detect.client import GatedHttpClient
from .engine.context import EngagementContext
from .engine.killswitch import KillSwitch
from .engine.referee import EngagementResult, Referee
from .range.runner import bring_up
from .report.compliance import enrich
from .report.generator import write_report
from .report.kpis import compute_kpis
from .scenarios.loader import load_scenario
from .telemetry.events import EventStore, InMemoryEventSink
from .telemetry.traffic import BenignTraffic

HOST = "127.0.0.1"
USER = "arena-operator"


@dataclass
class EngagementArtifacts:
    result: EngagementResult
    out_dir: Path
    events_path: Path
    audit_path: Path
    report_html: Path | None
    report_md: Path | None
    report_pdf: Path | None


def _build_red(name: str):
    return registry.get("red", name).build()


def _build_blue(name: str):
    return registry.get("blue", name).build()


def _make_scope(now) -> Scope:
    return Scope(
        allowed_hosts=[HOST],
        allowed_paths=["/"],  # full sandbox site is in scope (we own it)
        blocklist=[],
        rate_cap=RateCap(max_requests=2000, per_seconds=60),
        environment=Environment.STAGING,
        not_before=now - timedelta(minutes=5),
        not_after=now + timedelta(hours=2),
    )


def run_engagement(
    scenario_id: str = "shop-01",
    *,
    seed: int = 42,
    out_dir: str | Path | None = None,
    red_name: str = "scripted",
    blue_name: str = "scripted",
    red_agent=None,
    blue_agent=None,
    killswitch: KillSwitch | None = None,
    on_event=None,
    generate_report: bool = True,
    range_backend: str = "inprocess",
    tick_delay_s: float = 0.0,
) -> EngagementArtifacts:
    started_at = datetime.now(timezone.utc)
    scenario = load_scenario(scenario_id)
    randomized = scenario.randomized(seed)

    out_dir = Path(out_dir) if out_dir else Path("var/engagements") / f"{scenario_id}-{seed}"
    out_dir.mkdir(parents=True, exist_ok=True)

    events = EventStore(out_dir / "events.jsonl")
    if on_event is not None:
        events.subscribe(on_event)  # live stream for the arena API
    audit = AuditLog(out_dir / "audit.jsonl")
    sink = InMemoryEventSink(events)

    # A per-run secret; in production this comes from a vault. The range will
    # serve exactly the token the gate expects, so verification is genuine.
    secret = _secrets.token_bytes(32)
    challenge = make_challenge(USER, HOST, secret=secret)

    if range_backend == "docker":
        # Container-hosted range (internal network, no internet). Not exercised
        # by the offline suite; requires Docker + the 'docker' extra. The engine
        # treats it identically — same Range surface.
        from .range.docker_runner import bring_up_docker
        rng = bring_up_docker(scenario, randomized, token=challenge.token)
    else:
        # Tag every range request with the referee's current tick so traffic
        # lines up with actions on the timeline.
        tick_holder = {"ctx": None}
        rng = bring_up(scenario, randomized, token=challenge.token, sink=sink,
                       tick_provider=lambda: (tick_holder["ctx"].tick
                                              if tick_holder["ctx"] else -1))
    try:
        now = datetime.now(timezone.utc)
        scope = _make_scope(now)

        # The verifier fetches the well-known token from the range's real base
        # URL (ephemeral port on 127.0.0.1), so ownership proof is genuine.
        gate = AuthorizationGate(
            secret=secret,
            verifier=OwnershipVerifier(http=_BoundHttp(rng.base_url)),
            audit=audit,
        )

        # AUTHORIZE — genuine ownership proof before any red action.
        gate.authorize(USER, HOST, VerificationMethod.WELL_KNOWN_FILE, scope)

        red_client = GatedHttpClient(
            gate=gate, user_id=USER, host=HOST, base_url=rng.base_url,
            scope=scope, actor="red",
        )
        ctx = EngagementContext(
            gate=gate, user_id=USER, host=HOST, scope=scope, scenario=scenario,
            randomized=randomized, range=rng, events=events, red_client=red_client,
            seed=seed,
        )
        if range_backend != "docker":
            tick_holder["ctx"] = ctx

        red = red_agent or _build_red(red_name)
        blue = blue_agent or _build_blue(blue_name)

        referee = Referee(ctx, red, blue, killswitch=killswitch,
                          traffic=BenignTraffic(), tick_delay_s=tick_delay_s)
        result = referee.run()
        result.audit_path = str(audit.path)
    finally:
        rng.shutdown()

    # Persist a machine-readable summary + the human report.
    all_events = [e.model_dump() for e in events]
    timeline = [{"tick": e["tick"], **{k: e["data"].get(k) for k in
                 ("red", "blue", "resilience", "findings", "flag_captured")}}
                for e in all_events if e["kind"] == "score_tick"]
    red_spec = _spec("red", red_name, red)
    blue_spec = _spec("blue", blue_name, blue)
    (out_dir / "result.json").write_text(
        json.dumps(
            {
                "scenario": result.scenario_id,
                "seed": result.seed,
                "ended": result.ended_reason,
                "ticks_run": result.ticks_run,
                "max_ticks": scenario.max_ticks,
                "scoreboard": result.scoreboard.model_dump(),
                "findings": [enrich(f.model_dump(mode="json"))
                             for f in result.findings.findings],
                "duration_s": result.duration_s,
                "meta": {
                    "scenario_name": scenario.name,
                    "red": red_spec[0], "red_label": red_spec[1],
                    "blue": blue_spec[0], "blue_label": blue_spec[1],
                    "started_at": started_at.isoformat(),
                    "finished_at": datetime.now(timezone.utc).isoformat(),
                    "tick_delay_s": tick_delay_s,
                    "host": HOST,
                    "operator": USER,
                    "scope_fingerprint": scope.fingerprint(),
                    "environment": scope.environment.value,
                    "rate_cap": f"{scope.rate_cap.max_requests}/{scope.rate_cap.per_seconds}s",
                },
                "kpis": compute_kpis(all_events, result.ticks_run),
                "timeline": timeline,
            },
            indent=2,
        ),
        encoding="utf-8",
    )
    if generate_report:
        report_html, report_md, report_pdf = write_report(result, audit, out_dir)
    else:
        report_html = report_md = report_pdf = None

    return EngagementArtifacts(
        result=result,
        out_dir=out_dir,
        events_path=events.path,
        audit_path=audit.path,
        report_html=report_html,
        report_md=report_md,
        report_pdf=report_pdf,
    )


def _spec(team: str, name: str, agent) -> tuple[str, str]:
    """(registry name, display label) for the agent that actually ran. An agent
    passed in directly is matched to its registry entry by class."""
    table = registry.RED if team == "red" else registry.BLUE
    for spec_name, spec in table.items():
        if isinstance(spec.factory, type) and isinstance(agent, spec.factory):
            return spec_name, spec.label
    if name in table:
        return name, table[name].label
    return name, getattr(agent, "name", name)


class _BoundHttp:
    """Fetch the well-known path from the range's real base URL regardless of the
    host string in the gate's canonical URL (the range runs on an ephemeral port
    on 127.0.0.1)."""

    def __init__(self, base_url: str) -> None:
        self.base_url = base_url
        self._inner = StdlibHttpClient()

    def get_text(self, url: str) -> str:
        from urllib.parse import urlparse

        path = urlparse(url).path
        return self._inner.get_text(f"{self.base_url}{path}")
