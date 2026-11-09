"""Campaign engine - assess one target across a whole matrix of scenarios.

A single engagement answers "did *this* attacker beat *this* defender on *this*
scenario and seed?". A product needs the next question up: **"how resilient is
this target, overall, and exactly what should we fix first?"** That is a
campaign: a planned fan-out over

    scenarios  x  attacker agents  x  defender agents  x  seeds

run through the very same :func:`run_engagement` (so every run still passes the
authorization gate and stays inside the sandbox), then *aggregated* into one
verdict:

* an overall resilience posture (worst / mean / best) and a letter grade,
* the attacker win rate across the whole matrix,
* a **deduplicated, risk-ranked list of vulnerabilities**, each already carrying
  its fix, CVSS band, remediation priority + SLA and indicative control mapping
  (via :mod:`sentinel_arena.report.compliance`),
* per-matchup breakdowns and OWASP coverage.

Depth presets (``quick`` / ``standard`` / ``deep``) expand to progressively
larger matrices; ``deep`` runs into the hundreds of simulated engagements. The
"paste a target and get a prioritized remediation plan" experience is this
module plus a one-line CLI / API / MCP call on top of it.

SAFETY. A campaign changes *nothing* about where actions land. Every run is a
sandbox engagement on 127.0.0.1 behind a genuine ownership proof. An *external*
target is refused here unless ownership has been proven out of band
(``ownership_proven=True``), and even then this module only ever schedules the
non-destructive, observation-only engagement path - it never invents a new
attack. See ``docs/SAFETY.md``.
"""

from __future__ import annotations

import json
import tempfile
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Callable

from pydantic import BaseModel, Field

from .agents import registry
from .engagement import HOST, run_engagement
from .report.compliance import SLA_DAYS, enrich
from .scenarios.loader import list_scenarios

# --- depth presets ---------------------------------------------------------
# Seeds are fixed so a campaign is reproducible. Larger pools => more runs.
_SEEDS_QUICK = [42]
_SEEDS_STANDARD = [42, 7, 101]
_SEEDS_DEEP = [42, 7, 101, 2, 5, 13, 21, 99, 1, 8, 17, 23, 55, 71, 88, 97]

DEPTHS = ("quick", "standard", "deep")


def _bench(team: str) -> list[str]:
    return registry.benchmark_names(team)


@dataclass
class CampaignPlan:
    """What to run. Expands to a concrete list of (scenario, red, blue, seed)."""

    target: str = HOST                      # label; execution stays sandboxed
    depth: str = "standard"
    scenarios: list[str] = field(default_factory=list)
    reds: list[str] = field(default_factory=list)
    blues: list[str] = field(default_factory=list)
    seeds: list[int] = field(default_factory=list)
    ownership_proven: bool = False          # must be True for a non-sandbox target
    label: str = ""

    def resolve(self) -> "CampaignPlan":
        """Fill blanks from the depth preset. Returns a fully-specified plan."""
        if self.depth not in DEPTHS:
            raise ValueError(f"depth must be one of {DEPTHS}, got {self.depth!r}")
        scenarios = self.scenarios or list_scenarios()
        if self.depth == "quick":
            reds = self.reds or _bench("red")
            blues = self.blues or ["scripted"]
            seeds = self.seeds or _SEEDS_QUICK
        elif self.depth == "standard":
            reds = self.reds or _bench("red")
            blues = self.blues or _bench("blue")
            seeds = self.seeds or _SEEDS_STANDARD
        else:  # deep
            reds = self.reds or _bench("red")
            blues = self.blues or _bench("blue")
            seeds = self.seeds or _SEEDS_DEEP
        return CampaignPlan(
            target=self.target, depth=self.depth, scenarios=scenarios,
            reds=reds, blues=blues, seeds=seeds,
            ownership_proven=self.ownership_proven, label=self.label,
        )

    def matrix(self) -> list[tuple[str, str, str, int]]:
        p = self.resolve()
        return [(sc, r, b, s)
                for sc in p.scenarios for r in p.reds
                for b in p.blues for s in p.seeds]

    def total_runs(self) -> int:
        return len(self.matrix())


# --- result models ---------------------------------------------------------
class Vulnerability(BaseModel):
    """One deduplicated weakness across the whole campaign."""

    rule_id: str
    title: str
    owasp: str
    owasp_title: str
    severity: str
    cwe: list[str] = []
    cvss_band: str = ""
    risk_score: float = 0.0
    priority: str = "P4"
    fix_sla_days: int = SLA_DAYS["P4"]
    effort: str = "M"
    mitigation: str
    controls: dict[str, list[str]] = {}
    occurrences: int = 0            # how many runs surfaced it
    example_evidence: str = ""
    example_url: str = ""


class Matchup(BaseModel):
    red: str
    blue: str
    red_label: str = ""
    blue_label: str = ""
    runs: int = 0
    attacker_win_rate: float = 0.0
    mean_resilience: float = 0.0
    worst_resilience: int = 0
    mean_ticks_to_detect: float | None = None


class CampaignResult(BaseModel):
    id: str
    target: str
    label: str = ""
    depth: str
    created_at: str
    runs: int
    scenarios: list[str]
    reds: list[str]
    blues: list[str]
    seeds: list[int]

    posture_grade: str                 # A..F from worst-case resilience
    mean_resilience: float
    worst_resilience: int
    best_resilience: int
    attacker_win_rate: float           # fraction of runs the flag was captured

    vulnerabilities: list[Vulnerability]
    severity_counts: dict[str, int]
    owasp_coverage: dict[str, int]
    matchups: list[Matchup]

    def headline(self) -> str:
        return (f"Posture {self.posture_grade}  |  resilience "
                f"worst {self.worst_resilience} / mean {self.mean_resilience:.0f} / 100"
                f"  |  attacker win {self.attacker_win_rate*100:.0f}%"
                f"  |  {len(self.vulnerabilities)} distinct findings"
                f"  across {self.runs} runs")


# --- grading ---------------------------------------------------------------
def _grade(worst_resilience: int) -> str:
    # Graded on the *worst* run: a target is only as strong as its weakest day.
    if worst_resilience >= 90:
        return "A"
    if worst_resilience >= 75:
        return "B"
    if worst_resilience >= 60:
        return "C"
    if worst_resilience >= 40:
        return "D"
    return "F"


# --- the engine ------------------------------------------------------------
def run_campaign(
    plan: CampaignPlan,
    *,
    on_progress: Callable[[int, int, str], None] | None = None,
    max_workers: int = 1,
    campaign_id: str | None = None,
) -> CampaignResult:
    """Execute every (scenario, red, blue, seed) in the plan and aggregate.

    ``on_progress(done, total, label)`` fires after each run (drives the API's
    live progress + the CLI bar). ``max_workers > 1`` runs engagements in a
    thread pool; each stands up its own ephemeral sandbox so they are isolated.
    """
    plan = plan.resolve()

    # SAFETY GATE. A non-sandbox target must have had ownership proven already.
    if not _is_sandbox(plan.target) and not plan.ownership_proven:
        raise PermissionError(
            f"refusing to run a campaign against {plan.target!r}: ownership not "
            "proven. Verify the target first (verify_target / the gate's "
            "issue_challenge -> authorize flow); only then is a non-destructive, "
            "observation-only assessment permitted."
        )

    cid = campaign_id or f"camp-{uuid.uuid4().hex[:10]}"

    # Two axes, one run set:
    #  * the resilience MATRIX (red x blue x seed) grades how defenses respond;
    #  * a POSTURE pass (full-kill-chain attacker vs a passive target) enumerates
    #    the weaknesses that actually exist, so the vulnerability list is complete
    #    even when a strong defender would have blocked enumeration mid-run.
    plan_matrix = plan.matrix()
    plan_set = set(plan_matrix)
    posture = [(sc, "scripted", "noop", seed)
               for sc in plan.scenarios for seed in plan.seeds]
    run_tuples = list(plan_matrix) + [t for t in posture if t not in plan_set]
    total = len(run_tuples)

    rows: list[dict] = []
    done = 0

    with tempfile.TemporaryDirectory(prefix="arena-campaign-") as tmp:
        def _one(idx_item):
            idx, (sc, red, blue, seed) = idx_item
            art = run_engagement(
                sc, seed=seed,
                red_agent=registry.get("red", red).build(),
                blue_agent=registry.get("blue", blue).build(),
                out_dir=f"{tmp}/{idx}-{sc}-{red}-{blue}-{seed}",
                generate_report=False,
            )
            r = art.result
            return {
                "scenario": sc, "red": red, "blue": blue, "seed": seed,
                "in_matrix": (sc, red, blue, seed) in plan_set,
                "resilience": r.scoreboard.resilience,
                "flag_captured": r.scoreboard.red.flag_captured,
                "ticks_to_detect": r.scoreboard.blue.ticks_to_first_detection,
                "findings": [f.model_dump(mode="json") for f in r.findings.findings],
            }

        items = list(enumerate(run_tuples))
        if max_workers and max_workers > 1:
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                for row in pool.map(_one, items):
                    rows.append(row)
                    done += 1
                    if on_progress:
                        on_progress(done, total,
                                    f"{row['scenario']} {row['red']} vs {row['blue']} #{row['seed']}")
        else:
            for item in items:
                row = _one(item)
                rows.append(row)
                done += 1
                if on_progress:
                    on_progress(done, total,
                                f"{row['scenario']} {row['red']} vs {row['blue']} #{row['seed']}")

    return _aggregate(cid, plan, rows)


def _aggregate(cid: str, plan: CampaignPlan, rows: list[dict]) -> CampaignResult:
    # Resilience/win-rate are graded on the planned matrix only; the injected
    # posture runs enumerate vulnerabilities but must not skew the grade.
    graded = [r for r in rows if r["in_matrix"]]
    resiliences = [r["resilience"] for r in graded]
    worst = min(resiliences) if resiliences else 0
    caps = sum(1 for r in graded if r["flag_captured"])

    vulns = _dedup_vulnerabilities(rows)   # from ALL runs (posture + matrix)
    severity_counts: dict[str, int] = {}
    owasp_counts: dict[str, int] = {}
    for v in vulns:
        severity_counts[v.severity] = severity_counts.get(v.severity, 0) + 1
        owasp_counts[v.owasp] = owasp_counts.get(v.owasp, 0) + 1

    return CampaignResult(
        id=cid, target=plan.target, label=plan.label, depth=plan.depth,
        created_at=datetime.now(timezone.utc).isoformat(),
        runs=len(rows),
        scenarios=plan.scenarios, reds=plan.reds, blues=plan.blues, seeds=plan.seeds,
        posture_grade=_grade(worst),
        mean_resilience=round(mean(resiliences), 1) if resiliences else 0.0,
        worst_resilience=worst,
        best_resilience=max(resiliences) if resiliences else 0,
        attacker_win_rate=round(caps / len(graded), 3) if graded else 0.0,
        vulnerabilities=vulns,
        severity_counts=severity_counts,
        owasp_coverage=owasp_counts,
        matchups=_matchups(graded),
    )


def _dedup_vulnerabilities(rows: list[dict]) -> list[Vulnerability]:
    """Collapse every finding across every run into one row per rule, keeping the
    worst severity seen and counting how often it recurred. Ranked by risk."""
    by_rule: dict[str, Vulnerability] = {}
    for row in rows:
        for f in row["findings"]:
            e = enrich(f)
            rid = e["rule_id"]
            cur = by_rule.get(rid)
            if cur is None:
                by_rule[rid] = Vulnerability(
                    rule_id=rid, title=e["title"], owasp=e.get("owasp", ""),
                    owasp_title=e.get("owasp_title", "Uncategorized"),
                    severity=e["severity"], cwe=e.get("cwe", []),
                    cvss_band=e.get("cvss_band", ""), risk_score=e.get("risk_score", 0.0),
                    priority=e.get("priority", "P4"),
                    fix_sla_days=e.get("fix_sla_days", SLA_DAYS["P4"]),
                    effort=e.get("effort", "M"), mitigation=e["mitigation"],
                    controls=e.get("controls", {}), occurrences=1,
                    example_evidence=e.get("evidence", ""), example_url=e.get("url", ""),
                )
            else:
                cur.occurrences += 1
                if e.get("risk_score", 0.0) > cur.risk_score:
                    cur.severity = e["severity"]
                    cur.risk_score = e.get("risk_score", cur.risk_score)
                    cur.cvss_band = e.get("cvss_band", cur.cvss_band)
                    cur.priority = e.get("priority", cur.priority)
                    cur.fix_sla_days = e.get("fix_sla_days", cur.fix_sla_days)
    out = list(by_rule.values())
    out.sort(key=lambda v: (v.risk_score, v.occurrences), reverse=True)
    return out


def _matchups(rows: list[dict]) -> list[Matchup]:
    groups: dict[tuple[str, str], list[dict]] = {}
    for r in rows:
        groups.setdefault((r["red"], r["blue"]), []).append(r)
    out: list[Matchup] = []
    for (red, blue), rs in groups.items():
        ttds = [r["ticks_to_detect"] for r in rs if r["ticks_to_detect"] is not None]
        res = [r["resilience"] for r in rs]
        out.append(Matchup(
            red=red, blue=blue,
            red_label=registry.get("red", red).label,
            blue_label=registry.get("blue", blue).label,
            runs=len(rs),
            attacker_win_rate=round(sum(1 for r in rs if r["flag_captured"]) / len(rs), 3),
            mean_resilience=round(mean(res), 1),
            worst_resilience=min(res),
            mean_ticks_to_detect=round(mean(ttds), 2) if ttds else None,
        ))
    out.sort(key=lambda m: m.mean_resilience, reverse=True)
    return out


def _is_sandbox(target: str) -> bool:
    t = (target or "").strip().lower()
    # Strip a scheme/port if present.
    for pre in ("http://", "https://"):
        if t.startswith(pre):
            t = t[len(pre):]
    t = t.split("/")[0].split(":")[0]
    return t in {"127.0.0.1", "localhost", "::1", "sandbox", HOST}


# --- persistence + human summary ------------------------------------------
def save_campaign(result: CampaignResult, out_dir: str | Path) -> Path:
    out = Path(out_dir)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "campaign.json"
    path.write_text(json.dumps(result.model_dump(), indent=2), encoding="utf-8")
    (out / "campaign.md").write_text(to_markdown(result), encoding="utf-8")
    return path


def to_markdown(r: CampaignResult) -> str:
    lines = [
        f"# Security assessment - {r.label or r.target}",
        "",
        f"- **Posture grade:** {r.posture_grade}",
        f"- **Resilience:** worst {r.worst_resilience} / mean {r.mean_resilience:.0f} "
        f"/ best {r.best_resilience} (out of 100)",
        f"- **Attacker win rate:** {r.attacker_win_rate*100:.0f}% of {r.runs} simulated engagements",
        f"- **Depth:** {r.depth}  |  scenarios: {', '.join(r.scenarios)}  |  "
        f"attackers: {', '.join(r.reds)}  |  defenders: {', '.join(r.blues)}",
        "",
        "## Prioritized remediation plan",
        "",
        "| # | Priority | Severity | Finding | OWASP | Fix within | Seen in | Rule |",
        "| ---: | --- | --- | --- | --- | ---: | ---: | --- |",
    ]
    for i, v in enumerate(r.vulnerabilities, 1):
        lines.append(
            f"| {i} | {v.priority} | {v.severity} | {v.title} | {v.owasp} "
            f"{v.owasp_title} | {v.fix_sla_days}d | {v.occurrences}x | {v.rule_id} |"
        )
    if not r.vulnerabilities:
        lines.append("| - | - | - | No findings surfaced | - | - | - | - |")
    lines += ["", "## How to fix", ""]
    for i, v in enumerate(r.vulnerabilities, 1):
        lines += [f"### {i}. {v.title}  ({v.priority}, {v.severity})",
                  f"- **Mitigation:** {v.mitigation}",
                  f"- **CWE:** {', '.join(v.cwe) or 'n/a'}  |  **CVSS:** {v.cvss_band or 'n/a'}"
                  f"  |  **Effort:** {v.effort}",
                  ""]
    return "\n".join(lines)
