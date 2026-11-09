"""Resilience audit report generator.

Turns an :class:`EngagementResult` + the authorization audit log into a
manager-readable report: resilience score, findings mapped to the OWASP Top 10
with severity and mitigations, the engagement timeline, and the tamper-evident
audit trail (with a chain-integrity check). Always writes HTML and Markdown;
writes PDF too when the optional ``pdf`` extra (reportlab) is installed.
"""

from __future__ import annotations

import html
from pathlib import Path

from ..authz.audit import AuditLog
from ..detect.findings import OWASP_TOP_10, Severity
from ..telemetry.events import EventStore

_SEV_ORDER = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW,
              Severity.INFO]


def _timeline(events_path) -> list[dict]:
    rows = []
    for e in EventStore(events_path):
        if e.kind in {"action", "finding", "score"}:
            rows.append({
                "tick": e.tick, "team": e.team, "kind": e.kind,
                "summary": e.summary,
                "technique": e.data.get("attack_technique"),
                "tactic": e.data.get("tactic"),
            })
    return rows


def _audit_rows(audit: AuditLog) -> list[dict]:
    rows = []
    for entry in audit:
        rows.append({
            "seq": entry.seq, "actor": entry.actor, "action": entry.action,
            "host": entry.host, "outcome": entry.outcome,
            "detail": entry.detail,
        })
    return rows


def _chain_status(audit: AuditLog) -> str:
    try:
        audit.verify_chain()
        return "intact"
    except Exception as e:  # pragma: no cover
        return f"BROKEN: {e}"


def build_markdown(result, audit: AuditLog) -> str:
    sb = result.scoreboard
    f = result.findings
    lines: list[str] = []
    lines.append(f"# Resilience Audit — {result.scenario_id}")
    lines.append("")
    lines.append(f"**Resilience score: {sb.resilience}/100**")
    lines.append("")
    lines.append(f"- Scenario: `{result.scenario_id}`  |  Seed: `{result.seed}`")
    lines.append(f"- Outcome: **{result.ended_reason}** after {result.ticks_run} tick(s)")
    lines.append(f"- Red score: {sb.red.total}  |  Blue score: {sb.blue.total}")
    lines.append(f"- Flag captured: {'yes' if sb.red.flag_captured else 'no'}")
    lines.append(f"- Service uptime (SLA): {sb.blue.sla_uptime:.0%}  |  "
                 f"Legit availability: {sb.blue.legit_availability:.0%}")
    lines.append(f"- Attacker detected: "
                 f"{'yes' if sb.blue.true_positive_detections else 'no'}"
                 + (f" (tick {sb.blue.ticks_to_first_detection})"
                    if sb.blue.ticks_to_first_detection is not None else ""))
    lines.append("")

    lines.append("## Findings by OWASP Top 10 (2021)")
    lines.append("")
    cov = f.owasp_coverage()
    if not f.findings:
        lines.append("_No findings recorded._")
    for code in sorted(cov):
        lines.append(f"### {code} — {OWASP_TOP_10.get(code, 'Uncategorized')}")
        for finding in cov[code]:
            lines.append(f"- **[{finding.severity.value.upper()}] {finding.title}**")
            lines.append(f"  - {finding.description}")
            lines.append(f"  - Evidence: {finding.evidence}")
            lines.append(f"  - Mitigation: {finding.mitigation}")
        lines.append("")

    counts = f.by_severity()
    lines.append("## Severity summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("| --- | --- |")
    for s in _SEV_ORDER:
        lines.append(f"| {s.value} | {counts[s.value]} |")
    lines.append("")

    lines.append("## Engagement timeline")
    lines.append("")
    lines.append("| Tick | Team | Event | ATT&CK |")
    lines.append("| --- | --- | --- | --- |")
    for row in _timeline(result.events_path):
        tech = f"{row['technique']} ({row['tactic']})" if row["technique"] else ""
        lines.append(f"| {row['tick']} | {row['team']} | {row['summary']} | {tech} |")
    lines.append("")

    lines.append("## Tamper-evident audit trail")
    lines.append("")
    lines.append(f"Hash-chain integrity: **{_chain_status(audit)}**")
    lines.append("")
    lines.append("| Seq | Actor | Action | Host | Outcome |")
    lines.append("| --- | --- | --- | --- | --- |")
    for r in _audit_rows(audit):
        lines.append(f"| {r['seq']} | {r['actor']} | {r['action']} | {r['host']} | "
                     f"{r['outcome']} |")
    lines.append("")
    return "\n".join(lines)


def build_html(result, audit: AuditLog) -> str:
    sb = result.scoreboard
    f = result.findings
    e = html.escape

    def badge(sev: str) -> str:
        return f'<span class="sev sev-{sev}">{sev.upper()}</span>'

    rows_findings = []
    for code in sorted(f.owasp_coverage()):
        for finding in f.owasp_coverage()[code]:
            rows_findings.append(
                f"<tr><td>{e(code)} {e(OWASP_TOP_10.get(code, ''))}</td>"
                f"<td>{badge(finding.severity.value)}</td>"
                f"<td><strong>{e(finding.title)}</strong><br><small>{e(finding.evidence)}"
                f"</small></td><td>{e(finding.mitigation)}</td></tr>"
            )
    findings_html = "\n".join(rows_findings) or \
        '<tr><td colspan="4">No findings recorded.</td></tr>'

    timeline_html = "\n".join(
        f"<tr><td>{r['tick']}</td><td class='team-{r['team']}'>{e(r['team'])}</td>"
        f"<td>{e(r['summary'])}</td>"
        f"<td>{e((r['technique'] or '') + ((' / ' + r['tactic']) if r['tactic'] else ''))}</td></tr>"
        for r in _timeline(result.events_path)
    )

    audit_html = "\n".join(
        f"<tr><td>{r['seq']}</td><td>{e(r['actor'])}</td><td>{e(r['action'])}</td>"
        f"<td>{e(r['host'])}</td><td class='out-{r['outcome']}'>{e(r['outcome'])}</td></tr>"
        for r in _audit_rows(audit)
    )

    res = sb.resilience
    res_color = "#16a34a" if res >= 70 else "#d97706" if res >= 40 else "#dc2626"

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Resilience Audit — {e(result.scenario_id)}</title>
<style>
  :root {{ color-scheme: light dark; --fg:#111; --muted:#666; --bg:#fff;
           --card:#f6f7f9; --border:#e3e5e8; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --fg:#e8e8ea; --muted:#9aa0a6; --bg:#0f1115; --card:#181b20;
             --border:#2a2e35; }} }}
  body {{ font-family: -apple-system, Segoe UI, Roboto, sans-serif; margin:0;
          background:var(--bg); color:var(--fg); line-height:1.5; }}
  .wrap {{ max-width: 920px; margin: 0 auto; padding: 24px 16px 64px; }}
  h1 {{ margin: 0 0 4px; font-size: 1.6rem; }}
  .sub {{ color: var(--muted); margin-bottom: 20px; }}
  .score {{ display:flex; align-items:center; gap:20px; background:var(--card);
            border:1px solid var(--border); border-radius:14px; padding:20px;
            margin-bottom:24px; }}
  .dial {{ font-size:2.6rem; font-weight:700; color:{res_color}; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(150px,1fr));
           gap:10px; flex:1; }}
  .stat {{ font-size:.85rem; color:var(--muted); }}
  .stat b {{ display:block; font-size:1.1rem; color:var(--fg); }}
  table {{ width:100%; border-collapse:collapse; margin:10px 0 28px; font-size:.9rem; }}
  th,td {{ text-align:left; padding:8px 10px; border-bottom:1px solid var(--border);
           vertical-align:top; }}
  th {{ color:var(--muted); font-weight:600; font-size:.8rem; text-transform:uppercase;
        letter-spacing:.03em; }}
  .sev {{ font-size:.7rem; font-weight:700; padding:2px 7px; border-radius:20px;
          color:#fff; }}
  .sev-critical {{ background:#991b1b; }} .sev-high {{ background:#dc2626; }}
  .sev-medium {{ background:#d97706; }} .sev-low {{ background:#2563eb; }}
  .sev-info {{ background:#6b7280; }}
  .team-red {{ color:#dc2626; font-weight:600; }}
  .team-blue {{ color:#2563eb; font-weight:600; }}
  .out-deny {{ color:#dc2626; font-weight:600; }} .out-allow {{ color:#16a34a; }}
  h2 {{ font-size:1.15rem; margin-top:28px; border-top:1px solid var(--border);
        padding-top:18px; }}
  .chain {{ display:inline-block; padding:2px 10px; border-radius:6px;
            background:#16a34a22; color:#16a34a; font-weight:600; }}
</style></head>
<body><div class="wrap">
<h1>Resilience Audit — {e(result.scenario_id)}</h1>
<div class="sub">Seed {e(str(result.seed))} · outcome <strong>{e(result.ended_reason)}</strong>
 · {result.ticks_run} tick(s) · {result.duration_s}s</div>

<div class="score">
  <div><div class="dial">{res}</div><div class="stat">/ 100 resilience</div></div>
  <div class="grid">
    <div class="stat"><b>{sb.red.total}</b>red score</div>
    <div class="stat"><b>{sb.blue.total}</b>blue score</div>
    <div class="stat"><b>{'Yes' if sb.red.flag_captured else 'No'}</b>flag captured</div>
    <div class="stat"><b>{sb.blue.sla_uptime:.0%}</b>service uptime</div>
    <div class="stat"><b>{sb.blue.legit_availability:.0%}</b>legit availability</div>
    <div class="stat"><b>{sb.blue.true_positive_detections}</b>attacker detections</div>
  </div>
</div>

<h2>Findings — OWASP Top 10 (2021)</h2>
<table><thead><tr><th>Category</th><th>Severity</th><th>Finding</th><th>Mitigation</th></tr>
</thead><tbody>
{findings_html}
</tbody></table>

<h2>Engagement timeline</h2>
<table><thead><tr><th>Tick</th><th>Team</th><th>Event</th><th>MITRE ATT&amp;CK</th></tr>
</thead><tbody>
{timeline_html}
</tbody></table>

<h2>Tamper-evident audit trail</h2>
<p>Hash-chain integrity: <span class="chain">{e(_chain_status(audit))}</span></p>
<table><thead><tr><th>#</th><th>Actor</th><th>Action</th><th>Host</th><th>Outcome</th></tr>
</thead><tbody>
{audit_html}
</tbody></table>
</div></body></html>
"""


def build_pdf(result, audit: AuditLog, path: Path) -> bool:
    """Write a PDF if reportlab is available. Returns True on success."""
    try:
        from reportlab.lib.pagesizes import letter
        from reportlab.lib.units import inch
        from reportlab.pdfgen import canvas
    except Exception:
        return False

    sb = result.scoreboard
    c = canvas.Canvas(str(path), pagesize=letter)
    width, height = letter
    y = height - inch

    def line(text, size=11, dy=16, bold=False):
        nonlocal y
        if y < inch:
            c.showPage()
            y = height - inch
        c.setFont("Helvetica-Bold" if bold else "Helvetica", size)
        c.drawString(inch, y, text[:110])
        y -= dy

    line(f"Resilience Audit — {result.scenario_id}", size=18, dy=26, bold=True)
    line(f"Resilience score: {sb.resilience}/100", size=13, dy=22, bold=True)
    line(f"Seed {result.seed} · outcome {result.ended_reason} · {result.ticks_run} ticks")
    line(f"Red {sb.red.total} | Blue {sb.blue.total} | "
         f"flag {'captured' if sb.red.flag_captured else 'not captured'}")
    line(f"SLA uptime {sb.blue.sla_uptime:.0%} | legit availability "
         f"{sb.blue.legit_availability:.0%}")
    y -= 8
    line("Findings (OWASP Top 10)", size=13, dy=20, bold=True)
    if not result.findings.findings:
        line("No findings recorded.")
    for f in result.findings.findings:
        line(f"[{f.severity.value.upper()}] {f.owasp} {f.title}", bold=True)
        line(f"   Mitigation: {f.mitigation}", size=9, dy=14)
    y -= 8
    line(f"Audit hash-chain: {_chain_status(audit)}", size=11, bold=True)
    c.showPage()
    c.save()
    return True


def write_report(result, audit: AuditLog, out_dir: Path):
    """Write HTML + Markdown (+ PDF if available). Returns (html, md, pdf|None)."""
    out_dir = Path(out_dir)
    html_path = out_dir / "report.html"
    md_path = out_dir / "report.md"
    pdf_path = out_dir / "report.pdf"

    html_path.write_text(build_html(result, audit), encoding="utf-8")
    md_path.write_text(build_markdown(result, audit), encoding="utf-8")
    pdf_ok = build_pdf(result, audit, pdf_path)
    return html_path, md_path, (pdf_path if pdf_ok else None)
