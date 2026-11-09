"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ScanLine, ShieldCheck, Download, Target, Loader2, History } from "lucide-react";
import {
  CampaignBrief,
  CampaignJob,
  api,
  campaignReportUrl,
} from "@/lib/api";
import { Card, Empty, ErrorBanner, PageHead, Seg, Sev, Stat, StatusPill } from "@/components/ui";

const SANDBOX = new Set(["127.0.0.1", "localhost", "::1", "sandbox"]);
const isSandbox = (t: string) => SANDBOX.has(t.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);

const GRADE_TONE: Record<string, "good" | "warning" | "critical"> = {
  A: "good", B: "good", C: "warning", D: "critical", F: "critical",
};

export default function AssessmentPage() {
  const [target, setTarget] = useState("127.0.0.1");
  const [depth, setDepth] = useState("standard");
  const [label, setLabel] = useState("");
  const [own, setOwn] = useState(false);
  const [job, setJob] = useState<CampaignJob | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<CampaignBrief[]>([]);
  const poll = useRef<ReturnType<typeof setTimeout> | null>(null);

  const external = !isSandbox(target);

  const loadHistory = useCallback(() => {
    api.campaigns().then(setHistory).catch(() => {});
  }, []);
  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => () => { if (poll.current) clearTimeout(poll.current); }, []);

  const watch = useCallback((id: string) => {
    const tick = async () => {
      try {
        const j = await api.campaign(id);
        setJob(j);
        if (j.status === "running") poll.current = setTimeout(tick, 700);
        else { setBusy(false); loadHistory(); }
      } catch (e: any) {
        setError(e.message || "lost the campaign"); setBusy(false);
      }
    };
    tick();
  }, [loadHistory]);

  const run = async () => {
    setError(""); setBusy(true); setJob(null);
    if (external && !own) {
      setError("That target isn't the sandbox. Verify you own it first, then tick the ownership box.");
      setBusy(false);
      return;
    }
    try {
      const { id } = await api.startCampaign({
        target: target.trim(), depth, scenarios: [], label: label.trim(),
        i_own_this: own,
      });
      watch(id);
    } catch (e: any) {
      setError(e.message || "could not start"); setBusy(false);
    }
  };

  const open = (id: string) => { setBusy(true); setError(""); watch(id); };

  const r = job?.result || null;
  const pct = job && job.total ? Math.round((job.done / job.total) * 100) : 0;

  return (
    <div className="stack">
      <PageHead
        title="Assessment"
        sub="Point it at a target and get one verdict: a posture grade and a prioritized list of weaknesses, each with its fix — distilled from a whole matrix of simulated red-vs-blue engagements."
      />

      {error && <ErrorBanner error={error} onRetry={() => setError("")} />}

      <Card title={<><Target size={15} /> Launch an assessment</>}
            sub="The sandbox target runs with no setup. An external host must have its ownership proven first.">
        <div className="stack" style={{ gap: 14 }}>
          <div className="field">
            <label>Target</label>
            <input className="input" value={target} onChange={(e) => setTarget(e.target.value)}
                   placeholder="127.0.0.1  or  app.your-company.com" />
          </div>

          {external && (
            <div className="banner" style={{ alignItems: "flex-start" }}>
              <ShieldCheck size={16} style={{ color: "var(--accent)", flex: "none", marginTop: 2 }} />
              <div style={{ flex: 1 }}>
                <b>Prove ownership before assessing a live host.</b>
                <div className="muted" style={{ marginTop: 4 }}>
                  Publish a DNS&nbsp;TXT record or a <code>/.well-known/sentinel-arena.txt</code> file
                  for this host (the MCP <code>verify_target</code> tool and the authorization gate
                  issue and check the token). Only non-destructive, observation-only checks ever run
                  against an external target.
                </div>
                <label className="check" style={{ marginTop: 8, display: "flex", gap: 8, alignItems: "center" }}>
                  <input type="checkbox" checked={own} onChange={(e) => setOwn(e.target.checked)} />
                  I have proven ownership of this target.
                </label>
              </div>
            </div>
          )}

          <div className="row" style={{ gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div className="field" style={{ flex: "1 1 220px" }}>
              <label>Label (optional)</label>
              <input className="input" value={label} onChange={(e) => setLabel(e.target.value)}
                     placeholder="Q4 storefront review" />
            </div>
            <div className="field">
              <label>Depth</label>
              <Seg
                label="Depth"
                value={depth}
                onChange={(v) => setDepth(String(v))}
                options={[
                  { value: "quick", label: "Quick" },
                  { value: "standard", label: "Standard" },
                  { value: "deep", label: "Deep" },
                ]}
              />
            </div>
            <button className="btn primary" onClick={run} disabled={busy}>
              {busy ? <Loader2 size={15} className="spin" /> : <ScanLine size={15} />}
              {busy ? "Assessing…" : "Run assessment"}
            </button>
          </div>
          <div className="muted" style={{ fontSize: 13 }}>
            Deep runs into the hundreds of engagements across every attacker and defender; Quick is a fast look.
          </div>
        </div>
      </Card>

      {busy && job && job.status === "running" && (
        <Card title="Running">
          <div className="stack" style={{ gap: 8 }}>
            <div className="progress"><div className="bar" style={{ width: `${pct}%` }} /></div>
            <div className="muted">{job.done} / {job.total} engagements — {job.current || "starting…"}</div>
          </div>
        </Card>
      )}

      {r && (
        <>
          <div className="grid g4">
            <Stat label="Posture grade" value={r.posture_grade}
                  tone={GRADE_TONE[r.posture_grade]} foot={`${r.runs} engagements`} />
            <Stat label="Resilience (worst)" value={r.worst_resilience} unit="/100"
                  tone={r.worst_resilience >= 75 ? "good" : r.worst_resilience >= 50 ? "warning" : "critical"}
                  foot={`mean ${r.mean_resilience} · best ${r.best_resilience}`} />
            <Stat label="Attacker win rate" value={`${Math.round(r.attacker_win_rate * 100)}%`}
                  tone={r.attacker_win_rate === 0 ? "good" : r.attacker_win_rate < 0.5 ? "warning" : "critical"}
                  foot="of graded matchups" />
            <Stat label="Distinct findings" value={r.vulnerabilities.length}
                  foot={Object.entries(r.severity_counts).map(([s, n]) => `${n} ${s}`).join(" · ") || "none"} />
          </div>

          <Card
            title="Prioritized remediation plan"
            sub={`${r.label || r.target} · depth ${r.depth}`}
            actions={<a className="btn ghost sm" href={campaignReportUrl(r.id)} target="_blank" rel="noreferrer"><Download size={14} /> Report</a>}
          >
            {r.vulnerabilities.length === 0 ? (
              <Empty icon={<ShieldCheck size={22} />} title="No weaknesses surfaced">
                Nothing was detected across this matrix.
              </Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr>
                      <th>#</th><th>Priority</th><th>Severity</th><th>Finding</th>
                      <th>OWASP</th><th>Fix within</th><th>Seen</th><th>Fix</th>
                    </tr>
                  </thead>
                  <tbody>
                    {r.vulnerabilities.map((v, i) => (
                      <tr key={v.rule_id}>
                        <td className="muted">{i + 1}</td>
                        <td><span className={`pill ${v.priority === "P1" ? "critical" : v.priority === "P2" ? "warning" : "neutral"}`}>{v.priority}</span></td>
                        <td><Sev s={v.severity} /></td>
                        <td>
                          <div style={{ fontWeight: 600 }}>{v.title}</div>
                          <div className="muted" style={{ fontSize: 12 }}>{v.rule_id} · {v.cwe.join(", ") || "—"} · CVSS {v.cvss_band || "—"}</div>
                        </td>
                        <td className="muted">{v.owasp} {v.owasp_title}</td>
                        <td>{v.fix_sla_days}d</td>
                        <td className="muted">{v.occurrences}×</td>
                        <td style={{ maxWidth: 320 }}>{v.mitigation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </Card>

          <Card title="How defenses held up" sub="Each attacker against each defender, graded by mean resilience.">
            <div className="table-wrap">
              <table className="table">
                <thead>
                  <tr><th>Attacker</th><th>Defender</th><th>Runs</th><th>Attacker win</th><th>Mean resilience</th><th>Worst</th><th>Ticks to detect</th></tr>
                </thead>
                <tbody>
                  {r.matchups.map((m) => (
                    <tr key={`${m.red}-${m.blue}`}>
                      <td>{m.red_label || m.red}</td>
                      <td>{m.blue_label || m.blue}</td>
                      <td className="muted">{m.runs}</td>
                      <td>{Math.round(m.attacker_win_rate * 100)}%</td>
                      <td>{m.mean_resilience}</td>
                      <td className="muted">{m.worst_resilience}</td>
                      <td className="muted">{m.mean_ticks_to_detect ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}

      <Card title={<><History size={15} /> Recent assessments</>}>
        {history.length === 0 ? (
          <div className="muted">No assessments yet. Run one above.</div>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr><th>Target</th><th>Depth</th><th>Status</th><th>Grade</th><th>Worst</th><th>Findings</th><th></th></tr>
              </thead>
              <tbody>
                {history.map((h) => (
                  <tr key={h.id}>
                    <td>{h.label || h.target}</td>
                    <td className="muted">{h.depth}</td>
                    <td>
                      <StatusPill tone={h.status === "done" ? "good" : h.status === "error" ? "critical" : "neutral"} live={h.status === "running"}>
                        {h.status === "running" ? `${h.done}/${h.total}` : h.status}
                      </StatusPill>
                    </td>
                    <td>{h.grade ?? "—"}</td>
                    <td className="muted">{h.worst_resilience ?? "—"}</td>
                    <td className="muted">{h.findings ?? "—"}</td>
                    <td>{h.status === "done" && <button className="btn ghost sm" onClick={() => open(h.id)}>Open</button>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </div>
  );
}
