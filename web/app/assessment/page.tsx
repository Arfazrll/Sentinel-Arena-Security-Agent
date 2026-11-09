"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { ScanLine, ShieldCheck, Download, Target, Loader2, History, Check, Copy } from "lucide-react";
import {
  CampaignBrief,
  CampaignJob,
  CampaignResult,
  VerifyChallenge,
  api,
  campaignReportUrl,
} from "@/lib/api";
import { Card, Empty, ErrorBanner, PageHead, Seg, Sev, Stat, StatusPill } from "@/components/ui";

const SANDBOX = new Set(["127.0.0.1", "localhost", "::1", "sandbox"]);
const isSandbox = (t: string) =>
  SANDBOX.has(t.trim().toLowerCase().replace(/^https?:\/\//, "").split("/")[0].split(":")[0]);

const GRADE_TONE: Record<string, "good" | "warning" | "critical"> = {
  A: "good", B: "good", C: "warning", D: "critical", F: "critical",
};

type Method = "dns_txt" | "well_known_file" | "meta_tag";

function Copyable({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button className="btn ghost sm icon" title="Copy"
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}>
      {done ? <Check size={13} /> : <Copy size={13} />}
    </button>
  );
}

export default function AssessmentPage() {
  const [target, setTarget] = useState("127.0.0.1");
  const [depth, setDepth] = useState("standard");
  const [label, setLabel] = useState("");
  const [job, setJob] = useState<CampaignJob | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [history, setHistory] = useState<CampaignBrief[]>([]);
  const poll = useRef<ReturnType<typeof setTimeout> | null>(null);

  // external ownership wizard
  const [challenge, setChallenge] = useState<VerifyChallenge | null>(null);
  const [method, setMethod] = useState<Method>("dns_txt");
  const [verified, setVerified] = useState(false);
  const [checking, setChecking] = useState(false);
  const [checkDetail, setCheckDetail] = useState("");

  const external = !isSandbox(target);

  const loadHistory = useCallback(() => {
    api.campaigns().then(setHistory).catch(() => {});
  }, []);
  useEffect(() => { loadHistory(); }, [loadHistory]);
  useEffect(() => () => { if (poll.current) clearTimeout(poll.current); }, []);

  // reset the wizard whenever the target changes
  useEffect(() => { setChallenge(null); setVerified(false); setCheckDetail(""); }, [target]);

  const watch = useCallback((id: string) => {
    const tick = async () => {
      try {
        const j = await api.campaign(id);
        setJob(j);
        if (j.status === "running") poll.current = setTimeout(tick, 700);
        else { setBusy(false); loadHistory(); }
      } catch (e: any) { setError(e.message || "lost the campaign"); setBusy(false); }
    };
    tick();
  }, [loadHistory]);

  const doVerify = async () => {
    setError(""); setVerified(false); setCheckDetail("");
    try { setChallenge(await api.verifyTarget(target.trim())); }
    catch (e: any) { setError(e.message || "could not issue a challenge"); }
  };

  const doCheck = async () => {
    setError(""); setChecking(true);
    try {
      const r = await api.checkTarget(target.trim(), method);
      setVerified(r.verified);
      setCheckDetail(r.verified ? "Ownership verified." : r.detail || "Not verified yet.");
    } catch (e: any) { setError(e.message || "check failed"); }
    finally { setChecking(false); }
  };

  const run = async () => {
    setError(""); setJob(null);
    if (external) {
      if (!verified) { setError("Verify ownership of this host first (steps 1–2)."); return; }
      setBusy(true);
      try {
        const result: CampaignResult = await api.assessExternal(target.trim(), method, label.trim());
        setJob({ id: result.id, status: "done", target: result.target, depth: result.depth,
                 label: result.label, done: result.runs, total: result.runs, current: "",
                 result, started_at: result.created_at });
        loadHistory();
      } catch (e: any) { setError(e.message || "scan failed"); }
      finally { setBusy(false); }
      return;
    }
    setBusy(true);
    try {
      const { id } = await api.startCampaign({ target: target.trim(), depth, scenarios: [], label: label.trim(), i_own_this: false });
      watch(id);
    } catch (e: any) { setError(e.message || "could not start"); setBusy(false); }
  };

  const open = (id: string) => { setBusy(true); setError(""); watch(id); };

  const r = job?.result || null;
  const pct = job && job.total ? Math.round((job.done / job.total) * 100) : 0;
  const artifact = challenge
    ? method === "dns_txt"
      ? `${challenge.methods.dns_txt.name}  TXT  "${challenge.methods.dns_txt.value}"`
      : method === "well_known_file"
        ? `${challenge.methods.well_known_file.url}\n→ body: ${challenge.methods.well_known_file.body}`
        : challenge.methods.meta_tag
    : "";

  return (
    <div className="stack">
      <PageHead
        title="Assessment"
        sub="Point it at a target and get one verdict: a posture grade and a prioritized list of weaknesses, each with its fix. The sandbox runs a full red-vs-blue matrix; a host you own gets a non-destructive, observation-only posture scan."
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
            <div className="banner" style={{ alignItems: "flex-start", flexDirection: "column", gap: 10 }}>
              <div className="row" style={{ gap: 8 }}>
                <ShieldCheck size={16} style={{ color: "var(--accent)" }} />
                <b>Prove ownership before scanning a live host</b>
                {verified && <StatusPill tone="good">verified</StatusPill>}
              </div>

              <div className="row" style={{ gap: 10, flexWrap: "wrap" }}>
                <button className="btn sm" onClick={doVerify} disabled={busy}>1. Get verification token</button>
                <Seg label="Method" value={method} onChange={(v) => setMethod(v as Method)}
                     options={[{ value: "dns_txt", label: "DNS TXT" },
                               { value: "well_known_file", label: "File" },
                               { value: "meta_tag", label: "Meta tag" }]} />
              </div>

              {challenge && (
                <>
                  <div className="muted" style={{ fontSize: 13 }}>
                    {method === "dns_txt" && <>Add this <b>TXT record</b> at your DNS provider for <code>{challenge.host}</code>{!challenge.dns_available && <> — <b>note:</b> DNS checking isn't enabled on this server; use the File or Meta-tag method instead</>}, then check:</>}
                    {method === "well_known_file" && <>Host a file at this <b>URL</b> on <code>{challenge.host}</code> containing the token as its body, then check:</>}
                    {method === "meta_tag" && <>Add this <b>&lt;meta&gt; tag</b> into the <code>&lt;head&gt;</code> of your home page on <code>{challenge.host}</code>, then check:</>}
                  </div>
                  <div className="row" style={{ gap: 6, alignItems: "flex-start" }}>
                    <pre style={{ margin: 0, flex: 1, whiteSpace: "pre-wrap", wordBreak: "break-all",
                                  background: "var(--surface-2, rgba(127,127,127,.08))", padding: "8px 10px",
                                  borderRadius: 8, fontSize: 12.5 }}>{artifact}</pre>
                    <Copyable text={artifact} />
                  </div>
                  <div className="row" style={{ gap: 10 }}>
                    <button className="btn sm" onClick={doCheck} disabled={checking}>
                      {checking ? <Loader2 size={14} className="spin" /> : <Check size={14} />} 2. Check now
                    </button>
                    {checkDetail && <span className="muted" style={{ fontSize: 13 }}>{checkDetail}</span>}
                  </div>
                </>
              )}
            </div>
          )}

          <div className="row" style={{ gap: 16, flexWrap: "wrap", alignItems: "flex-end" }}>
            <div className="field" style={{ flex: "1 1 220px" }}>
              <label>Label (optional)</label>
              <input className="input" value={label} onChange={(e) => setLabel(e.target.value)}
                     placeholder="Q4 storefront review" />
            </div>
            {!external && (
              <div className="field">
                <label>Depth</label>
                <Seg label="Depth" value={depth} onChange={(v) => setDepth(String(v))}
                     options={[{ value: "quick", label: "Quick" },
                               { value: "standard", label: "Standard" },
                               { value: "deep", label: "Deep" }]} />
              </div>
            )}
            <button className="btn primary" onClick={run} disabled={busy || (external && !verified)}>
              {busy ? <Loader2 size={15} className="spin" /> : <ScanLine size={15} />}
              {busy ? "Assessing…" : external ? "Run posture scan" : "Run assessment"}
            </button>
          </div>
          <div className="muted" style={{ fontSize: 13 }}>
            {external
              ? "External scan is observation-only: one request to the site root, headers analyzed. No payloads, no path fuzzing."
              : "Deep runs into the hundreds of engagements across every attacker and defender; Quick is a fast look."}
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
                  tone={GRADE_TONE[r.posture_grade]}
                  foot={r.depth === "external" ? "external scan" : `${r.runs} engagements`} />
            <Stat label={r.depth === "external" ? "Posture score" : "Resilience (worst)"}
                  value={r.worst_resilience} unit="/100"
                  tone={r.worst_resilience >= 75 ? "good" : r.worst_resilience >= 50 ? "warning" : "critical"}
                  foot={r.depth === "external" ? "from header findings" : `mean ${r.mean_resilience} · best ${r.best_resilience}`} />
            <Stat label="Attacker win rate" value={`${Math.round(r.attacker_win_rate * 100)}%`}
                  tone={r.attacker_win_rate === 0 ? "good" : r.attacker_win_rate < 0.5 ? "warning" : "critical"}
                  foot={r.depth === "external" ? "n/a for passive scan" : "of graded matchups"} />
            <Stat label="Distinct findings" value={r.vulnerabilities.length}
                  foot={Object.entries(r.severity_counts).map(([s, n]) => `${n} ${s}`).join(" · ") || "none"} />
          </div>

          <Card
            title="Prioritized remediation plan"
            sub={`${r.label || r.target} · ${r.depth === "external" ? "external posture scan" : "depth " + r.depth}`}
            actions={<a className="btn ghost sm" href={campaignReportUrl(r.id)} target="_blank" rel="noreferrer"><Download size={14} /> Report</a>}
          >
            {r.vulnerabilities.length === 0 ? (
              <Empty icon={<ShieldCheck size={22} />} title="No weaknesses surfaced">Nothing was detected.</Empty>
            ) : (
              <div className="table-wrap">
                <table className="table">
                  <thead>
                    <tr><th>#</th><th>Priority</th><th>Severity</th><th>Finding</th><th>OWASP</th><th>Fix within</th><th>Seen</th><th>Fix</th></tr>
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

          {r.matchups.length > 0 && (
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
          )}
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
