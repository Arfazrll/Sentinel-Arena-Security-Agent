"use client";

import { Suspense, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  Activity,
  BadgeCheck,
  Clock,
  Download,
  FileCode2,
  FileJson,
  FileSpreadsheet,
  FileText,
  GitCompare,
  Hash,
  Layers,
  ListChecks,
  PlayCircle,
  ShieldAlert,
  Timer,
  Users,
  ShieldX,
} from "lucide-react";
import { EngagementResult, api, exportUrl, reportUrl } from "@/lib/api";
import { derive } from "@/lib/derive";
import { useFetch, useReplay } from "@/lib/hooks";
import { dateTime, outcome, pct, shortHash, ticks } from "@/lib/format";
import ArenaView from "@/components/arena/ArenaView";
import { ReplayBar } from "@/components/arena/panels";
import { BarList, LineChart, SegBar, StackedColumns } from "@/components/charts";
import FindingsTable from "@/components/FindingsTable";
import ScoreExplainer from "@/components/ScoreExplainer";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, Stat, StatusPill, Tabs } from "@/components/ui";

type Tab = "replay" | "findings" | "metrics" | "audit" | "export";

function Detail({ id }: { id: string }) {
  const params = useSearchParams();
  const router = useRouter();
  const [tab, setTabState] = useState<Tab>((params.get("tab") as Tab) || "replay");
  const setTab = (t: Tab) => {
    setTabState(t);
    router.replace(`/engagements/${id}?tab=${t}`, { scroll: false });
  };

  const res = useFetch(() => api.result(id), [id]);
  const evs = useFetch(() => api.events(id), [id]);

  if (res.error && !res.data) {
    return (
      <>
        <PageHead title="Engagement" sub={<span className="mono">{id}</span>} />
        <ErrorBanner error={res.error === "not ready" ? "This engagement is still running or failed. Watch it in the live arena." : res.error} onRetry={res.reload} />
        <Link className="btn" href={`/arena?id=${id}`}>Open in live arena</Link>
      </>
    );
  }
  if (!res.data) return <Skeleton h={420} />;

  const r = res.data;
  const m = r.meta;
  const o = outcome(r.ended, r.scoreboard.red.flag_captured);

  return (
    <>
      <PageHead
        title={`${m?.red_label ?? "Red"} vs ${m?.blue_label ?? "Blue"}`}
        sub={
          <span className="row" style={{ gap: 10 }}>
            <StatusPill tone={o.tone}>{o.label}</StatusPill>
            <span>{m?.scenario_name ?? r.scenario}</span>
            <span className="muted">·</span>
            <span>seed <span className="mono">{r.seed}</span></span>
            <span className="muted">·</span>
            <span>{dateTime(m?.started_at)}</span>
            <span className="muted">·</span>
            <span className="mono muted">{id}</span>
          </span>
        }
        actions={
          <>
            <Link className="btn" href={`/compare?a=${id}`}>
              <GitCompare size={14} /> Compare
            </Link>
            <Link className="btn" href={`/arena?red=${m?.red ?? "scripted"}&blue=${m?.blue ?? "scripted"}&seed=${r.seed}&scenario=${r.scenario}`}>
              <PlayCircle size={14} /> Re-run
            </Link>
            <a className="btn primary" href={exportUrl(id, "sarif")}>
              <Download size={14} /> SARIF
            </a>
          </>
        }
      />

      <Tabs<Tab>
        value={tab}
        onChange={setTab}
        tabs={[
          { id: "replay", label: "Replay", icon: <PlayCircle size={14} /> },
          { id: "findings", label: "Findings", icon: <ShieldAlert size={14} />, count: r.findings.length },
          { id: "metrics", label: "Metrics", icon: <Activity size={14} /> },
          { id: "audit", label: "Audit trail", icon: <Hash size={14} /> },
          { id: "export", label: "Export", icon: <Download size={14} /> },
        ]}
      />

      {tab === "replay" && (evs.data ? <ReplayTab r={r} events={evs.data} /> : evs.error ? <ErrorBanner error={evs.error} /> : <Skeleton h={480} />)}
      {tab === "findings" && <FindingsTab r={r} />}
      {tab === "metrics" && <MetricsTab r={r} />}
      {tab === "audit" && <AuditTab id={id} />}
      {tab === "export" && <ExportTab id={id} />}
    </>
  );
}

function ReplayTab({ r, events }: { r: EngagementResult; events: any[] }) {
  const maxTicks = r.max_ticks ?? 12;
  const lastTick = Math.max(0, r.ticks_run - 1);
  const rp = useReplay(lastTick);
  const st = useMemo(() => derive(events, rp.tick, maxTicks), [events, rp.tick, maxTicks]);
  const full = useMemo(() => derive(events, Infinity, maxTicks), [events, maxTicks]);
  const m = r.meta;
  return (
    <>
      <ArenaView
        st={st}
        events={events}
        maxTicks={maxTicks}
        red={{ name: m?.red ?? "scripted", label: m?.red_label ?? "Red" }}
        blue={{ name: m?.blue ?? "scripted", label: m?.blue_label ?? "Blue" }}
        live={false}
        onPickTick={rp.seek}
      />
      <ReplayBar
        tick={rp.tick}
        lastTick={lastTick}
        playing={rp.playing}
        speed={rp.speed}
        moments={full.moments}
        onToggle={rp.toggle}
        onSeek={rp.seek}
        onStep={rp.step}
        onSpeed={rp.setSpeed}
      />
    </>
  );
}

function FindingsTab({ r }: { r: EngagementResult }) {
  if (!r.findings.length) {
    return (
      <Card>
        <Empty icon={<BadgeCheck size={20} />} title="No weaknesses were confirmed in this run">
          {r.scoreboard.blue.blocked_attacker_before_flag
            ? "The defender blocked the attacker before it could run its checks. That's a strong result, but it also means this run didn't test the app itself. Run against a passive defender to get a full weakness inventory."
            : "The attacker didn't reach the detection stage."}
        </Empty>
        <div className="row" style={{ justifyContent: "center", paddingBottom: 24 }}>
          <Link className="btn" href={`/arena?red=scripted&blue=noop&seed=${r.seed}`}>Run a full weakness scan (no defense)</Link>
        </div>
      </Card>
    );
  }
  const sev = (s: string) => r.findings.filter((f) => f.severity === s).length;
  const p1 = r.findings.filter((f) => f.priority === "P1").length;
  return (
    <div className="stack">
      <div className="grid g4">
        <Stat label="Findings" value={r.findings.length} foot={`${new Set(r.findings.map((f) => f.owasp)).size} OWASP categories`} />
        <Stat label="Fix within 7 days" value={p1} tone={p1 ? "critical" : "good"} foot="P1 (high and critical)" />
        <Stat label="Highest risk" value={Math.max(...r.findings.map((f) => f.risk_score)).toFixed(1)} unit="/ 10" foot="CVSS-aligned band score" />
        <Card title="Severity mix">
          <SegBar
            parts={[
              { label: "Critical", value: sev("critical"), color: "var(--critical)" },
              { label: "High", value: sev("high"), color: "var(--serious)" },
              { label: "Medium", value: sev("medium"), color: "var(--warning)" },
              { label: "Low", value: sev("low"), color: "var(--blue)" },
            ]}
          />
        </Card>
      </div>
      <Card title="Findings" sub="Click a row for evidence, fix guidance and compliance mapping" bodyClass="" >
        <div style={{ paddingTop: 12 }}>
          <FindingsTable
            findings={r.findings}
            extraCols={[{ head: "Found", cell: (f) => <span className="mono muted">T{f.tick}</span> }]}
          />
        </div>
      </Card>
    </div>
  );
}

function MetricsTab({ r }: { r: EngagementResult }) {
  const k = r.kpis;
  const b = r.scoreboard.blue;
  const timeline = (r.timeline || []).map((t) => ({ x: t.tick, resilience: t.resilience, red: t.red, blue: t.blue }));
  const traffic = (k?.traffic || []).map((t) => ({
    x: t.tick,
    legit: t.legit_ok || 0,
    red: t.red_ok || 0,
    blocked: (t.red_blocked || 0) + (t.legit_blocked || 0),
    system: (t.system_ok || 0) + (t.system_blocked || 0),
  }));
  return (
    <div className="stack">
      <div className="grid g5">
        <Stat icon={<Timer size={13} />} label="Time to detect" value={k?.time_to_detect ?? "—"} unit={k?.time_to_detect !== null && k?.time_to_detect !== undefined ? "ticks" : undefined} foot={k?.detect_tick !== null && k?.detect_tick !== undefined ? `flagged at T${k.detect_tick}` : "attacker never flagged"} tone={k?.time_to_detect === null ? "critical" : (k?.time_to_detect ?? 9) <= 1 ? "good" : "warning"} />
        <Stat icon={<ShieldX size={13} />} label="Time to contain" value={k?.time_to_contain ?? "—"} unit={k?.time_to_contain !== null && k?.time_to_contain !== undefined ? "ticks" : undefined} foot={k?.contain_tick !== null && k?.contain_tick !== undefined ? `blocked at T${k.contain_tick}` : "never contained"} />
        <Stat icon={<Clock size={13} />} label="Attacker dwell" value={k?.dwell_ticks ?? "—"} unit="ticks" foot="first move to containment" />
        <Stat icon={<Layers size={13} />} label="Attacker requests blocked" value={pct(k?.attacker_block_rate)} foot={`${k?.requests?.red_blocked ?? 0} of ${k?.requests?.red_total ?? 0}`} />
        <Stat icon={<Users size={13} />} label="Real users served" value={pct(b.legit_availability)} tone={b.false_blocks ? "critical" : "good"} foot={b.false_blocks ? `${b.false_blocks} wrongly blocked` : "no false blocks"} />
      </div>

      <div className="grid g2">
        <Card title="Why this score" sub="The resilience formula, term by term">
          <ScoreExplainer result={r} />
        </Card>
        <div className="stack">
          <Card
            title="Resilience by tick"
            table={
              <table className="table"><thead><tr><th>Tick</th><th className="num">Resilience</th><th className="num">Red</th><th className="num">Blue</th></tr></thead>
                <tbody>{timeline.map((t) => <tr key={t.x}><td>T{t.x}</td><td className="num">{t.resilience}</td><td className="num">{t.red}</td><td className="num">{t.blue}</td></tr>)}</tbody></table>
            }
          >
            <LineChart data={timeline} yMax={100} series={[{ key: "resilience", label: "Resilience", color: "var(--blue)" }]} area height={170} />
          </Card>
          <Card title="Traffic per tick">
            <StackedColumns
              data={traffic}
              series={[
                { key: "legit", label: "Users", color: "var(--legit)" },
                { key: "red", label: "Red allowed", color: "var(--red)" },
                { key: "blocked", label: "Blocked", color: "var(--blue)" },
                { key: "system", label: "Health", color: "var(--system)" },
              ]}
              height={160}
            />
          </Card>
        </div>
      </div>

      <div className="grid g2">
        <Card title="ATT&CK techniques used by red" sub="Uses per technique">
          {k?.techniques?.length ? (
            <BarList
              color="var(--red)"
              rows={k.techniques.map((t) => ({
                label: (
                  <span>
                    <span className="mono">{t.id}</span> {t.name}
                  </span>
                ),
                value: t.uses,
                title: `${t.tactic} · first at T${t.first_tick} · ${t.succeeded} succeeded`,
              }))}
            />
          ) : (
            <div className="muted">No techniques recorded.</div>
          )}
        </Card>
        <Card title="Agent activity">
          <dl className="kv">
            <dt>Red actions</dt><dd>{k?.red_actions ?? 0} · {pct(k?.red_success_rate)} succeeded</dd>
            <dt>Blue actions</dt><dd>{k?.blue_actions ?? 0} · {pct(k?.blue_success_rate)} succeeded</dd>
            <dt>Rejected by referee</dt><dd>{k?.rejected_actions ?? 0}</dd>
            <dt>Ticks run</dt><dd>{r.ticks_run} of {r.max_ticks ?? "?"} ({r.ended})</dd>
            <dt>Wall time</dt><dd>{r.duration_s}s</dd>
            <dt>First detection</dt><dd>{ticks(b.ticks_to_first_detection)}</dd>
            <dt>SLA uptime</dt><dd>{pct(b.sla_uptime)}</dd>
          </dl>
        </Card>
      </div>
    </div>
  );
}

function AuditTab({ id }: { id: string }) {
  const a = useFetch(() => api.audit(id), [id]);
  const [q, setQ] = useState("");
  if (a.error) return <ErrorBanner error={a.error} onRetry={a.reload} />;
  if (!a.data) return <Skeleton h={300} />;
  const d = a.data;
  const rows = d.entries.filter((e) => !q || JSON.stringify(e).toLowerCase().includes(q.toLowerCase()));
  return (
    <div className="stack">
      <div className="grid g4">
        <Stat label="Chain integrity" value={d.verified ? "Verified" : "Broken"} tone={d.verified ? "good" : "critical"} foot={d.verified ? "every hash links to the previous entry" : d.error} />
        <Stat label="Entries" value={d.total} foot="append-only, SHA-256 chained" />
        <Stat label="Denied requests" value={Object.entries(d.counts).filter(([k]) => k.endsWith(":deny")).reduce((x, [, v]) => x + v, 0)} foot="out-of-scope attempts" />
        <Stat label="Chain tip" value={<span className="mono" style={{ fontSize: 16 }}>{shortHash(d.tip, 10)}</span>} foot="latest entry hash" />
      </div>
      <Card title="Hash chain" sub="First entries of the chain. Each block stores the previous block's hash.">
        <div className="hashchain">
          {d.entries.slice(0, 10).map((e, i) => (
            <div key={e.seq} className="row" style={{ gap: 0, flexWrap: "nowrap" }}>
              {i > 0 && <span className="hash-link" />}
              <div className={`hash-block ${e.outcome}`}>
                <div className="hb-seq">#{e.seq} · {e.outcome}</div>
                <div className="hb-act">{e.action}</div>
                <div className="mono muted" style={{ fontSize: 10 }}>{e.entry_hash.slice(0, 12)}</div>
              </div>
            </div>
          ))}
        </div>
      </Card>
      <Card
        title="Entries"
        bodyClass=""
        actions={<input className="input" placeholder="Filter entries…" value={q} onChange={(e) => setQ(e.target.value)} style={{ width: 200 }} aria-label="Filter audit entries" />}
      >
        <div className="table-wrap" style={{ maxHeight: 460, marginTop: 12 }}>
          <table className="table">
            <thead>
              <tr><th>#</th><th>Time</th><th>Actor</th><th>Action</th><th>Outcome</th><th>Detail</th><th>Hash</th></tr>
            </thead>
            <tbody>
              {rows.map((e) => (
                <tr key={e.seq}>
                  <td className="mono muted">{e.seq}</td>
                  <td className="mono nowrap" style={{ fontSize: 11.5 }}>{new Date(e.timestamp).toLocaleTimeString()}</td>
                  <td>{e.actor}</td>
                  <td><span className="tag">{e.action}</span></td>
                  <td><StatusPill tone={e.outcome === "allow" ? "good" : e.outcome === "deny" ? "critical" : "neutral"}>{e.outcome}</StatusPill></td>
                  <td className="mono muted" style={{ fontSize: 11.5, maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={JSON.stringify(e.detail)}>{JSON.stringify(e.detail)}</td>
                  <td className="mono muted" style={{ fontSize: 11 }} title={e.entry_hash}>{e.entry_hash.slice(0, 10)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function ExportTab({ id }: { id: string }) {
  const items = [
    { fmt: "sarif", icon: <FileCode2 size={18} />, title: "SARIF 2.1.0", desc: "Upload to GitHub code scanning, Azure DevOps, or any SARIF dashboard." },
    { fmt: "navigator", icon: <Layers size={18} />, title: "ATT&CK Navigator layer", desc: "Open in MITRE ATT&CK Navigator to see the techniques red used." },
    { fmt: "csv", icon: <FileSpreadsheet size={18} />, title: "Findings CSV", desc: "Import into Jira, Linear or a spreadsheet. Includes CWE and control mapping." },
    { fmt: "json", icon: <FileJson size={18} />, title: "Full result JSON", desc: "Scoreboard, KPIs, per-tick timeline and enriched findings." },
    { fmt: "md", icon: <ListChecks size={18} />, title: "Markdown report", desc: "Paste into a PR, wiki or ticket." },
  ];
  return (
    <div className="grid g3">
      {items.map((it) => (
        <Card key={it.fmt}>
          <div className="callout" style={{ padding: 0 }}>
            <span className="ci">{it.icon}</span>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 600 }}>{it.title}</div>
              <div className="text-2" style={{ fontSize: 12.5, margin: "4px 0 12px" }}>{it.desc}</div>
              <a className="btn sm" href={exportUrl(id, it.fmt)}>
                <Download size={13} /> Download
              </a>
            </div>
          </div>
        </Card>
      ))}
      <Card>
        <div className="callout" style={{ padding: 0 }}>
          <span className="ci"><FileText size={18} /></span>
          <div style={{ flex: 1 }}>
            <div style={{ fontWeight: 600 }}>HTML audit report</div>
            <div className="text-2" style={{ fontSize: 12.5, margin: "4px 0 12px" }}>A self-contained report to print or attach to an audit.</div>
            <a className="btn sm" href={reportUrl(id)} target="_blank" rel="noreferrer">Open report</a>
          </div>
        </div>
      </Card>
    </div>
  );
}

export default function EngagementPage({ params }: { params: { id: string } }) {
  return (
    <Suspense fallback={<Skeleton h={420} />}>
      <Detail id={params.id} />
    </Suspense>
  );
}
