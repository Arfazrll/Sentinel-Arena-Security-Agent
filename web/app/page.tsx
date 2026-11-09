"use client";

import { useMemo } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import {
  ArrowRight,
  Bot,
  CircleCheck,
  ClipboardList,
  Crosshair,
  FlaskConical,
  Gauge as GaugeIcon,
  History,
  ShieldCheck,
  Swords,
  Target,
  Timer,
  Trophy,
} from "lucide-react";
import { api } from "@/lib/api";
import { useFetch, useLocalState } from "@/lib/hooks";
import { ago, mean, median, outcome, pct, resilienceWord } from "@/lib/format";
import { BarList, Gauge, LineChart, Sparkline } from "@/components/charts";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, Stat, StatusPill } from "@/components/ui";

export default function Overview() {
  const router = useRouter();
  const eng = useFetch(() => api.engagements());
  const fnd = useFetch(() => api.findings());
  const [statuses] = useLocalState<Record<string, string>>("sa-remediation", {});

  const done = useMemo(
    () => (eng.data || []).filter((e) => e.result && e.status !== "running" && !e.result.error).slice().reverse(),
    [eng.data]
  );

  const stats = useMemo(() => {
    const res = done.map((e) => e.result!.resilience);
    const caps = done.filter((e) => e.result!.flag_captured).length;
    const ttd = done.map((e) => e.time_to_detect).filter((x): x is number => x !== null && x !== undefined);
    const byBlue = new Map<string, number[]>();
    done.forEach((e) => {
      const k = e.blue_label || e.blue;
      byBlue.set(k, [...(byBlue.get(k) || []), e.result!.resilience]);
    });
    const latest = done[done.length - 1];
    const prev = done[done.length - 2];
    return {
      res,
      caps,
      ttd,
      latest,
      delta: latest && prev ? latest.result!.resilience - prev.result!.resilience : null,
      byBlue: Array.from(byBlue.entries())
        .map(([k, v]) => ({ label: k, value: Math.round(mean(v)!), runs: v.length }))
        .sort((a, b) => b.value - a.value),
    };
  }, [done]);

  const openFindings = (fnd.data || []).filter((f) => (statuses[f.rule_id] || "open") !== "fixed" && (statuses[f.rule_id] || "open") !== "accepted");
  const owasp = useMemo(() => {
    const m = new Map<string, { label: string; value: number }>();
    (fnd.data || []).forEach((f) => {
      const cur = m.get(f.owasp) || { label: `${f.owasp} ${f.owasp_title}`, value: 0 };
      cur.value += f.occurrences;
      m.set(f.owasp, cur);
    });
    return Array.from(m.values()).sort((a, b) => b.value - a.value);
  }, [fnd.data]);

  if (eng.loading && !eng.data) {
    return (
      <>
        <PageHead title="Overview" />
        <div className="grid g4">{[0, 1, 2, 3].map((i) => <Skeleton key={i} h={110} />)}</div>
      </>
    );
  }

  if (eng.error) {
    return (
      <>
        <PageHead title="Overview" sub="Your security posture across every engagement." />
        <ErrorBanner error={eng.error} onRetry={eng.reload} />
        <Onboarding apiDown />
      </>
    );
  }

  if (!done.length) {
    return (
      <>
        <PageHead title="Welcome to Sentinel Arena" sub="Red and blue AI agents fight over a sandbox you own. You get a resilience score, a replay of every move, and a compliance-mapped findings report." />
        <Onboarding />
      </>
    );
  }

  const latest = stats.latest!;
  const latestRes = latest.result!.resilience;
  const o = outcome(latest.result!.ended, latest.result!.flag_captured);
  const series = done.map((e, i) => ({ x: i + 1, resilience: e.result!.resilience }));

  return (
    <>
      <PageHead
        title="Overview"
        sub="Security posture across every engagement you've run."
        actions={
          <>
            <Link className="btn" href="/leaderboard"><Trophy size={14} /> Benchmark agents</Link>
            <Link className="btn primary" href="/arena"><Swords size={14} /> New engagement</Link>
          </>
        }
      />

      <div className="grid split-a">
        <Card title="Latest posture" sub={`${latest.red_label || latest.red} vs ${latest.blue_label || latest.blue} · ${ago(latest.created_at)}`}>
          <div className="row posture-row" style={{ gap: 18, alignItems: "center", flexWrap: "nowrap" }}>
            <Gauge value={latestRes} size={150} />
            <div className="stack" style={{ gap: 8 }}>
              <div style={{ fontSize: 18, fontWeight: 650 }}>{resilienceWord(latestRes)}</div>
              <StatusPill tone={o.tone}>{o.label}</StatusPill>
              {stats.delta !== null && (
                <div className={stats.delta >= 0 ? "delta-up" : "delta-down"} style={{ fontSize: 12.5 }}>
                  {stats.delta >= 0 ? "▲" : "▼"} {Math.abs(stats.delta)} vs previous run
                </div>
              )}
              <Link className="btn sm" href={`/engagements/${latest.id}`}>Open run <ArrowRight size={12} /></Link>
            </div>
          </div>
        </Card>
        <div className="grid g2">
          <Stat icon={<GaugeIcon size={13} />} label="Mean resilience" value={Math.round(mean(stats.res) || 0)} unit="/ 100" foot={<><Sparkline values={stats.res.slice(-12)} color="var(--blue)" /> last {Math.min(12, stats.res.length)} runs</>} />
          <Stat icon={<Crosshair size={13} />} label="Attacker win rate" value={pct(stats.caps / done.length)} tone={stats.caps / done.length > 0.5 ? "critical" : stats.caps ? "warning" : "good"} foot={`${stats.caps} of ${done.length} runs reached the flag`} />
          <Stat icon={<Timer size={13} />} label="Median time to detect" value={median(stats.ttd) ?? "—"} unit={stats.ttd.length ? "ticks" : undefined} foot={`${done.length - stats.ttd.length} run(s) never detected the attacker`} />
          <Stat icon={<ClipboardList size={13} />} label="Open findings" value={openFindings.length} tone={openFindings.some((f) => f.priority === "P1") ? "critical" : openFindings.length ? "warning" : "good"} foot={<Link href="/remediation" className="text-2">{openFindings.filter((f) => f.priority === "P1").length} need a fix within 7 days →</Link>} />
        </div>
      </div>

      <div className="grid g3" style={{ marginTop: 14 }}>
        <Card
          className="span2"
          title="Resilience across runs"
          sub="Each point is one engagement, oldest to newest"
          table={
            <table className="table"><thead><tr><th>Run</th><th>Matchup</th><th className="num">Resilience</th></tr></thead>
              <tbody>{done.map((e, i) => <tr key={e.id}><td>#{i + 1}</td><td>{e.red_label || e.red} vs {e.blue_label || e.blue}</td><td className="num">{e.result!.resilience}</td></tr>)}</tbody></table>
          }
        >
          <LineChart data={series} yMax={100} series={[{ key: "resilience", label: "Resilience", color: "var(--blue)" }]} area xFormat={(x) => `#${x}`} height={230} />
        </Card>
        <Card title="Mean resilience by defender" sub="Across all your runs">
          <BarList rows={stats.byBlue.map((b) => ({ label: b.label, value: b.value, title: `${b.runs} run(s)` }))} max={100} />
          <div className="divider" />
          <div className="muted" style={{ fontSize: 12 }}>Run the benchmark to compare every defender on the same seeds.</div>
        </Card>
      </div>

      <div className="grid g3" style={{ marginTop: 14 }}>
        <Card className="span2" title="Recent engagements" actions={<Link href="/engagements" className="btn ghost sm">View all <ArrowRight size={12} /></Link>} bodyClass="">
          <div className="table-wrap" style={{ marginTop: 8 }}>
            <table className="table">
              <thead><tr><th>When</th><th>Matchup</th><th>Outcome</th><th className="num">Resilience</th><th className="num">Findings</th></tr></thead>
              <tbody>
                {done.slice(-6).reverse().map((e) => {
                  const oo = outcome(e.result!.ended, e.result!.flag_captured);
                  return (
                    <tr key={e.id} className="clickable" onClick={() => router.push(`/engagements/${e.id}`)}>
                      <td className="nowrap">{ago(e.created_at)}</td>
                      <td>{e.red_label || e.red} <span className="muted">vs</span> {e.blue_label || e.blue}</td>
                      <td><StatusPill tone={oo.tone}>{oo.label}</StatusPill></td>
                      <td className="num"><b>{e.result!.resilience}</b></td>
                      <td className="num">{e.findings ?? "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
        <Card title="Weaknesses by OWASP category" sub="Occurrences across runs">
          {owasp.length ? <BarList rows={owasp} color="var(--serious)" /> : <div className="muted">No findings yet. Run against a passive defender to inventory weaknesses.</div>}
        </Card>
      </div>
    </>
  );
}

function Onboarding({ apiDown }: { apiDown?: boolean }) {
  const steps = [
    { done: !apiDown, title: "Start the API", body: <>From the repo root: <code>uv run uvicorn sentinel_arena.api.server:app</code></>, icon: <ShieldCheck size={16} /> },
    { done: false, title: "Run your first engagement", body: "Pick an attacker and a defender. Watch them fight live, tick by tick.", icon: <Swords size={16} />, href: "/arena", cta: "Open arena" },
    { done: false, title: "Benchmark the defenders", body: "Run every attacker against every defender on fixed seeds and see who holds.", icon: <Trophy size={16} />, href: "/leaderboard", cta: "Benchmarks" },
    { done: false, title: "Work the findings", body: "Triage weaknesses by priority, with CWE and compliance mapping, and export SARIF.", icon: <ClipboardList size={16} />, href: "/remediation", cta: "Remediation" },
  ];
  return (
    <div className="grid split-b">
      <Card title="Get started" sub="Four steps to a full resilience audit">
        <div className="stack" style={{ gap: 10 }}>
          {steps.map((s, i) => (
            <div key={i} className="callout card flat" style={{ padding: 12 }}>
              <span className="ci">{s.done ? <CircleCheck size={16} color="var(--good-text)" /> : s.icon}</span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600 }}>{i + 1}. {s.title}</div>
                <div className="text-2" style={{ fontSize: 12.5 }}>{s.body}</div>
              </div>
              {s.href && <Link className="btn sm" href={s.href}>{s.cta}</Link>}
            </div>
          ))}
        </div>
      </Card>
      <div className="stack">
        <Card title="What's in the box">
          <div className="stack" style={{ gap: 12, fontSize: 13 }}>
            <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><FlaskConical size={15} className="muted" /> <span><b>Sandbox target</b> with planted OWASP weaknesses and a hidden flag, randomized per seed.</span></div>
            <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><Bot size={15} className="muted" /> <span><b>6 agents</b>: methodical and rush attackers; real-time, batch, block-everything and passive defenders. LLM agents plug in with an API key.</span></div>
            <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><Target size={15} className="muted" /> <span><b>SOC metrics</b>: time to detect, time to contain, attacker dwell, false blocks.</span></div>
            <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><History size={15} className="muted" /> <span><b>Full replay</b> of every run with a scrubbable timeline.</span></div>
            <div className="row" style={{ flexWrap: "nowrap", alignItems: "flex-start" }}><ShieldCheck size={15} className="muted" /> <span><b>Safe by construction</b>: ownership-gated, non-destructive, hash-chained audit, kill switch.</span></div>
          </div>
        </Card>
        {!apiDown && (
          <Card>
            <Empty icon={<Swords size={20} />} title="No engagements yet" action={<Link className="btn primary" href="/arena?red=scripted&blue=scripted"><Swords size={14} /> Run the default matchup</Link>}>
              The default matchup takes about 10 seconds at watch pace.
            </Empty>
          </Card>
        )}
      </div>
    </div>
  );
}
