"use client";

import { Suspense, useMemo } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import { ArrowRight, GitCompare, Minus, TrendingDown, TrendingUp } from "lucide-react";
import { EngagementResult, api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { dateTime, outcome, pct } from "@/lib/format";
import { LineChart } from "@/components/charts";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, StatusPill } from "@/components/ui";

type Metric = { label: string; get: (r: EngagementResult) => number | null; fmt?: (v: number) => string; higherIsBetter: boolean };

const METRICS: Metric[] = [
  { label: "Resilience", get: (r) => r.scoreboard.resilience, higherIsBetter: true },
  { label: "Red score", get: (r) => r.timeline?.at(-1)?.red ?? null, higherIsBetter: false },
  { label: "Blue score", get: (r) => r.timeline?.at(-1)?.blue ?? null, higherIsBetter: true },
  { label: "Findings", get: (r) => r.findings.length, higherIsBetter: false },
  { label: "Time to detect (ticks)", get: (r) => r.kpis?.time_to_detect ?? null, higherIsBetter: false },
  { label: "Time to contain (ticks)", get: (r) => r.kpis?.time_to_contain ?? null, higherIsBetter: false },
  { label: "Attacker dwell (ticks)", get: (r) => r.kpis?.dwell_ticks ?? null, higherIsBetter: false },
  { label: "Attacker requests blocked", get: (r) => r.kpis?.attacker_block_rate ?? null, fmt: (v) => pct(v), higherIsBetter: true },
  { label: "Real users served", get: (r) => r.scoreboard.blue.legit_availability, fmt: (v) => pct(v), higherIsBetter: true },
  { label: "False blocks", get: (r) => r.scoreboard.blue.false_blocks, higherIsBetter: false },
];

function Inner() {
  const params = useSearchParams();
  const router = useRouter();
  const a = params.get("a");
  const b = params.get("b");
  const list = useFetch(() => api.engagements());
  const ra = useFetch(() => (a ? api.result(a) : Promise.resolve(null)), [a]);
  const rb = useFetch(() => (b ? api.result(b) : Promise.resolve(null)), [b]);
  const done = (list.data || []).filter((e) => e.status !== "running");

  const set = (k: "a" | "b", v: string) => {
    const p = new URLSearchParams(params.toString());
    p.set(k, v);
    router.replace(`/compare?${p}`);
  };

  const label = (id: string | null) => {
    const e = done.find((x) => x.id === id);
    return e ? `${e.red_label || e.red} vs ${e.blue_label || e.blue} · seed ${e.seed}` : id || "";
  };

  const findingsDiff = useMemo(() => {
    if (!ra.data || !rb.data) return null;
    const A = new Set(ra.data.findings.map((f) => f.rule_id));
    const B = new Set(rb.data.findings.map((f) => f.rule_id));
    const all = new Map([...ra.data.findings, ...rb.data.findings].map((f) => [f.rule_id, f]));
    return Array.from(all.values()).map((f) => ({
      f,
      status: A.has(f.rule_id) && B.has(f.rule_id) ? "both" : A.has(f.rule_id) ? "fixed" : "new",
    }));
  }, [ra.data, rb.data]);

  const picker = (k: "a" | "b", v: string | null) => (
    <select className="input" value={v || ""} onChange={(e) => set(k, e.target.value)} style={{ minWidth: 280 }} aria-label={`Run ${k.toUpperCase()}`}>
      <option value="" disabled>Choose a run…</option>
      {done.map((e) => (
        <option key={e.id} value={e.id}>
          {dateTime(e.created_at)} · {e.red_label || e.red} vs {e.blue_label || e.blue} · seed {e.seed} · {e.result?.resilience ?? "?"}
        </option>
      ))}
    </select>
  );

  return (
    <>
      <PageHead title="Compare runs" sub="Put two engagements side by side: did a defender change, a new agent or a fix move the numbers?" />
      {list.error && <ErrorBanner error={list.error} onRetry={list.reload} />}
      <Card>
        <div className="row" style={{ gap: 12 }}>
          <span className="pill">A</span>
          {picker("a", a)}
          <ArrowRight size={16} className="muted" />
          <span className="pill">B</span>
          {picker("b", b)}
        </div>
      </Card>

      {!a || !b ? (
        <Card className="" bodyClass="">
          <Empty icon={<GitCompare size={20} />} title="Pick two runs">
            Choose a baseline (A) and a candidate (B). Deltas are shown as B minus A.
          </Empty>
        </Card>
      ) : !ra.data || !rb.data ? (
        <Skeleton h={300} style={{ marginTop: 14 }} />
      ) : (
        <div className="stack" style={{ marginTop: 14 }}>
          <div className="grid g2">
            {[{ k: "A", r: ra.data, id: a }, { k: "B", r: rb.data, id: b }].map(({ k, r, id }) => {
              const o = outcome(r.ended, r.scoreboard.red.flag_captured);
              return (
                <Card key={k}>
                  <div className="row between">
                    <div>
                      <div className="muted" style={{ fontSize: 12 }}>Run {k}</div>
                      <div style={{ fontWeight: 600 }}>{label(id)}</div>
                    </div>
                    <div className="row">
                      <StatusPill tone={o.tone}>{o.label}</StatusPill>
                      <span className="hero-num" style={{ fontSize: 34 }}>{r.scoreboard.resilience}</span>
                    </div>
                  </div>
                  <Link href={`/engagements/${id}`} className="muted" style={{ fontSize: 12 }}>Open run →</Link>
                </Card>
              );
            })}
          </div>

          <div className="grid g2">
            <Card title="Metric deltas" sub="B minus A. Green means B is better." bodyClass="">
              <div className="table-wrap" style={{ marginTop: 10 }}>
                <table className="table">
                  <thead><tr><th>Metric</th><th className="num">A</th><th className="num">B</th><th className="num">Change</th></tr></thead>
                  <tbody>
                    {METRICS.map((m) => {
                      const x = m.get(ra.data!);
                      const y = m.get(rb.data!);
                      const f = m.fmt || ((v: number) => String(Math.round(v * 100) / 100));
                      const d = x !== null && y !== null ? y - x : null;
                      const better = d === null || d === 0 ? null : (d > 0) === m.higherIsBetter;
                      return (
                        <tr key={m.label}>
                          <td>{m.label}</td>
                          <td className="num">{x === null ? "—" : f(x)}</td>
                          <td className="num">{y === null ? "—" : f(y)}</td>
                          <td className="num">
                            {d === null ? (
                              <span className="muted">n/a</span>
                            ) : d === 0 ? (
                              <span className="muted"><Minus size={12} /> 0</span>
                            ) : (
                              <span className={better ? "delta-up" : "delta-down"}>
                                {d > 0 ? <TrendingUp size={12} /> : <TrendingDown size={12} />} {d > 0 ? "+" : ""}
                                {m.fmt ? f(d) : Math.round(d * 100) / 100}
                              </span>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </Card>
            <div className="stack">
              <Card title="Resilience over the match">
                <LineChart
                  yMax={100}
                  data={Array.from({ length: Math.max(ra.data.timeline?.length || 0, rb.data.timeline?.length || 0) }, (_, i) => ({
                    x: i,
                    a: ra.data!.timeline?.[i]?.resilience ?? null,
                    b: rb.data!.timeline?.[i]?.resilience ?? null,
                  }))}
                  series={[
                    { key: "a", label: "Run A", color: "var(--system)" },
                    { key: "b", label: "Run B", color: "var(--blue)" },
                  ]}
                  height={200}
                />
              </Card>
              <Card title="Findings diff" bodyClass="">
                <div className="table-wrap" style={{ marginTop: 10 }}>
                  <table className="table">
                    <tbody>
                      {findingsDiff?.length === 0 && <tr><td className="muted">Neither run recorded findings.</td></tr>}
                      {findingsDiff?.map(({ f, status }) => (
                        <tr key={f.rule_id}>
                          <td>{f.title}</td>
                          <td className="num">
                            <StatusPill tone={status === "fixed" ? "good" : status === "new" ? "critical" : "neutral"}>
                              {status === "fixed" ? "Only in A" : status === "new" ? "New in B" : "In both"}
                            </StatusPill>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </Card>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

export default function ComparePage() {
  return (
    <Suspense fallback={<Skeleton h={300} />}>
      <Inner />
    </Suspense>
  );
}
