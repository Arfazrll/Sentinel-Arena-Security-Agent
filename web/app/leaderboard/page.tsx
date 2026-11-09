"use client";

import { Suspense, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useSearchParams } from "next/navigation";
import { Crown, Download, Play, ShieldHalf, Trophy, Zap } from "lucide-react";
import { BenchmarkJob, api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { ago, download, pct } from "@/lib/format";
import { BarList, Heatmap } from "@/components/charts";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, Stat } from "@/components/ui";
import { useToast } from "@/components/Shell";

function Inner() {
  const params = useSearchParams();
  const toast = useToast();
  const agents = useFetch(() => api.agents());
  const [seeds, setSeeds] = useState("42,7,101");
  const [reds, setReds] = useState<string[]>([]);
  const [blues, setBlues] = useState<string[]>([]);
  const [job, setJob] = useState<BenchmarkJob | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const poll = useRef<ReturnType<typeof setInterval> | null>(null);

  const benchable = (agents.data || []).filter((a) => a.benchmark && a.available);
  useEffect(() => {
    if (agents.data && !reds.length && !blues.length) {
      setReds(benchable.filter((a) => a.team === "red").map((a) => a.name));
      setBlues(benchable.filter((a) => a.team === "blue").map((a) => a.name));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agents.data]);

  useEffect(() => {
    api.latestBenchmark().then(setJob).catch(() => {});
    return () => {
      if (poll.current) clearInterval(poll.current);
    };
  }, []);

  const run = useCallback(async () => {
    setErr(null);
    try {
      const { id } = await api.startBenchmark(seeds, reds, blues);
      setJob({ id, status: "running", done: 0, total: 1, rows: [], seeds: [], scenario: "shop-01", current: "", started_at: new Date().toISOString() });
      if (poll.current) clearInterval(poll.current);
      poll.current = setInterval(async () => {
        try {
          const j = await api.benchmark(id);
          setJob(j);
          if (j.status !== "running") {
            clearInterval(poll.current!);
            if (j.status === "done") toast(`Benchmark finished: ${j.rows.length} matchups over ${j.seeds.length} seeds.`);
          }
        } catch {}
      }, 700);
    } catch (e: any) {
      setErr(e.message);
    }
  }, [seeds, reds, blues, toast]);

  const autoRan = useRef(false);
  useEffect(() => {
    if (params.get("run") && agents.data && reds.length && !autoRan.current) {
      autoRan.current = true;
      run();
    }
  }, [params, agents.data, reds, run]);

  const rows = job?.rows || [];
  const labelOf = (team: string, n: string) => agents.data?.find((a) => a.team === team && a.name === n)?.label || n;
  const redNames = Array.from(new Set(rows.map((r) => r.red)));
  const blueNames = Array.from(new Set(rows.map((r) => r.blue)));

  const insights = useMemo(() => {
    if (!rows.length) return null;
    const byBlue = blueNames.map((b) => {
      const rs = rows.filter((r) => r.blue === b);
      return { b, mean: rs.reduce((a, r) => a + r.mean_resilience, 0) / rs.length, worst: Math.min(...rs.map((r) => r.mean_resilience)) };
    });
    const best = [...byBlue].sort((a, b) => b.worst - a.worst || b.mean - a.mean)[0];
    const byRed = redNames.map((r) => {
      const rs = rows.filter((x) => x.red === r);
      return { r, win: rs.reduce((a, x) => a + x.flag_capture_rate, 0) / rs.length };
    });
    const strongest = [...byRed].sort((a, b) => b.win - a.win)[0];
    return { best, strongest, total: rows.reduce((a, r) => a + r.runs, 0) };
  }, [rows, redNames, blueNames]);

  const toggle = (list: string[], set: (v: string[]) => void, n: string) => set(list.includes(n) ? list.filter((x) => x !== n) : [...list, n]);
  const running = job?.status === "running";
  const total = reds.length * blues.length * seeds.split(",").filter((s) => s.trim()).length;

  return (
    <>
      <PageHead
        title="Benchmarks"
        sub="Every selected attacker against every selected defender, on the same seeds. Rank defenders by how well they hold, and find the attacker that breaks them."
        actions={
          rows.length ? (
            <button className="btn" onClick={() => download("benchmark.json", JSON.stringify(job, null, 2), "application/json")}>
              <Download size={14} /> Export JSON
            </button>
          ) : null
        }
      />
      {agents.error && <ErrorBanner error={agents.error} onRetry={agents.reload} />}
      {err && <ErrorBanner error={err} />}

      <Card title="Configure">
        {agents.loading ? (
          <Skeleton h={80} />
        ) : (
          <div className="stack" style={{ gap: 14 }}>
            <div>
              <div className="field-label">Attackers</div>
              <div className="row">
                {benchable.filter((a) => a.team === "red").map((a) => (
                  <button key={a.name} className={`chip ${reds.includes(a.name) ? "on" : ""}`} onClick={() => toggle(reds, setReds, a.name)} title={a.description}>
                    <span className="sw" style={{ background: "var(--red)" }} /> {a.label}
                  </button>
                ))}
              </div>
            </div>
            <div>
              <div className="field-label">Defenders</div>
              <div className="row">
                {benchable.filter((a) => a.team === "blue").map((a) => (
                  <button key={a.name} className={`chip ${blues.includes(a.name) ? "on" : ""}`} onClick={() => toggle(blues, setBlues, a.name)} title={a.description}>
                    <span className="sw" style={{ background: "var(--blue)" }} /> {a.label}
                  </button>
                ))}
              </div>
            </div>
            <div className="row" style={{ alignItems: "flex-end", gap: 14 }}>
              <div>
                <div className="field-label">Seeds (comma separated, up to 10)</div>
                <input className="input mono" value={seeds} onChange={(e) => setSeeds(e.target.value)} style={{ width: 220 }} aria-label="Seeds" />
              </div>
              <button className="btn primary" onClick={run} disabled={running || !reds.length || !blues.length}>
                <Play size={14} /> {running ? "Running…" : `Run ${total} engagements`}
              </button>
              <span className="muted" style={{ fontSize: 12 }}>About 1 second per engagement.</span>
            </div>
            {running && job && (
              <div>
                <div className="row between" style={{ fontSize: 12, marginBottom: 6 }}>
                  <span className="text-2">{job.current || "Starting…"}</span>
                  <span className="tnum">{job.done} / {job.total}</span>
                </div>
                <div className="progress"><span style={{ width: `${(job.done / Math.max(1, job.total)) * 100}%` }} /></div>
              </div>
            )}
          </div>
        )}
      </Card>

      {!rows.length && !running ? (
        <Card className="" bodyClass="">
          <Empty icon={<Trophy size={20} />} title="No benchmark yet">
            Run one to see which defender holds best and which attacker finds the gaps.
          </Empty>
        </Card>
      ) : rows.length ? (
        <div className="stack" style={{ marginTop: 14 }}>
          {insights && (
            <div className="grid g3">
              <Stat icon={<Crown size={13} />} label="Most robust defender" value={labelOf("blue", insights.best.b)} foot={`worst case ${insights.best.worst.toFixed(0)}, mean ${insights.best.mean.toFixed(0)}`} />
              <Stat icon={<Zap size={13} />} label="Strongest attacker" value={labelOf("red", insights.strongest.r)} foot={`wins ${pct(insights.strongest.win)} of its matchups`} />
              <Stat icon={<ShieldHalf size={13} />} label="Engagements run" value={insights.total} foot={`${rows.length} matchups · finished ${ago(job?.finished_at)}`} />
            </div>
          )}
          <div className="grid g2">
            <Card title="Resilience matrix" sub="Mean resilience for each attacker × defender pair. Higher is better for the defender.">
              <Heatmap
                rows={redNames}
                cols={blueNames}
                rowLabel={(r) => labelOf("red", r)}
                colLabel={(c) => labelOf("blue", c)}
                value={(r, c) => rows.find((x) => x.red === r && x.blue === c)?.mean_resilience ?? null}
                format={(v) => v.toFixed(0)}
              />
            </Card>
            <Card title="Matchups ranked" sub="By mean resilience">
              <BarList
                max={100}
                rows={rows.map((r) => ({
                  label: `${r.red_label || r.red} vs ${r.blue_label || r.blue}`,
                  value: r.mean_resilience,
                  color: r.flag_capture_rate > 0.5 ? "var(--critical)" : r.flag_capture_rate > 0 ? "var(--warning)" : "var(--good)",
                  title: `Attacker won ${pct(r.flag_capture_rate)}`,
                }))}
                format={(v) => v.toFixed(0)}
              />
              <div className="legend" style={{ marginTop: 12 }}>
                <span><i style={{ background: "var(--good)" }} />flag always held</span>
                <span><i style={{ background: "var(--warning)" }} />sometimes captured</span>
                <span><i style={{ background: "var(--critical)" }} />mostly captured</span>
              </div>
            </Card>
          </div>
          <Card title="All matchups" bodyClass="">
            <div className="table-wrap" style={{ marginTop: 10 }}>
              <table className="table">
                <thead>
                  <tr>
                    <th>#</th><th>Attacker</th><th>Defender</th><th className="num">Runs</th><th className="num">Attacker wins</th>
                    <th className="num">Resilience</th><th>Per seed</th><th className="num">Red</th><th className="num">Blue</th>
                    <th className="num">Detect</th><th className="num">False blocks</th><th className="num">Ticks</th>
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r, i) => (
                    <tr key={r.red + r.blue}>
                      <td className="muted">{i + 1}</td>
                      <td><span style={{ color: "var(--red)" }}>●</span> {r.red_label || r.red}</td>
                      <td><span style={{ color: "var(--blue)" }}>●</span> {r.blue_label || r.blue}</td>
                      <td className="num">{r.runs}</td>
                      <td className="num">{pct(r.flag_capture_rate)}</td>
                      <td className="num"><b>{r.mean_resilience}</b></td>
                      <td>
                        <div className="row" style={{ gap: 3, flexWrap: "nowrap" }}>
                          {r.resilience_runs?.map((v, j) => (
                            <span key={j} title={`seed ${job?.seeds[j]}: ${v}`} style={{ width: 10, height: 10, borderRadius: 3, background: v >= 70 ? "var(--good)" : v >= 40 ? "var(--warning)" : "var(--critical)" }} />
                          ))}
                        </div>
                      </td>
                      <td className="num">{r.mean_red_score}</td>
                      <td className="num">{r.mean_blue_score}</td>
                      <td className="num">{r.mean_ticks_to_detection ?? "—"}</td>
                      <td className="num">{r.mean_false_blocks ?? 0}</td>
                      <td className="num">{r.mean_ticks_run ?? "—"}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      ) : null}
    </>
  );
}

export default function LeaderboardPage() {
  return (
    <Suspense fallback={<Skeleton h={300} />}>
      <Inner />
    </Suspense>
  );
}
