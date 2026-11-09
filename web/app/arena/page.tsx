"use client";

import { Suspense, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter, useSearchParams } from "next/navigation";
import {
  CheckCircle2,
  Crosshair,
  Dice5,
  ExternalLink,
  FileText,
  Lock,
  OctagonX,
  Play,
  RotateCcw,
  ShieldHalf,
  Swords,
} from "lucide-react";
import { AgentInfo, ApiError, ScenarioInfo, api } from "@/lib/api";
import { derive } from "@/lib/derive";
import { useEngagementStream, useFetch } from "@/lib/hooks";
import ArenaView from "@/components/arena/ArenaView";
import { Card, ErrorBanner, PageHead, Seg, Skeleton, StatusPill } from "@/components/ui";
import { useToast } from "@/components/Shell";
import { outcome } from "@/lib/format";

const PACES = [
  { value: 0, label: "Instant" },
  { value: 350, label: "Fast" },
  { value: 700, label: "Watch" },
  { value: 1400, label: "Slow" },
];

function ArenaInner() {
  const params = useSearchParams();
  const router = useRouter();
  const toast = useToast();
  const meta = useFetch(async () => {
    const [agents, scenarios] = await Promise.all([api.agents(), api.scenarios()]);
    return { agents, scenarios };
  });

  const [scenario, setScenario] = useState(params.get("scenario") || "shop-01");
  const [red, setRed] = useState(params.get("red") || "scripted");
  const [blue, setBlue] = useState(params.get("blue") || "scripted");
  const [seed, setSeed] = useState(Number(params.get("seed") || 42));
  const [pace, setPace] = useState(700);
  const [id, setId] = useState<string | null>(params.get("id"));
  const [startError, setStartError] = useState<string | null>(null);
  const [starting, setStarting] = useState(false);
  const [stopping, setStopping] = useState(false);

  const { events, status, result } = useEngagementStream(id);
  const sc: ScenarioInfo | undefined = meta.data?.scenarios.find((s) => s.id === scenario);
  const maxTicks = sc?.max_ticks ?? 12;
  const st = useMemo(() => derive(events, Infinity, maxTicks), [events, maxTicks]);

  const reds = meta.data?.agents.filter((a) => a.team === "red") ?? [];
  const blues = meta.data?.agents.filter((a) => a.team === "blue") ?? [];
  const redInfo = reds.find((a) => a.name === red);
  const blueInfo = blues.find((a) => a.name === blue);

  useEffect(() => {
    if (status === "done" && result) {
      const o = outcome(result.ended, result.flag_captured);
      toast(
        <>
          Engagement finished: <b>{o.label}</b>, resilience {result.resilience}.
        </>
      );
    }
  }, [status, result, toast]);

  const start = async () => {
    setStarting(true);
    setStartError(null);
    try {
      const r = await api.start({ scenario, seed, red, blue, pace_ms: pace });
      setId(r.id);
      router.replace(`/arena?id=${r.id}&red=${red}&blue=${blue}&seed=${seed}&scenario=${scenario}`, { scroll: false });
    } catch (e: any) {
      setStartError(e instanceof ApiError ? e.message : String(e));
    } finally {
      setStarting(false);
    }
  };

  const stop = async () => {
    if (!id) return;
    setStopping(true);
    try {
      await api.stop(id);
      toast("Kill switch tripped. All agents halted.");
    } catch (e: any) {
      toast("Could not stop: " + e.message);
    } finally {
      setStopping(false);
    }
  };

  const reset = () => {
    setId(null);
    router.replace(`/arena?red=${red}&blue=${blue}&scenario=${scenario}`, { scroll: false });
  };

  const running = !!id && status !== "done" && status !== "error";

  if (id) {
    return (
      <>
        <PageHead
          title={`${redInfo?.label ?? red} vs ${blueInfo?.label ?? blue}`}
          sub={
            <>
              {sc?.name ?? scenario} · seed <span className="mono">{seed}</span> · engagement <span className="mono">{id}</span>
            </>
          }
          actions={
            <>
              {running ? (
                <button className="btn danger" onClick={stop} disabled={stopping} title="Halts every agent immediately">
                  <OctagonX size={15} /> {stopping ? "Stopping…" : "Emergency stop"}
                </button>
              ) : (
                <>
                  <button className="btn" onClick={reset}>
                    <RotateCcw size={14} /> New run
                  </button>
                  <Link className="btn" href={`/engagements/${id}?tab=replay`}>
                    <Play size={14} /> Replay
                  </Link>
                  <Link className="btn primary" href={`/engagements/${id}?tab=findings`}>
                    <FileText size={14} /> Open report
                  </Link>
                </>
              )}
            </>
          }
        />
        {status === "error" && <ErrorBanner error="The live stream failed. The engagement may still be running; check Engagements." />}
        {status === "connecting" && <Skeleton h={4} style={{ marginBottom: 14 }} />}
        <ArenaView
          st={st}
          events={events}
          maxTicks={maxTicks}
          red={{ name: red, label: redInfo?.label ?? red }}
          blue={{ name: blue, label: blueInfo?.label ?? blue }}
          live={running}
        />
      </>
    );
  }

  return (
    <>
      <PageHead
        title="Launch an engagement"
        sub="Pick a target scenario and two agents. The referee runs them tick by tick against the bundled sandbox. Nothing leaves 127.0.0.1."
      />
      {meta.error && <ErrorBanner error={meta.error} onRetry={meta.reload} />}
      {startError && <ErrorBanner error={startError} />}

      <div className="launch-grid">
        <div className="stack">
          <Card title="1 · Target scenario">
            {meta.loading ? (
              <Skeleton h={64} />
            ) : (
              <div className="pick-grid">
                {meta.data?.scenarios.map((s) => (
                  <button key={s.id} className={`pick ${scenario === s.id ? "on" : ""}`} onClick={() => setScenario(s.id)}>
                    <span className="pk-title">{s.name}</span>
                    <span className="pk-desc">
                      {s.weaknesses.length} planted weaknesses · {s.max_ticks} ticks · randomized {s.randomize.join(", ")}
                    </span>
                  </button>
                ))}
              </div>
            )}
          </Card>

          <div className="grid g2">
            <Card title={<span className="row" style={{ gap: 6 }}><Crosshair size={14} color="var(--red)" /> 2 · Red agent (attacker)</span>}>
              <AgentPicker agents={reds} value={red} onChange={setRed} team="red" loading={meta.loading} />
            </Card>
            <Card title={<span className="row" style={{ gap: 6 }}><ShieldHalf size={14} color="var(--blue)" /> 3 · Blue agent (defender)</span>}>
              <AgentPicker agents={blues} value={blue} onChange={setBlue} team="blue" loading={meta.loading} />
            </Card>
          </div>

          <Card title="4 · Run settings">
            <div className="row" style={{ gap: 28, alignItems: "flex-start" }}>
              <div>
                <div className="field-label">Seed</div>
                <div className="row" style={{ gap: 6 }}>
                  <input
                    className="input mono"
                    type="number"
                    min={0}
                    value={seed}
                    onChange={(e) => setSeed(Math.max(0, Number(e.target.value) || 0))}
                    style={{ width: 110 }}
                    aria-label="Seed"
                  />
                  <button className="btn icon" onClick={() => setSeed(Math.floor(Math.random() * 100000))} title="Random seed" aria-label="Random seed">
                    <Dice5 size={15} />
                  </button>
                </div>
                <div className="muted" style={{ fontSize: 11.5, marginTop: 6, maxWidth: 240 }}>
                  The seed randomizes hidden paths and the flag, so agents can't win by memorizing.
                </div>
              </div>
              <div>
                <div className="field-label">Pace</div>
                <Seg options={PACES} value={pace} onChange={setPace} label="Pace" />
                <div className="muted" style={{ fontSize: 11.5, marginTop: 6 }}>
                  Delay between ticks so you can follow the match live.
                </div>
              </div>
            </div>
          </Card>
        </div>

        <div className="stack launch-side">
          <Card title="Authorization preview" sub="What the gate will enforce for this run">
            <div className="checklist">
              <div><CheckCircle2 size={14} /><span>Ownership proven via a <span className="mono">/.well-known</span> token on 127.0.0.1</span></div>
              <div><CheckCircle2 size={14} /><span>Scope: one host, staging environment, 2-hour window</span></div>
              <div><CheckCircle2 size={14} /><span>Rate cap 2,000 requests / 60s, max 3 actions per tick</span></div>
              <div><CheckCircle2 size={14} /><span>Red: non-destructive detection set only</span></div>
              <div><CheckCircle2 size={14} /><span>Blue: defensive whitelist, no shell</span></div>
              <div><CheckCircle2 size={14} /><span>Every request hash-chained to the audit log</span></div>
            </div>
            <div className="divider" />
            <div className="row between" style={{ fontSize: 12.5 }}>
              <span className="muted">Matchup</span>
              <span>
                <b style={{ color: "var(--text)" }}>{redInfo?.label ?? red}</b> <span className="muted">vs</span> <b>{blueInfo?.label ?? blue}</b>
              </span>
            </div>
            <button className="btn primary lg" style={{ width: "100%", marginTop: 14 }} onClick={start} disabled={starting || !!meta.error}>
              <Swords size={16} /> {starting ? "Authorizing…" : "Authorize & start"}
            </button>
            <div className="muted row" style={{ fontSize: 11.5, marginTop: 10, gap: 6, flexWrap: "nowrap", alignItems: "flex-start" }}>
              <Lock size={12} /> You can halt every agent at any time with the emergency stop.
            </div>
          </Card>
          <Link href="/governance" className="muted row" style={{ fontSize: 12.5, gap: 6 }}>
            How authorization works <ExternalLink size={12} />
          </Link>
        </div>
      </div>
    </>
  );
}

function AgentPicker({
  agents,
  value,
  onChange,
  team,
  loading,
}: {
  agents: AgentInfo[];
  value: string;
  onChange: (v: string) => void;
  team: "red" | "blue";
  loading: boolean;
}) {
  if (loading) return <Skeleton h={120} />;
  return (
    <div className="pick-grid" style={{ gridTemplateColumns: "1fr" }}>
      {agents.map((a) => (
        <button
          key={a.name}
          className={`pick ${team} ${value === a.name ? "on" : ""}`}
          disabled={!a.available}
          onClick={() => onChange(a.name)}
          title={a.available ? a.description : "Set ANTHROPIC_API_KEY on the API server to enable"}
        >
          <span className="pk-title">
            {a.label}
            <span className="tag">{a.kind}</span>
            {!a.available && <StatusPill tone="neutral">needs API key</StatusPill>}
          </span>
          <span className="pk-desc">{a.description}</span>
        </button>
      ))}
    </div>
  );
}

export default function ArenaPage() {
  return (
    <Suspense fallback={<Skeleton h={300} />}>
      <ArenaInner />
    </Suspense>
  );
}
