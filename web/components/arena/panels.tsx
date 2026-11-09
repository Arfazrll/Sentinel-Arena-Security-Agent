"use client";

import { Fragment, ReactNode, useEffect, useMemo, useState } from "react";
import {
  Brain,
  ChevronLeft,
  ChevronRight,
  Crosshair,
  Pause,
  Play,
  Search,
  ShieldHalf,
  SkipBack,
  SkipForward,
} from "lucide-react";
import type { ArenaEvent } from "@/lib/api";
import type { AgentAction, AgentStatus, DerivedState, Moment, Stage } from "@/lib/derive";
import { Gauge } from "@/components/charts";
import { StatusPill } from "@/components/ui";
import { outcome, pct } from "@/lib/format";

// ------------------------------------------------------------ agent card
const STATUS_TEXT: Record<AgentStatus, { label: string; tone: "good" | "warning" | "critical" | "neutral" }> = {
  standby: { label: "Standby", tone: "neutral" },
  active: { label: "Engaged", tone: "neutral" },
  blocked: { label: "Blocked", tone: "warning" },
  won: { label: "Objective reached", tone: "critical" },
  held: { label: "Held the line", tone: "good" },
  stopped: { label: "Stopped", tone: "warning" },
};

const ACTION_TEXT: Record<string, string> = {
  recon: "Mapping the site",
  enumerate_paths: "Probing common endpoints",
  detect: "Running weakness checks",
  capture_flag: "Going for the flag",
  query_logs: "Reviewing request logs",
  block_ip: "Blocking an actor",
  isolate_host: "Isolating suspects",
  kill_process: "Killing a process",
  rotate_password: "Rotating credentials",
  restart_service: "Restarting a service",
};

export function AgentCard({
  team,
  label,
  name,
  status,
  actions,
  stages,
  tick,
  live,
}: {
  team: "red" | "blue";
  label: string;
  name: string;
  status: AgentStatus;
  actions: AgentAction[];
  stages: Stage[];
  tick: number;
  live: boolean;
}) {
  const last = actions[actions.length - 1];
  const okRate = actions.length ? actions.filter((a) => a.ok).length / actions.length : 0;
  const techniques = new Set(actions.map((a) => a.technique).filter(Boolean)).size;
  const thinking = live && status === "active" && !!last && last.tick === tick;
  const s = STATUS_TEXT[status];
  return (
    <section className={`card agent-card ${team}`} aria-label={`${team} agent`}>
      <div className="agent-id">
        <div className={`avatar ${thinking ? "thinking" : ""}`}>
          {team === "red" ? <Crosshair size={18} /> : <ShieldHalf size={18} />}
        </div>
        <div style={{ minWidth: 0 }}>
          <div className="name">{label}</div>
          <div className="role">
            {team === "red" ? "Attacker" : "Defender"} · <span className="mono">{name}</span>
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          <StatusPill tone={s.tone} live={status === "active" && live}>
            {s.label}
          </StatusPill>
        </div>
      </div>

      <div className="stages" aria-label="Progress">
        {stages.map((st) => (
          <div key={st.key} className={`stage ${st.done ? "done" : ""} ${st.active ? "active" : ""}`} title={st.tick !== null ? `${st.label} at tick ${st.tick}` : st.label}>
            <div className="bar" />
            <div className="lbl">
              {st.label}
              {st.tick !== null && <span className="muted"> · T{st.tick}</span>}
            </div>
          </div>
        ))}
      </div>

      <div className="thought" aria-live="polite">
        <div className="th-label">
          <Brain size={12} /> {last ? `Tick ${last.tick} · intent` : "Waiting for first move"}
        </div>
        {last ? (
          <>
            <div className="th-action">
              {ACTION_TEXT[last.kind] || last.kind}
              <span className={last.ok ? "delta-up" : "muted"} style={{ fontWeight: 500 }}>
                {" "}
                · {last.ok ? "succeeded" : "no result"}
              </span>
            </div>
            <div>“{last.rationale || "no rationale given"}”</div>
            <div className="muted mono" style={{ fontSize: 11, marginTop: 3 }}>
              {last.summary}
            </div>
          </>
        ) : (
          <div className="muted">The agent proposes up to 3 actions per tick. The referee validates each one.</div>
        )}
      </div>

      <div>
        <div className="muted" style={{ fontSize: 11, marginBottom: 5 }}>
          Action history (filled = succeeded)
        </div>
        <div className="action-strip">
          {actions.slice(-28).map((a, i) => (
            <span key={i} className={a.ok ? "ok" : "fail"} title={`T${a.tick} ${a.kind}: ${a.summary}`} />
          ))}
          {actions.length === 0 && <span />}
        </div>
      </div>

      <div className="mini-stats">
        <div>
          <b>{actions.length}</b>actions
        </div>
        <div>
          <b>{pct(okRate)}</b>success
        </div>
        <div>
          <b>{techniques}</b>techniques
        </div>
      </div>
    </section>
  );
}

// ------------------------------------------------------------ scoreboard
export function Scoreboard({ st, maxTicks, live }: { st: DerivedState; maxTicks: number; live: boolean }) {
  const o = outcome(st.finished ? st.ended : null, st.flagCaptured);
  const flagTick = st.moments.find((m) => m.kind === "flag")?.tick;
  return (
    <section className="card scoreboard" aria-label="Scoreboard">
      <div className="row between">
        <span className="muted" style={{ fontSize: 12 }}>
          {st.started ? `Tick ${Math.max(0, st.tick)} of ${maxTicks}` : "Not started"}
        </span>
        {st.finished ? (
          <StatusPill tone={o.tone}>{o.label}</StatusPill>
        ) : st.started ? (
          <StatusPill tone="neutral" live={live}>
            {live ? "Live" : "Replay"}
          </StatusPill>
        ) : null}
      </div>
      <div className="vs">
        <div className="side">
          <b style={{ color: "var(--text)" }}>
            <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: "var(--red)", marginRight: 6, verticalAlign: "middle" }} />
            {st.red}
          </b>
          <span>red score</span>
        </div>
        <Gauge value={st.resilience} size={150} />
        <div className="side blue-side">
          <b>
            {st.blue}
            <span style={{ display: "inline-block", width: 8, height: 8, borderRadius: 2, background: "var(--blue)", marginLeft: 6, verticalAlign: "middle" }} />
          </b>
          <span>blue score</span>
        </div>
      </div>
      <div className="tickbar" aria-label="Tick progress">
        {Array.from({ length: maxTicks }, (_, i) => (
          <span
            key={i}
            className={i === flagTick ? "flag" : i === st.tick ? "now" : i < st.tick ? "past" : ""}
            title={`Tick ${i}`}
          />
        ))}
      </div>
      <div className="row between" style={{ fontSize: 12 }}>
        <span className="text-2">
          SLA <b style={{ color: st.slaOk ? "var(--good-text)" : "var(--critical-text)" }}>{st.slaOk ? "healthy" : "failing"}</b>
        </span>
        <span className="text-2">
          Findings <b className="tnum">{st.findings.length}</b>
        </span>
        <span className="text-2">
          Blocked <b className="tnum">{st.blocked.length}</b>
        </span>
      </div>
    </section>
  );
}

// ------------------------------------------------------------ ATT&CK matrix
const MATRIX: { team: "red" | "blue"; tactic: string; techniques: { id: string; name: string }[] }[] = [
  { team: "red", tactic: "Reconnaissance", techniques: [{ id: "T1595", name: "Active Scanning" }, { id: "T1595.003", name: "Wordlist Scanning" }] },
  { team: "red", tactic: "Initial Access", techniques: [{ id: "T1190", name: "Exploit Public-Facing App (detect only)" }] },
  { team: "red", tactic: "Discovery", techniques: [{ id: "T1083", name: "File & Directory Discovery" }] },
  { team: "blue", tactic: "Detection", techniques: [{ id: "DS0015", name: "Application Log" }] },
  { team: "blue", tactic: "Mitigation", techniques: [{ id: "M1037", name: "Filter Network Traffic" }, { id: "M1030", name: "Network Segmentation" }] },
];

export function AttackMatrix({ st }: { st: DerivedState }) {
  const used = new Map(st.techniques.map((t) => [t.id, t]));
  return (
    <div className="killchain">
      {MATRIX.map((col) => (
        <div className="kc-col" key={col.tactic}>
          <h4>
            <span style={{ color: col.team === "red" ? "var(--red)" : "var(--blue)" }}>●</span> {col.tactic}
          </h4>
          <div className="kc-cells">
            {col.techniques.map((t) => {
              const u = used.get(t.id);
              return (
                <div key={t.id} className={`kc-cell ${col.team} ${u ? "on" : ""}`} title={u ? `Used ${u.count}x, first at tick ${u.firstTick}, ${u.ok} succeeded` : "Not used yet"}>
                  {u && <span className="cnt">{u.count}×</span>}
                  <span className="id">{t.id}</span>
                  <span className="nm">{t.name}</span>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ------------------------------------------------------------ event log
type Filter = "key" | "red" | "blue" | "findings" | "traffic" | "all";

function teamColor(team: string, actor: string) {
  if (team === "red" || actor === "red") return "var(--red)";
  if (team === "blue") return "var(--blue)";
  if (actor.startsWith("legit")) return "var(--legit)";
  return "var(--system)";
}

export function EventLog({ events, uptoTick = Infinity, newestFirst = true }: { events: ArenaEvent[]; uptoTick?: number; newestFirst?: boolean }) {
  const [filter, setFilter] = useState<Filter>("key");
  const [q, setQ] = useState("");
  const [sel, setSel] = useState<number | null>(null);

  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    const out = events
      .map((e, i) => ({ e, i }))
      .filter(({ e }) => e.tick <= uptoTick)
      .filter(({ e }) => {
        switch (filter) {
          case "key":
            return ["action", "finding", "rejected", "score", "engagement_start"].includes(e.kind);
          case "red":
            return e.team === "red";
          case "blue":
            return e.team === "blue";
          case "findings":
            return e.kind === "finding";
          case "traffic":
            return e.kind === "request";
          default:
            return e.kind !== "score_tick";
        }
      })
      .filter(({ e }) => !s || (e.summary + " " + e.kind + " " + e.actor + " " + JSON.stringify(e.data)).toLowerCase().includes(s));
    return newestFirst ? out.reverse() : out;
  }, [events, filter, q, uptoTick, newestFirst]);

  const tabs: { id: Filter; label: string }[] = [
    { id: "key", label: "Key events" },
    { id: "red", label: "Red" },
    { id: "blue", label: "Blue" },
    { id: "findings", label: "Findings" },
    { id: "traffic", label: "Traffic" },
    { id: "all", label: "All" },
  ];

  return (
    <section className="card">
      <div className="card-head" style={{ flexWrap: "wrap" }}>
        <h3>Event log</h3>
        <span className="sub">{rows.length} events · click a row for raw data</span>
        <div className="actions" style={{ flexWrap: "wrap" }}>
          <div className="seg" role="group" aria-label="Filter events">
            {tabs.map((t) => (
              <button key={t.id} className={filter === t.id ? "on" : ""} onClick={() => setFilter(t.id)}>
                {t.label}
              </button>
            ))}
          </div>
          <div style={{ position: "relative" }}>
            <Search size={13} style={{ position: "absolute", left: 9, top: 9, color: "var(--muted)" }} />
            <input className="input" style={{ paddingLeft: 28, height: 30, width: 170 }} placeholder="Filter…" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search events" />
          </div>
        </div>
      </div>
      <div className="log" style={{ marginTop: 12 }}>
        {rows.length === 0 && <div className="empty" style={{ padding: 28 }}>No events match.</div>}
        {rows.slice(0, 400).map(({ e, i }) => {
          const tag =
            e.data?.attack_technique ? (
              <span className="tag">{e.data.attack_technique}</span>
            ) : e.kind === "finding" ? (
              <span className="tag">{e.data?.owasp} · {e.data?.severity}</span>
            ) : e.kind === "request" ? (
              <span className="tag">{e.data?.status}</span>
            ) : null;
          return (
            <Fragment key={i}>
              <div className={`log-row ${sel === i ? "sel" : ""}`} onClick={() => setSel(sel === i ? null : i)}>
                <span className="lt">{e.tick >= 0 ? `T${String(e.tick).padStart(2, "0")}` : "pre"}</span>
                <span className="who">
                  <i style={{ background: teamColor(e.team, e.actor) }} />
                  {e.kind === "request" ? e.actor : e.team || "system"}
                </span>
                <span className="msg">
                  <b>{e.kind === "action" ? e.data?.kind : e.kind}</b> {e.kind === "action" ? e.summary.replace(/^[a-z_]+: /, "") : e.summary}
                </span>
                {tag || <span />}
              </div>
              {sel === i && (
                <div className="log-detail">
                  <pre className="mono">{JSON.stringify(e, null, 2)}</pre>
                </div>
              )}
            </Fragment>
          );
        })}
      </div>
    </section>
  );
}

// ------------------------------------------------------------ replay bar
const MOMENT_COLOR: Record<Moment["kind"], string> = {
  finding: "var(--serious)",
  detect: "var(--blue)",
  block: "var(--blue)",
  flag: "var(--critical)",
  kill: "var(--warning)",
  false_block: "var(--warning)",
};

export function ReplayBar({
  tick,
  lastTick,
  playing,
  speed,
  moments,
  onToggle,
  onSeek,
  onStep,
  onSpeed,
  extra,
}: {
  tick: number;
  lastTick: number;
  playing: boolean;
  speed: number;
  moments: Moment[];
  onToggle: () => void;
  onSeek: (t: number) => void;
  onStep: (d: number) => void;
  onSpeed: (s: number) => void;
  extra?: ReactNode;
}) {
  const span = Math.max(1, lastTick + 1);
  const pos = (t: number) => `${((t + 1) / span) * 100}%`;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      const tag = (e.target as HTMLElement)?.tagName;
      if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return;
      if (e.key === " ") {
        e.preventDefault();
        onToggle();
      } else if (e.key === "ArrowRight") onStep(1);
      else if (e.key === "ArrowLeft") onStep(-1);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onToggle, onStep]);

  return (
    <div className="replay" role="group" aria-label="Replay controls">
      <button className="btn ghost sm icon" onClick={() => onSeek(-1)} aria-label="Back to start" title="Start">
        <SkipBack size={14} />
      </button>
      <button className="btn ghost sm icon" onClick={() => onStep(-1)} aria-label="Previous tick" title="Previous tick (←)">
        <ChevronLeft size={15} />
      </button>
      <button className="btn primary sm icon" onClick={onToggle} aria-label={playing ? "Pause" : "Play"} title="Play / pause (space)">
        {playing ? <Pause size={14} /> : <Play size={14} />}
      </button>
      <button className="btn ghost sm icon" onClick={() => onStep(1)} aria-label="Next tick" title="Next tick (→)">
        <ChevronRight size={15} />
      </button>
      <button className="btn ghost sm icon" onClick={() => onSeek(lastTick)} aria-label="Jump to end" title="End">
        <SkipForward size={14} />
      </button>
      <span className="mono nowrap" style={{ fontSize: 12, minWidth: 62 }}>
        {tick < 0 ? "start" : `T${tick} / ${lastTick}`}
      </span>
      <div
        className="scrub"
        onClick={(e) => {
          const r = (e.currentTarget as HTMLDivElement).getBoundingClientRect();
          onSeek(Math.round(((e.clientX - r.left) / r.width) * span) - 1);
        }}
        role="slider"
        aria-valuemin={-1}
        aria-valuemax={lastTick}
        aria-valuenow={tick}
        aria-label="Timeline"
        tabIndex={0}
      >
        <div className="track" />
        <div className="fill" style={{ width: pos(tick) }} />
        {moments.map((m, i) => (
          <span key={i} className="mark" style={{ left: pos(m.tick), background: MOMENT_COLOR[m.kind] }} title={`T${m.tick}: ${m.label}`} />
        ))}
        <div className="knob" style={{ left: pos(tick) }} />
      </div>
      <div className="seg" aria-label="Playback speed">
        {[0.5, 1, 2, 4].map((s) => (
          <button key={s} className={speed === s ? "on" : ""} onClick={() => onSpeed(s)}>
            {s}×
          </button>
        ))}
      </div>
      {extra}
    </div>
  );
}

export function MomentsList({ moments, onPick }: { moments: Moment[]; onPick?: (t: number) => void }) {
  if (!moments.length) return <div className="muted" style={{ fontSize: 12.5 }}>Nothing notable yet.</div>;
  return (
    <div className="stack" style={{ gap: 6 }}>
      {moments.map((m, i) => (
        <button
          key={i}
          className="btn ghost sm"
          style={{ justifyContent: "flex-start", height: "auto", padding: "5px 8px", fontWeight: 500 }}
          onClick={() => onPick?.(m.tick)}
        >
          <span className="mono muted" style={{ width: 30, textAlign: "left" }}>
            T{m.tick}
          </span>
          <span style={{ width: 8, height: 8, borderRadius: 2, background: MOMENT_COLOR[m.kind], flex: "none" }} />
          <span style={{ whiteSpace: "normal", textAlign: "left" }}>{m.label}</span>
        </button>
      ))}
    </div>
  );
}
