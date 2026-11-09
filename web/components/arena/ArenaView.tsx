"use client";

import dynamic from "next/dynamic";
import type { ArenaEvent } from "@/lib/api";
import type { DerivedState } from "@/lib/derive";
import { Card } from "@/components/ui";
import { LineChart, StackedColumns } from "@/components/charts";
import { AgentCard, AttackMatrix, EventLog, MomentsList, Scoreboard } from "./panels";

const AttackGraph = dynamic(() => import("./AttackGraph"), {
  ssr: false,
  loading: () => <div className="graph-box skeleton" />,
});

export default function ArenaView({
  st,
  events,
  maxTicks,
  red,
  blue,
  live,
  onPickTick,
}: {
  st: DerivedState;
  events: ArenaEvent[];
  maxTicks: number;
  red: { name: string; label: string };
  blue: { name: string; label: string };
  live: boolean;
  onPickTick?: (t: number) => void;
}) {
  const scoreData = st.series.map((p) => ({ x: p.tick, red: p.red, blue: p.blue }));
  const resData = st.series.map((p) => ({ x: p.tick, resilience: p.resilience }));
  const traffic = st.traffic.map((r) => ({
    x: r.tick,
    legit: r.legit_ok,
    red: r.red_ok,
    blocked: r.red_blocked + r.legit_blocked,
    system: r.system,
  }));
  const markers = st.moments
    .filter((m) => m.kind === "flag" || m.kind === "block" || m.kind === "detect")
    .map((m) => ({
      x: m.tick,
      color: m.kind === "flag" ? "var(--critical)" : "var(--blue)",
      label: `T${m.tick} ${m.label}`,
    }));

  return (
    <div className="stack">
      <div className="arena-grid">
        <AgentCard team="red" label={red.label} name={red.name} status={st.redStatus} actions={st.red_actions} stages={st.redStages} tick={st.tick} live={live} />
        <Scoreboard st={st} maxTicks={maxTicks} live={live} />
        <AgentCard team="blue" label={blue.label} name={blue.name} status={st.blueStatus} actions={st.blue_actions} stages={st.blueStages} tick={st.tick} live={live} />
      </div>

      <Card
        title="Attack surface"
        sub="Every request the red agent makes lights its path. Drag nodes to rearrange."
        bodyClass=""
        actions={
          <div className="graph-legend">
            <span><i style={{ borderColor: "var(--red)" }} />probed</span>
            <span><i style={{ borderColor: "var(--serious)" }} />weakness</span>
            <span><i style={{ borderColor: "var(--blue)" }} />blocked</span>
            <span><i style={{ borderColor: "var(--critical)", background: "var(--critical)" }} />breached</span>
          </div>
        }
      >
        <AttackGraph st={st} redLabel={red.label} blueLabel={blue.label} />
      </Card>
      <div className="grid g3">
        <Card
          title="Score over time"
          sub="Red earns for progress, blue for fast, accurate defense"
          table={
            <table className="table">
              <thead><tr><th>Tick</th><th className="num">Red</th><th className="num">Blue</th></tr></thead>
              <tbody>{scoreData.map((d) => <tr key={d.x}><td>T{d.x}</td><td className="num">{d.red}</td><td className="num">{d.blue}</td></tr>)}</tbody>
            </table>
          }
        >
          <LineChart
            data={scoreData}
            xDomain={[0, maxTicks - 1]}
            series={[
              { key: "red", label: "Red score", color: "var(--red)" },
              { key: "blue", label: "Blue score", color: "var(--blue)" },
            ]}
            markers={markers}
            height={190}
          />
        </Card>
        <Card
          title="Resilience"
          sub="0-100. Above 70 is resilient, below 40 is breached"
          table={
            <table className="table">
              <thead><tr><th>Tick</th><th className="num">Resilience</th></tr></thead>
              <tbody>{resData.map((d) => <tr key={d.x}><td>T{d.x}</td><td className="num">{d.resilience}</td></tr>)}</tbody>
            </table>
          }
        >
          <LineChart
            data={resData}
            xDomain={[0, maxTicks - 1]}
            yMax={100}
            series={[{ key: "resilience", label: "Resilience", color: "var(--blue)" }]}
            area
            height={214}
          />
        </Card>
        <Card
          title="Traffic per tick"
          sub="Real users must keep getting through"
          table={
            <table className="table">
              <thead><tr><th>Tick</th><th className="num">Users</th><th className="num">Red</th><th className="num">Blocked</th><th className="num">Health</th></tr></thead>
              <tbody>{traffic.map((d) => <tr key={d.x}><td>T{d.x}</td><td className="num">{d.legit}</td><td className="num">{d.red}</td><td className="num">{d.blocked}</td><td className="num">{d.system}</td></tr>)}</tbody>
            </table>
          }
        >
          <StackedColumns
            data={traffic}
            slots={maxTicks}
            series={[
              { key: "legit", label: "Users", color: "var(--legit)" },
              { key: "red", label: "Red allowed", color: "var(--red)" },
              { key: "blocked", label: "Blocked (403)", color: "var(--blue)" },
              { key: "system", label: "Health checks", color: "var(--system)" },
            ]}
            height={190}
          />
        </Card>
      </div>

      <div className="grid g2">
        <Card title="MITRE ATT&CK coverage" sub="Techniques used so far, by tactic">
          <AttackMatrix st={st} />
        </Card>
        <Card title="Key moments" sub={onPickTick ? "Click to jump" : "Detections, blocks, findings and the flag"}>
          <MomentsList moments={st.moments} onPick={onPickTick} />
        </Card>
      </div>

      <EventLog events={events} uptoTick={live ? Infinity : st.tick} />
    </div>
  );
}
