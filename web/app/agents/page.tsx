"use client";

import Link from "next/link";
import { Crosshair, KeyRound, ShieldHalf, Swords } from "lucide-react";
import { AgentInfo, api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { Card, ErrorBanner, PageHead, Skeleton, StatusPill } from "@/components/ui";

function AgentTile({ a }: { a: AgentInfo }) {
  const red = a.team === "red";
  return (
    <section className={`card agent-card ${a.team}`}>
      <div className="agent-id">
        <div className="avatar">{red ? <Crosshair size={18} /> : <ShieldHalf size={18} />}</div>
        <div>
          <div className="name">{a.label}</div>
          <div className="role">
            {red ? "Attacker" : "Defender"} · <span className="mono">{a.name}</span> · {a.kind}
          </div>
        </div>
        <div style={{ marginLeft: "auto" }}>
          {a.available ? <StatusPill tone="good">Ready</StatusPill> : <StatusPill tone="warning">Needs API key</StatusPill>}
        </div>
      </div>
      <div className="text-2" style={{ fontSize: 13 }}>{a.description}</div>
      <div>
        <div className="field-label">Strategy</div>
        <div className="row" style={{ gap: 4 }}>
          {a.strategy.map((s, i) => (
            <span key={i} className="row" style={{ gap: 4 }}>
              {i > 0 && <span className="muted">→</span>}
              <span className="tag">{s}</span>
            </span>
          ))}
        </div>
      </div>
      <div>
        <div className="field-label">Allowed actions (enforced by the referee)</div>
        <div className="row" style={{ gap: 4 }}>
          {a.actions.map((x) => <span key={x} className="tag" style={{ opacity: 0.8 }}>{x}</span>)}
        </div>
      </div>
      <div className="row" style={{ marginTop: "auto" }}>
        {a.available ? (
          <Link className="btn sm" href={red ? `/arena?red=${a.name}` : `/arena?blue=${a.name}`}>
            <Swords size={13} /> Use in arena
          </Link>
        ) : (
          <span className="muted row" style={{ fontSize: 12, gap: 6 }}>
            <KeyRound size={13} /> Set <code>ANTHROPIC_API_KEY</code> on the API server
          </span>
        )}
        {!a.benchmark && <span className="muted" style={{ fontSize: 12 }}>Not in the default benchmark</span>}
      </div>
    </section>
  );
}

export default function AgentsPage() {
  const { data, error, loading, reload } = useFetch(() => api.agents());
  return (
    <>
      <PageHead
        title="Agents"
        sub="Agents only propose actions. The referee validates each one against a fixed vocabulary: red has no destructive verbs, and blue has a defensive whitelist with no shell. Bring your own agent by adding one registry entry."
      />
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {loading && <Skeleton h={300} />}
      {data && (
        <div className="stack">
          <Card title={<span className="row" style={{ gap: 6 }}><Crosshair size={14} color="var(--red)" /> Red team</span>} sub="Attackers: non-destructive detection set, through the authorization gate">
            <div className="grid g3">{data.filter((a) => a.team === "red").map((a) => <AgentTile key={a.name} a={a} />)}</div>
          </Card>
          <Card title={<span className="row" style={{ gap: 6 }}><ShieldHalf size={14} color="var(--blue)" /> Blue team</span>} sub="Defenders: scored on fast, accurate detection without blocking real users">
            <div className="grid g3">{data.filter((a) => a.team === "blue").map((a) => <AgentTile key={a.name} a={a} />)}</div>
          </Card>
          <Card title="Add your own agent">
            <pre className="mono" style={{ margin: 0, fontSize: 12, color: "var(--text-2)", whiteSpace: "pre-wrap" }}>{`# sentinel_arena/agents/registry.py
BLUE["mine"] = AgentSpec(
    name="mine", team="blue", label="My defender", kind="scripted",
    description="What it does", strategy=["query_logs", "block_ip"],
    factory=MyBlue,          # any class with propose(ctx) -> list[Action]
)`}</pre>
          </Card>
        </div>
      )}
    </>
  );
}
