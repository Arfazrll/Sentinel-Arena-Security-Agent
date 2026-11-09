"use client";

import Link from "next/link";
import { FlaskConical, HeartPulse, Shuffle, Swords, Timer } from "lucide-react";
import { api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { Card, Empty, ErrorBanner, PageHead, Sev, Skeleton } from "@/components/ui";
import { SegBar } from "@/components/charts";

export default function ScenariosPage() {
  const { data, error, loading, reload } = useFetch(() => api.scenarios());
  return (
    <>
      <PageHead title="Scenarios" sub="Targets the agents fight over. Each is a self-hosted app with planted, non-destructive weaknesses and a hidden flag. Paths and secrets change with every seed." />
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {loading && <Skeleton h={260} />}
      {data?.length === 0 && <Empty icon={<FlaskConical size={20} />} title="No scenarios found" />}
      <div className="stack">
        {data?.map((s) => {
          const c = (x: string) => s.weaknesses.filter((w) => w.severity === x).length;
          return (
            <Card
              key={s.id}
              title={<span style={{ fontSize: 16 }}>{s.name}</span>}
              sub={<span className="mono">{s.id}</span>}
              actions={
                <Link className="btn primary" href={`/arena?scenario=${s.id}`}>
                  <Swords size={14} /> Launch
                </Link>
              }
            >
              <p className="text-2" style={{ marginTop: 0, maxWidth: "80ch" }}>{s.description}</p>
              <div className="grid g4" style={{ marginBottom: 16 }}>
                <div className="card flat stat"><div className="label"><Timer size={13} /> Tick budget</div><div className="value" style={{ fontSize: 20 }}>{s.max_ticks}</div></div>
                <div className="card flat stat"><div className="label"><Shuffle size={13} /> Randomized per seed</div><div className="value" style={{ fontSize: 14, fontWeight: 550 }}>{s.randomize.join(", ") || "nothing"}</div></div>
                <div className="card flat stat"><div className="label"><HeartPulse size={13} /> SLA health check</div><div className="value mono" style={{ fontSize: 14 }}>{s.health_path}</div></div>
                <div className="card flat stat">
                  <div className="label">Weakness severity</div>
                  <SegBar parts={[
                    { label: "High", value: c("high") + c("critical"), color: "var(--serious)" },
                    { label: "Medium", value: c("medium"), color: "var(--warning)" },
                    { label: "Low", value: c("low"), color: "var(--blue)" },
                  ]} />
                </div>
              </div>
              <div className="table-wrap">
                <table className="table">
                  <thead><tr><th>Planted weakness</th><th>Severity</th><th>OWASP</th><th>Detected by</th><th>Fix</th></tr></thead>
                  <tbody>
                    {s.weaknesses.map((w) => (
                      <tr key={w.id}>
                        <td style={{ fontWeight: 550 }}>{w.title}</td>
                        <td><Sev s={w.severity} /></td>
                        <td><span className="tag">{w.owasp}</span></td>
                        <td className="mono muted">{w.detect}</td>
                        <td className="text-2" style={{ fontSize: 12.5, maxWidth: 420 }}>{w.mitigation}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Card>
          );
        })}
      </div>
    </>
  );
}
