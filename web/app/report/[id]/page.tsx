"use client";

import { useEffect, useState } from "react";
import { fetchResult, reportUrl } from "@/lib/api";

type Finding = {
  owasp: string;
  severity: string;
  title: string;
  description: string;
  evidence: string;
  mitigation: string;
};

export default function ReportPage({ params }: { params: { id: string } }) {
  const [data, setData] = useState<any>(null);
  const [error, setError] = useState("");

  useEffect(() => {
    let tries = 0;
    const tick = async () => {
      try {
        const d = await fetchResult(params.id);
        setData(d);
      } catch {
        if (tries++ < 20) setTimeout(tick, 500);
        else setError("report not available");
      }
    };
    tick();
  }, [params.id]);

  if (error) return <div className="wrap">{error}</div>;
  if (!data) return <div className="wrap">Loading report…</div>;

  const sb = data.scoreboard;
  const res = sb.resilience;
  const resColor =
    res >= 70 ? "var(--green)" : res >= 40 ? "var(--amber)" : "var(--red)";
  const findings: Finding[] = data.findings || [];

  return (
    <div className="wrap">
      <h1>Resilience Audit — {data.scenario}</h1>
      <div className="sub">
        seed {data.seed} · outcome <b>{data.ended}</b> · {data.ticks_run} ticks ·{" "}
        <a href={reportUrl(params.id)} target="_blank" rel="noreferrer">
          full HTML report ↗
        </a>
      </div>

      <div className="score">
        <div>
          <div className="dial" style={{ color: resColor }}>
            {res}
          </div>
          <div className="stat">resilience / 100</div>
        </div>
        <div className="stat">
          <b>{sb.red.total}</b>red
        </div>
        <div className="stat">
          <b>{sb.blue.total}</b>blue
        </div>
        <div className="stat">
          <b>{sb.red.flag_captured ? "captured" : "held"}</b>flag
        </div>
        <div className="stat">
          <b>{Math.round(sb.blue.sla_uptime * 100)}%</b>uptime
        </div>
        <div className="stat">
          <b>{Math.round(sb.blue.legit_availability * 100)}%</b>legit availability
        </div>
      </div>

      <h2 style={{ fontSize: "1.1rem", marginTop: 24 }}>
        Findings — OWASP Top 10 (2021)
      </h2>
      <table>
        <thead>
          <tr>
            <th>OWASP</th>
            <th>Severity</th>
            <th>Finding</th>
            <th>Mitigation</th>
          </tr>
        </thead>
        <tbody>
          {findings.length === 0 && (
            <tr>
              <td colSpan={4}>No findings recorded.</td>
            </tr>
          )}
          {findings.map((f, i) => (
            <tr key={i}>
              <td>{f.owasp}</td>
              <td>
                <span className={`sev sev-${f.severity}`}>
                  {f.severity.toUpperCase()}
                </span>
              </td>
              <td>
                <b>{f.title}</b>
                <br />
                <small style={{ color: "var(--muted)" }}>{f.evidence}</small>
              </td>
              <td>{f.mitigation}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
