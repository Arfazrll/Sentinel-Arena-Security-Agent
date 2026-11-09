"use client";

// "Why this score": the resilience formula from engine/scoring.py, term by
// term, so a run is explainable rather than a magic number.

import type { EngagementResult } from "@/lib/api";

export function resilienceTerms(r: EngagementResult) {
  const b = r.scoreboard.blue;
  const red = r.scoreboard.red;
  const highs = r.findings.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const terms = [
    { label: "Starting point", value: 50, note: "every run starts neutral" },
    { label: "Service uptime", value: 12 * b.sla_uptime, note: `${Math.round(b.sla_uptime * 100)}% of health checks passed` },
    { label: "Real users served", value: 8 * b.legit_availability, note: `${Math.round(b.legit_availability * 100)}% of legitimate requests succeeded` },
    { label: "Attacker blocked before flag", value: b.blocked_attacker_before_flag ? 15 : 0, note: b.blocked_attacker_before_flag ? "contained in time" : "not contained in time" },
    { label: "Correct detections", value: Math.min(10, 3 * b.true_positive_detections), note: `${b.true_positive_detections} true positive(s)` },
    { label: "Flag captured", value: red.flag_captured ? -30 : 0, note: red.flag_captured ? "the attacker reached the objective" : "objective protected" },
    { label: "High/critical findings", value: -5 * highs, note: `${highs} found` },
    { label: "Real users blocked", value: -3 * b.false_blocks, note: `${b.false_blocks} false block(s)` },
  ];
  const raw = terms.reduce((a, t) => a + t.value, 0);
  return { terms, raw, final: r.scoreboard.resilience };
}

export default function ScoreExplainer({ result }: { result: EngagementResult }) {
  const { terms, raw, final } = resilienceTerms(result);
  const max = 50;
  return (
    <div>
      {terms.map((t) => {
        const w = (Math.abs(t.value) / max) * 50;
        const pos = t.value >= 0;
        return (
          <div className="wf-row" key={t.label} title={t.note}>
            <div>
              <div style={{ fontWeight: 550 }}>{t.label}</div>
              <div className="muted" style={{ fontSize: 11.5 }}>{t.note}</div>
            </div>
            <div className="wf-track" aria-hidden>
              <span className="wf-zero" style={{ left: "50%" }} />
              {t.value !== 0 && (
                <span
                  className="wf-bar"
                  style={{
                    left: pos ? "50%" : `${50 - w}%`,
                    width: `${w}%`,
                    background: pos ? "var(--good)" : "var(--critical)",
                    borderRadius: pos ? "0 3px 3px 0" : "3px 0 0 3px",
                  }}
                />
              )}
            </div>
            <div className="tnum" style={{ textAlign: "right", fontWeight: 600, color: t.value > 0 ? "var(--good-text)" : t.value < 0 ? "var(--critical-text)" : "var(--muted)" }}>
              {t.value > 0 ? "+" : ""}
              {Math.round(t.value * 10) / 10}
            </div>
          </div>
        );
      })}
      <div className="divider" />
      <div className="row between">
        <span className="text-2">
          Sum {Math.round(raw)} → clamped to 0–100
        </span>
        <span style={{ fontSize: 20, fontWeight: 650 }}>{final}</span>
      </div>
    </div>
  );
}
