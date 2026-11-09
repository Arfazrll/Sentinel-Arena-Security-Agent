"use client";

import { Fragment, ReactNode, useMemo, useState } from "react";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Finding, Severity } from "@/lib/api";
import { Sev } from "@/components/ui";
import { SEVERITY_ORDER } from "@/lib/format";

const FW_LABEL: Record<string, string> = {
  nist_csf: "NIST CSF 2.0",
  iso27001: "ISO 27001:2022",
  pci_dss: "PCI DSS 4.0",
  soc2: "SOC 2",
};

export function ControlTags({ f }: { f: Finding }) {
  return (
    <div className="kv" style={{ gridTemplateColumns: "120px 1fr", gap: "6px 12px" }}>
      {Object.entries(f.controls || {}).map(([k, v]) => (
        <Fragment key={k}>
          <dt>{FW_LABEL[k] || k}</dt>
          <dd className="row" style={{ gap: 4 }}>
            {(v as string[]).map((c) => (
              <span className="tag" key={c}>
                {c}
              </span>
            ))}
          </dd>
        </Fragment>
      ))}
    </div>
  );
}

export default function FindingsTable<T extends Finding>({
  findings,
  extraCols = [],
}: {
  findings: T[];
  extraCols?: { head: string; cell: (f: T) => ReactNode; className?: string }[];
}) {
  const [open, setOpen] = useState<string | null>(null);
  const [sevFilter, setSevFilter] = useState<Severity | "all">("all");
  const sorted = useMemo(
    () =>
      [...findings]
        .filter((f) => sevFilter === "all" || f.severity === sevFilter)
        .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity)),
    [findings, sevFilter]
  );
  const present = SEVERITY_ORDER.filter((s) => findings.some((f) => f.severity === s));

  return (
    <div>
      {present.length > 1 && (
        <div className="row" style={{ padding: "0 16px 12px" }}>
          <button className={`chip ${sevFilter === "all" ? "on" : ""}`} onClick={() => setSevFilter("all")}>
            All {findings.length}
          </button>
          {present.map((s) => (
            <button key={s} className={`chip ${sevFilter === s ? "on" : ""}`} onClick={() => setSevFilter(s)}>
              <Sev s={s} /> {findings.filter((f) => f.severity === s).length}
            </button>
          ))}
        </div>
      )}
      <div className="table-wrap">
        <table className="table">
          <thead>
            <tr>
              <th style={{ width: 28 }} />
              <th>Finding</th>
              <th>Severity</th>
              <th>Priority</th>
              <th>OWASP</th>
              <th>CWE</th>
              {extraCols.map((c) => (
                <th key={c.head} className={c.className}>
                  {c.head}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sorted.map((f) => {
              const key = f.rule_id + f.id;
              const isOpen = open === key;
              return (
                <Fragment key={key}>
                  <tr className="clickable" onClick={() => setOpen(isOpen ? null : key)} aria-expanded={isOpen}>
                    <td>{isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}</td>
                    <td>
                      <div style={{ fontWeight: 550 }}>{f.title}</div>
                      <div className="muted mono" style={{ fontSize: 11 }}>
                        {f.rule_id}
                      </div>
                    </td>
                    <td>
                      <Sev s={f.severity} />
                      <div className="muted" style={{ fontSize: 11 }}>CVSS {f.cvss_band}</div>
                    </td>
                    <td>
                      <span className={`prio ${f.priority}`}>{f.priority}</span>
                      <div className="muted" style={{ fontSize: 11 }}>fix in {f.fix_sla_days}d</div>
                    </td>
                    <td>
                      <span className="tag">{f.owasp}</span> <span className="text-2" style={{ fontSize: 12 }}>{f.owasp_title}</span>
                    </td>
                    <td>
                      <div className="row" style={{ gap: 4 }}>
                        {f.cwe?.map((c) => (
                          <a
                            key={c}
                            className="tag"
                            href={`https://cwe.mitre.org/data/definitions/${c.replace("CWE-", "")}.html`}
                            target="_blank"
                            rel="noreferrer"
                            onClick={(e) => e.stopPropagation()}
                          >
                            {c}
                          </a>
                        ))}
                      </div>
                    </td>
                    {extraCols.map((c) => (
                      <td key={c.head} className={c.className} onClick={(e) => e.stopPropagation()}>
                        {c.cell(f)}
                      </td>
                    ))}
                  </tr>
                  {isOpen && (
                    <tr className="details-row">
                      <td />
                      <td colSpan={5 + extraCols.length}>
                        <div className="grid g2" style={{ gap: 18, padding: "6px 0 8px" }}>
                          <div className="stack" style={{ gap: 10 }}>
                            <div>
                              <div className="field-label">What we observed</div>
                              <div className="text-2">{f.description}</div>
                            </div>
                            <div>
                              <div className="field-label">Evidence</div>
                              <code style={{ display: "block", whiteSpace: "pre-wrap", color: "var(--text-2)" }}>{f.evidence}</code>
                              {f.url && <div className="muted mono" style={{ fontSize: 11, marginTop: 4 }}>{f.url}</div>}
                            </div>
                            <div>
                              <div className="field-label">How to fix</div>
                              <div>{f.mitigation}</div>
                              <div className="muted" style={{ fontSize: 12, marginTop: 4 }}>
                                Estimated effort: {f.effort === "S" ? "small (under a day)" : f.effort === "M" ? "medium (1-3 days)" : "large"}
                              </div>
                            </div>
                          </div>
                          <div>
                            <div className="field-label">Compliance mapping (indicative)</div>
                            <ControlTags f={f} />
                            <div className="muted" style={{ fontSize: 11.5, marginTop: 10 }}>
                              Mappings show where this most likely lands in each framework. Confirm with your auditor.
                            </div>
                          </div>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}
