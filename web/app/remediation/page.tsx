"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { ClipboardList, Download, ShieldCheck } from "lucide-react";
import { AggregatedFinding, api } from "@/lib/api";
import { useFetch, useLocalState } from "@/lib/hooks";
import { ago, download } from "@/lib/format";
import FindingsTable from "@/components/FindingsTable";
import { BarList, SegBar } from "@/components/charts";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, Stat } from "@/components/ui";

const STATUSES = [
  { id: "open", label: "Open" },
  { id: "in_progress", label: "In progress" },
  { id: "fixed", label: "Fixed" },
  { id: "accepted", label: "Risk accepted" },
] as const;
type Status = (typeof STATUSES)[number]["id"];

const FW: Record<string, string> = { nist_csf: "NIST CSF 2.0", iso27001: "ISO 27001", pci_dss: "PCI DSS 4.0", soc2: "SOC 2" };

export default function RemediationPage() {
  const { data, error, loading, reload } = useFetch(() => api.findings());
  const [statuses, setStatuses] = useLocalState<Record<string, Status>>("sa-remediation", {});
  const [view, setView] = useState<Status | "all">("all");

  const items = data || [];
  const st = (f: AggregatedFinding) => statuses[f.rule_id] || "open";
  const shown = items.filter((f) => view === "all" || st(f) === view);
  const count = (s: Status) => items.filter((f) => st(f) === s).length;
  const closed = count("fixed") + count("accepted");

  const controls = useMemo(() => {
    const m = new Map<string, number>();
    items.filter((f) => st(f) !== "fixed").forEach((f) =>
      Object.entries(f.controls || {}).forEach(([fw, ids]) => (ids as string[]).forEach((id) => m.set(`${FW[fw]} ${id}`, (m.get(`${FW[fw]} ${id}`) || 0) + 1)))
    );
    return Array.from(m.entries()).map(([label, value]) => ({ label, value })).sort((a, b) => b.value - a.value).slice(0, 8);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [items, statuses]);

  const exportCsv = () => {
    const cols = ["rule_id", "title", "severity", "priority", "status", "owasp", "cwe", "occurrences", "first_seen", "last_seen", "fix_sla_days", "mitigation"];
    const esc = (v: unknown) => `"${String(v ?? "").replace(/"/g, '""')}"`;
    const lines = [cols.join(",")].concat(
      items.map((f) => [f.rule_id, f.title, f.severity, f.priority, st(f), f.owasp, f.cwe.join(" "), f.occurrences, f.first_seen, f.last_seen, f.fix_sla_days, f.mitigation].map(esc).join(","))
    );
    download("remediation-backlog.csv", lines.join("\n"), "text/csv");
  };

  return (
    <>
      <PageHead
        title="Remediation"
        sub="Every weakness found across all runs, de-duplicated by rule and ranked by risk. Track each to closure. Status is saved in this browser."
        actions={<button className="btn" onClick={exportCsv} disabled={!items.length}><Download size={14} /> Export backlog</button>}
      />
      {error && <ErrorBanner error={error} onRetry={reload} />}
      {loading && !data ? (
        <Skeleton h={300} />
      ) : !items.length ? (
        <Card bodyClass="">
          <Empty icon={<ShieldCheck size={20} />} title="Nothing to fix yet" action={<Link className="btn primary" href="/arena?red=scripted&blue=noop">Run a full weakness scan</Link>}>
            Findings appear once the attacker gets far enough to run its checks. A run against the passive defender inventories every planted weakness.
          </Empty>
        </Card>
      ) : (
        <div className="stack">
          <div className="grid g4">
            <Stat label="Open" value={count("open") + count("in_progress")} tone={count("open") ? "warning" : "good"} foot={`${count("in_progress")} in progress`} />
            <Stat label="P1 still open" value={items.filter((f) => f.priority === "P1" && !["fixed", "accepted"].includes(st(f))).length} tone="critical" foot="fix within 7 days" />
            <Stat label="Closed" value={`${Math.round((closed / items.length) * 100)}%`} foot={`${count("fixed")} fixed · ${count("accepted")} accepted`} />
            <Card title="Progress">
              <SegBar parts={[
                { label: "Open", value: count("open"), color: "var(--critical)" },
                { label: "In progress", value: count("in_progress"), color: "var(--warning)" },
                { label: "Fixed", value: count("fixed"), color: "var(--good)" },
                { label: "Accepted", value: count("accepted"), color: "var(--system)" },
              ]} />
            </Card>
          </div>

          <div className="grid split-c">
            <Card
              title="Backlog"
              bodyClass=""
              actions={
                <div className="seg">
                  <button className={view === "all" ? "on" : ""} onClick={() => setView("all")}>All</button>
                  {STATUSES.map((s) => (
                    <button key={s.id} className={view === s.id ? "on" : ""} onClick={() => setView(s.id)}>
                      {s.label} {count(s.id)}
                    </button>
                  ))}
                </div>
              }
            >
              <div style={{ paddingTop: 12 }}>
                {shown.length ? (
                  <FindingsTable
                    findings={shown}
                    extraCols={[
                      { head: "Seen", cell: (f) => <span className="text-2 nowrap" title={`first ${f.first_seen}`}>{f.occurrences}× · {ago(f.last_seen)}</span> },
                      {
                        head: "Status",
                        cell: (f) => (
                          <select className="input" style={{ height: 28, fontSize: 12 }} value={st(f)} onChange={(e) => setStatuses((s) => ({ ...s, [f.rule_id]: e.target.value as Status }))} aria-label={`Status of ${f.title}`}>
                            {STATUSES.map((s) => <option key={s.id} value={s.id}>{s.label}</option>)}
                          </select>
                        ),
                      },
                    ]}
                  />
                ) : (
                  <Empty icon={<ClipboardList size={20} />} title="Nothing in this view" />
                )}
              </div>
            </Card>
            <Card title="Controls affected" sub="Unfixed findings per framework control (indicative)">
              <BarList rows={controls} color="var(--blue)" />
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
