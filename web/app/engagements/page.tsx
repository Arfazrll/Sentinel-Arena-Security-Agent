"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { ArrowDown, ArrowUp, Download, GitCompare, History, Search, Swords } from "lucide-react";
import { EngagementSummary, api } from "@/lib/api";
import { useFetch } from "@/lib/hooks";
import { ago, download, outcome } from "@/lib/format";
import { Card, Empty, ErrorBanner, PageHead, Skeleton, StatusPill } from "@/components/ui";

type SortKey = "created_at" | "resilience" | "findings" | "time_to_detect";

export default function EngagementsPage() {
  const router = useRouter();
  const { data, error, loading, reload } = useFetch(() => api.engagements());
  const [q, setQ] = useState("");
  const [result, setResult] = useState<"all" | "defended" | "breached" | "stopped">("all");
  const [sort, setSort] = useState<{ key: SortKey; dir: 1 | -1 }>({ key: "created_at", dir: -1 });
  const [sel, setSel] = useState<string[]>([]);

  const rows = useMemo(() => {
    const s = q.trim().toLowerCase();
    const val = (e: EngagementSummary, k: SortKey): number | string =>
      k === "created_at" ? e.created_at || "" : k === "resilience" ? e.result?.resilience ?? -1 : k === "findings" ? e.findings ?? -1 : e.time_to_detect ?? 999;
    return (data || [])
      .filter((e) => !s || [e.id, e.scenario, e.scenario_name, e.red, e.blue, e.red_label, e.blue_label, String(e.seed)].join(" ").toLowerCase().includes(s))
      .filter((e) => {
        if (result === "all") return true;
        const o = outcome(e.result?.ended, e.result?.flag_captured).label;
        return result === "defended" ? o === "Defended" : result === "breached" ? o === "Flag captured" : o === "Stopped";
      })
      .sort((a, b) => {
        const x = val(a, sort.key);
        const y = val(b, sort.key);
        return (x > y ? 1 : x < y ? -1 : 0) * sort.dir;
      });
  }, [data, q, result, sort]);

  const toggle = (id: string) => setSel((s) => (s.includes(id) ? s.filter((x) => x !== id) : [...s.slice(-1), id]));
  const head = (k: SortKey, label: string, num = false) => (
    <th className={`sortable ${num ? "num" : ""}`} onClick={() => setSort((s) => ({ key: k, dir: s.key === k ? (s.dir === 1 ? -1 : 1) : -1 }))}>
      {label} {sort.key === k && (sort.dir === 1 ? <ArrowUp size={11} /> : <ArrowDown size={11} />)}
    </th>
  );

  const exportCsv = () => {
    const cols = ["id", "created_at", "scenario", "seed", "red", "blue", "status", "resilience", "flag_captured", "findings", "time_to_detect", "time_to_contain", "false_blocks"];
    const lines = [cols.join(",")].concat(
      rows.map((e) =>
        [e.id, e.created_at, e.scenario, e.seed, e.red, e.blue, e.status, e.result?.resilience ?? "", e.result?.flag_captured ?? "", e.findings ?? "", e.time_to_detect ?? "", e.time_to_contain ?? "", e.false_blocks ?? ""].join(",")
      )
    );
    download("engagements.csv", lines.join("\n"), "text/csv");
  };

  return (
    <>
      <PageHead
        title="Engagements"
        sub="Every run is kept with its event log, scores and audit trail. Select two runs to compare them."
        actions={
          <>
            <button className="btn" onClick={exportCsv} disabled={!rows.length}>
              <Download size={14} /> CSV
            </button>
            <button className="btn" disabled={sel.length !== 2} onClick={() => router.push(`/compare?a=${sel[0]}&b=${sel[1]}`)}>
              <GitCompare size={14} /> Compare {sel.length ? `(${sel.length}/2)` : ""}
            </button>
          </>
        }
      />
      {error && <ErrorBanner error={error} onRetry={reload} />}
      <Card bodyClass="">
        <div className="row" style={{ padding: "14px 16px" }}>
          <div style={{ position: "relative" }}>
            <Search size={13} style={{ position: "absolute", left: 9, top: 10, color: "var(--muted)" }} />
            <input className="input" placeholder="Search by agent, seed, id…" value={q} onChange={(e) => setQ(e.target.value)} style={{ paddingLeft: 28, width: 260 }} aria-label="Search engagements" />
          </div>
          {(["all", "defended", "breached", "stopped"] as const).map((r) => (
            <button key={r} className={`chip ${result === r ? "on" : ""}`} onClick={() => setResult(r)}>
              {r === "all" ? "All outcomes" : r === "defended" ? "Defended" : r === "breached" ? "Flag captured" : "Stopped"}
            </button>
          ))}
          <span className="muted" style={{ marginLeft: "auto", fontSize: 12 }}>
            {rows.length} of {data?.length ?? 0}
          </span>
        </div>
        {loading && !data ? (
          <div style={{ padding: 16 }}><Skeleton h={180} /></div>
        ) : rows.length === 0 ? (
          <Empty icon={<History size={20} />} title={data?.length ? "No engagements match" : "No engagements yet"} action={<Link href="/arena" className="btn primary"><Swords size={14} /> Run your first engagement</Link>}>
            {data?.length ? "Try a different search or outcome filter." : "Launch a red-vs-blue run in the arena. It will show up here with its full replay."}
          </Empty>
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th style={{ width: 34 }}><span className="sr-only">Select</span></th>
                  {head("created_at", "When")}
                  <th>Matchup</th>
                  <th>Outcome</th>
                  {head("resilience", "Resilience", true)}
                  {head("findings", "Findings", true)}
                  {head("time_to_detect", "Detect", true)}
                  <th className="num">Contain</th>
                  <th className="num">False blocks</th>
                  <th>Seed</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((e) => {
                  const o = e.status === "running" ? { label: "Running", tone: "neutral" as const } : outcome(e.result?.ended, e.result?.flag_captured);
                  const r = e.result?.resilience;
                  return (
                    <tr key={e.id} className={`clickable ${sel.includes(e.id) ? "selected" : ""}`} onClick={() => router.push(e.status === "running" ? `/arena?id=${e.id}` : `/engagements/${e.id}`)}>
                      <td onClick={(ev) => ev.stopPropagation()}>
                        <input type="checkbox" checked={sel.includes(e.id)} onChange={() => toggle(e.id)} aria-label={`Select ${e.id}`} disabled={e.status === "running"} />
                      </td>
                      <td className="nowrap" title={e.created_at}>{ago(e.created_at)}</td>
                      <td>
                        <div style={{ fontWeight: 550 }}>
                          <span style={{ color: "var(--red)" }}>●</span> {e.red_label || e.red} <span className="muted">vs</span> <span style={{ color: "var(--blue)" }}>●</span> {e.blue_label || e.blue}
                        </div>
                        <div className="muted" style={{ fontSize: 11.5 }}>{e.scenario_name || e.scenario} · <span className="mono">{e.id}</span></div>
                      </td>
                      <td><StatusPill tone={o.tone} live={e.status === "running"}>{o.label}</StatusPill></td>
                      <td className="num">
                        <b style={{ color: r === undefined ? undefined : r >= 70 ? "var(--good-text)" : r >= 40 ? "var(--warning)" : "var(--critical-text)" }}>{r ?? "—"}</b>
                      </td>
                      <td className="num">{e.findings ?? "—"}</td>
                      <td className="num">{e.time_to_detect ?? "—"}</td>
                      <td className="num">{e.time_to_contain ?? "—"}</td>
                      <td className="num">{e.false_blocks ?? "—"}</td>
                      <td className="mono muted">{e.seed}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </Card>
    </>
  );
}
