import type { Severity } from "./api";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function pct(x: number | null | undefined, digits = 0): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return `${(x * 100).toFixed(digits)}%`;
}

export function num(x: number | null | undefined, digits = 0): string {
  if (x === null || x === undefined || Number.isNaN(x)) return "—";
  return x.toLocaleString(undefined, { maximumFractionDigits: digits, minimumFractionDigits: 0 });
}

export function ticks(x: number | null | undefined): string {
  if (x === null || x === undefined) return "—";
  return `${x} ${x === 1 ? "tick" : "ticks"}`;
}

export function ago(iso?: string | null): string {
  if (!iso) return "—";
  const s = (Date.now() - new Date(iso).getTime()) / 1000;
  if (s < 45) return "just now";
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  if (s < 86400) return `${Math.round(s / 3600)}h ago`;
  return `${Math.round(s / 86400)}d ago`;
}

export function dateTime(iso?: string | null): string {
  if (!iso) return "—";
  return new Date(iso).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

export type Tone = "good" | "warning" | "critical" | "neutral";

export function resilienceTone(r: number | null | undefined): Tone {
  if (r === null || r === undefined) return "neutral";
  if (r >= 70) return "good";
  if (r >= 40) return "warning";
  return "critical";
}

export function resilienceWord(r: number | null | undefined): string {
  const t = resilienceTone(r);
  return t === "good" ? "Resilient" : t === "warning" ? "At risk" : t === "critical" ? "Breached" : "No data";
}

export function outcome(ended?: string | null, flag?: boolean): { label: string; tone: Tone } {
  if (!ended) return { label: "Running", tone: "neutral" };
  if (ended.startsWith("killswitch")) return { label: "Stopped", tone: "warning" };
  if (flag || ended === "flag_captured") return { label: "Flag captured", tone: "critical" };
  return { label: "Defended", tone: "good" };
}

export function shortHash(h?: string | null, n = 8): string {
  if (!h) return "—";
  return h.slice(0, n) + "…" + h.slice(-4);
}

export function download(filename: string, content: string, type = "text/plain") {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}

export function median(xs: number[]): number | null {
  if (!xs.length) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

export function mean(xs: number[]): number | null {
  return xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null;
}
