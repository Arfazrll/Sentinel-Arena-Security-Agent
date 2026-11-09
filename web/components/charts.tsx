"use client";

// Small SVG chart kit. Rules (see the dataviz method): thin marks, 2px lines,
// solid hairline grid, one y-axis, legend for >= 2 series, selective direct
// labels, a hover layer on every plot, text in text tokens (never series color).

import { ReactNode, useMemo, useState } from "react";
import { useWidth } from "@/lib/hooks";

export type Series = { key: string; label: string; color: string };

function niceMax(v: number): number {
  if (v <= 0) return 1;
  const p = Math.pow(10, Math.floor(Math.log10(v)));
  const n = v / p;
  const step = n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10;
  return step * p;
}

function ticksFor(max: number, count = 4): number[] {
  const step = max / count;
  return Array.from({ length: count + 1 }, (_, i) => Math.round(i * step * 100) / 100);
}

export function Legend({ series, line }: { series: Series[]; line?: boolean }) {
  if (series.length < 2) return null;
  return (
    <div className="legend">
      {series.map((s) => (
        <span key={s.key}>
          <i className={line ? "line" : ""} style={{ background: s.color }} />
          {s.label}
        </span>
      ))}
    </div>
  );
}

// ------------------------------------------------------------ line chart
export function LineChart({
  data,
  series,
  height = 200,
  xDomain,
  yMax,
  xFormat = (x) => `T${x}`,
  area,
  endLabels = true,
  markers = [],
}: {
  data: ({ x: number } & Record<string, number | null | undefined>)[];
  series: Series[];
  height?: number;
  xDomain?: [number, number];
  yMax?: number;
  xFormat?: (x: number) => string;
  area?: boolean;
  endLabels?: boolean;
  markers?: { x: number; color: string; label: string }[];
}) {
  const { ref, width } = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const pad = { l: 34, r: endLabels ? 64 : 12, t: 10, b: 24 };
  const w = Math.max(0, width - pad.l - pad.r);
  const h = height - pad.t - pad.b;

  const [x0, x1] = xDomain || [
    data.length ? data[0].x : 0,
    data.length ? Math.max(data[data.length - 1].x, data[0].x + 1) : 1,
  ];
  const maxV =
    yMax ??
    niceMax(Math.max(1, ...data.flatMap((d) => series.map((s) => Number(d[s.key] ?? 0)))));
  const sx = (x: number) => pad.l + ((x - x0) / Math.max(1, x1 - x0)) * w;
  const sy = (v: number) => pad.t + h - (v / maxV) * h;
  const yTicks = ticksFor(maxV);
  const xStep = Math.max(1, Math.ceil((x1 - x0) / Math.max(1, Math.floor(w / 46))));
  const xTicks: number[] = [];
  for (let x = x0; x <= x1; x += xStep) xTicks.push(x);

  const paths = series.map((s) => {
    const pts = data.filter((d) => d[s.key] !== null && d[s.key] !== undefined);
    const line = pts.map((d, i) => `${i ? "L" : "M"}${sx(d.x)},${sy(Number(d[s.key]))}`).join("");
    const fill =
      pts.length > 1
        ? `${line}L${sx(pts[pts.length - 1].x)},${sy(0)}L${sx(pts[0].x)},${sy(0)}Z`
        : "";
    return { s, pts, line, fill };
  });

  const hoverRow = hover !== null ? data.find((d) => d.x === hover) : undefined;

  const onMove = (e: React.MouseEvent<SVGRectElement>) => {
    const rect = (e.target as SVGRectElement).getBoundingClientRect();
    const px = e.clientX - rect.left;
    const x = Math.round(x0 + (px / Math.max(1, w)) * (x1 - x0));
    const nearest = data.reduce<number | null>(
      (best, d) => (best === null || Math.abs(d.x - x) < Math.abs(best - x) ? d.x : best),
      null
    );
    setHover(nearest);
  };

  return (
    <div className="chart" ref={ref}>
      <Legend series={series} line />
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label={series.map((s) => s.label).join(", ") + " over time"}>
          {yTicks.map((t) => (
            <g key={t}>
              <line className={t === 0 ? "axis-line" : "grid-line"} x1={pad.l} x2={pad.l + w} y1={sy(t)} y2={sy(t)} />
              <text className="tick-label" x={pad.l - 8} y={sy(t) + 4} textAnchor="end">
                {t}
              </text>
            </g>
          ))}
          {xTicks.map((x) => (
            <text key={x} className="tick-label" x={sx(x)} y={height - 6} textAnchor="middle">
              {xFormat(x)}
            </text>
          ))}
          {markers.map((m, i) => (
            <g key={i}>
              <line x1={sx(m.x)} x2={sx(m.x)} y1={pad.t} y2={pad.t + h} stroke={m.color} strokeWidth={1} opacity={0.55} />
              <rect x={sx(m.x) - 3} y={pad.t - 3} width={6} height={6} rx={1.5} fill={m.color}>
                <title>{m.label}</title>
              </rect>
            </g>
          ))}
          {paths.map(({ s, fill }) =>
            area && fill ? <path key={s.key + "a"} d={fill} fill={s.color} opacity={0.1} /> : null
          )}
          {paths.map(({ s, line }) => (
            <path
              key={s.key}
              d={line}
              fill="none"
              stroke={s.color}
              strokeWidth={2}
              strokeLinejoin="round"
              strokeLinecap="round"
              style={{ transition: "d 0.3s" }}
            />
          ))}
          {paths.map(({ s, pts }) => {
            const last = pts[pts.length - 1];
            if (!last) return null;
            return (
              <g key={s.key + "e"}>
                <circle cx={sx(last.x)} cy={sy(Number(last[s.key]))} r={4} fill={s.color} stroke="var(--surface)" strokeWidth={2} />
                {endLabels && (
                  <text className="end-label" x={sx(last.x) + 9} y={sy(Number(last[s.key])) + 4}>
                    {String(last[s.key])} {series.length > 1 ? s.label.split(" ")[0] : ""}
                  </text>
                )}
              </g>
            );
          })}
          {hoverRow && (
            <g pointerEvents="none">
              <line x1={sx(hoverRow.x)} x2={sx(hoverRow.x)} y1={pad.t} y2={pad.t + h} stroke="var(--text-2)" strokeWidth={1} opacity={0.5} />
              {series.map((s) =>
                hoverRow[s.key] !== null && hoverRow[s.key] !== undefined ? (
                  <circle key={s.key} cx={sx(hoverRow.x)} cy={sy(Number(hoverRow[s.key]))} r={4.5} fill={s.color} stroke="var(--surface)" strokeWidth={2} />
                ) : null
              )}
            </g>
          )}
          <rect
            x={pad.l}
            y={pad.t}
            width={w}
            height={h}
            fill="transparent"
            onMouseMove={onMove}
            onMouseLeave={() => setHover(null)}
          />
        </svg>
      )}
      {hoverRow && width > 0 && (
        <div className="tooltip" style={{ left: sx(hoverRow.x), top: pad.t + 18 + (series.length > 1 ? 26 : 0) }}>
          <div className="tt-title">{xFormat(hoverRow.x)}</div>
          {series.map((s) => (
            <div className="tt-row" key={s.key}>
              <span>
                <i style={{ background: s.color }} />
                {s.label}
              </span>
              <b>{hoverRow[s.key] ?? "—"}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------ stacked columns
export function StackedColumns({
  data,
  series,
  height = 180,
  xFormat = (x) => `T${x}`,
  slots,
}: {
  data: ({ x: number } & Record<string, number>)[];
  series: Series[];
  height?: number;
  xFormat?: (x: number) => string;
  /** fixed number of x slots (e.g. max ticks) so bars don't jump while live */
  slots?: number;
}) {
  const { ref, width } = useWidth<HTMLDivElement>();
  const [hover, setHover] = useState<number | null>(null);
  const pad = { l: 30, r: 8, t: 8, b: 22 };
  const w = Math.max(0, width - pad.l - pad.r);
  const h = height - pad.t - pad.b;
  const n = Math.max(slots ?? 0, data.length ? data[data.length - 1].x + 1 : 0, 1);
  const band = w / n;
  const bw = Math.min(24, band * 0.62);
  const totals = data.map((d) => series.reduce((a, s) => a + (d[s.key] || 0), 0));
  const maxV = niceMax(Math.max(1, ...totals));
  const sy = (v: number) => (v / maxV) * h;
  const yTicks = ticksFor(maxV, 4);
  const hoverRow = hover !== null ? data.find((d) => d.x === hover) : undefined;

  return (
    <div className="chart" ref={ref}>
      <Legend series={series} />
      {width > 0 && (
        <svg width={width} height={height} role="img" aria-label="Requests per tick by source">
          {yTicks.map((t) => (
            <g key={t}>
              <line className={t === 0 ? "axis-line" : "grid-line"} x1={pad.l} x2={pad.l + w} y1={pad.t + h - sy(t)} y2={pad.t + h - sy(t)} />
              <text className="tick-label" x={pad.l - 6} y={pad.t + h - sy(t) + 4} textAnchor="end">
                {t}
              </text>
            </g>
          ))}
          {Array.from({ length: n }, (_, i) => i).map((i) => {
            const d = data.find((r) => r.x === i);
            const cx = pad.l + band * i + band / 2;
            let y = pad.t + h;
            const segs = d
              ? series.map((s, si) => {
                  const v = d[s.key] || 0;
                  const sh = sy(v);
                  const gap = si > 0 && v > 0 ? 2 : 0;
                  y -= sh;
                  const top = y;
                  const isTop = series.slice(si + 1).every((s2) => !(d[s2.key] > 0));
                  return v > 0 ? (
                    <rect
                      key={s.key}
                      x={cx - bw / 2}
                      y={top}
                      width={bw}
                      height={Math.max(0, sh - gap)}
                      rx={isTop ? 3 : 0}
                      fill={s.color}
                      style={{ transition: "all 0.3s" }}
                    />
                  ) : null;
                })
              : null;
            const showLabel = n <= 16 || i % Math.ceil(n / 12) === 0;
            return (
              <g key={i} onMouseEnter={() => d && setHover(i)} onMouseLeave={() => setHover(null)}>
                <rect x={pad.l + band * i} y={pad.t} width={band} height={h} fill={hover === i ? "var(--hover)" : "transparent"} />
                {segs}
                {showLabel && (
                  <text className="tick-label" x={cx} y={height - 6} textAnchor="middle">
                    {xFormat(i)}
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      )}
      {hoverRow && (
        <div className="tooltip" style={{ left: pad.l + band * hoverRow.x + band / 2, top: 40 }}>
          <div className="tt-title">{xFormat(hoverRow.x)}</div>
          {series.map((s) => (
            <div className="tt-row" key={s.key}>
              <span>
                <i style={{ background: s.color }} />
                {s.label}
              </span>
              <b>{hoverRow[s.key] || 0}</b>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ------------------------------------------------------------ gauge (meter)
export function Gauge({ value, size = 168, label }: { value: number | null; size?: number; label?: ReactNode }) {
  const v = value ?? 0;
  const r = size / 2 - 12;
  const cx = size / 2;
  const cy = size / 2;
  const start = Math.PI * 0.8;
  const sweep = Math.PI * 1.4;
  const arc = (from: number, to: number) => {
    const a0 = start + sweep * from;
    const a1 = start + sweep * to;
    const large = a1 - a0 > Math.PI ? 1 : 0;
    return `M${cx + r * Math.cos(a0)},${cy + r * Math.sin(a0)} A${r},${r} 0 ${large} 1 ${cx + r * Math.cos(a1)},${cy + r * Math.sin(a1)}`;
  };
  const color = value === null ? "var(--axis)" : v >= 70 ? "var(--good)" : v >= 40 ? "var(--warning)" : "var(--critical)";
  return (
    <div style={{ position: "relative", width: size, height: size * 0.86, margin: "0 auto" }}>
      <svg width={size} height={size} role="meter" aria-valuenow={v} aria-valuemin={0} aria-valuemax={100} aria-label="Resilience score">
        <path d={arc(0, 1)} fill="none" stroke="var(--surface-3)" strokeWidth={10} strokeLinecap="round" />
        {[0.4, 0.7].map((t) => {
          const a = start + sweep * t;
          return (
            <line
              key={t}
              x1={cx + (r - 9) * Math.cos(a)}
              y1={cy + (r - 9) * Math.sin(a)}
              x2={cx + (r + 9) * Math.cos(a)}
              y2={cy + (r + 9) * Math.sin(a)}
              stroke="var(--surface)"
              strokeWidth={2}
            />
          );
        })}
        {value !== null && v > 0 && (
          <path d={arc(0, Math.max(0.005, v / 100))} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round" style={{ transition: "d 0.5s ease, stroke 0.4s" }} />
        )}
      </svg>
      <div style={{ position: "absolute", inset: 0, display: "grid", placeItems: "center", paddingTop: 4 }}>
        <div style={{ textAlign: "center" }}>
          <div style={{ fontSize: size * 0.27, fontWeight: 650, letterSpacing: "-0.03em", lineHeight: 1 }}>{value ?? "—"}</div>
          <div style={{ fontSize: 11.5, color: "var(--muted)", marginTop: 4 }}>{label ?? "resilience / 100"}</div>
        </div>
      </div>
    </div>
  );
}

// ------------------------------------------------------------ sparkline
export function Sparkline({ values, color = "var(--text-2)", height = 28, width = 96 }: { values: number[]; color?: string; height?: number; width?: number }) {
  if (values.length < 2) return <svg width={width} height={height} />;
  const max = Math.max(...values, 1);
  const min = Math.min(...values, 0);
  const sx = (i: number) => (i / (values.length - 1)) * (width - 6) + 3;
  const sy = (v: number) => height - 3 - ((v - min) / Math.max(1, max - min)) * (height - 6);
  const d = values.map((v, i) => `${i ? "L" : "M"}${sx(i)},${sy(v)}`).join("");
  return (
    <svg width={width} height={height} aria-hidden>
      <path d={d} fill="none" stroke={color} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={sx(values.length - 1)} cy={sy(values[values.length - 1])} r={2.5} fill={color} />
    </svg>
  );
}

// ------------------------------------------------------------ bar list
export function BarList({
  rows,
  max,
  color = "var(--blue)",
  format = (v) => String(v),
}: {
  rows: { label: ReactNode; value: number; color?: string; title?: string }[];
  max?: number;
  color?: string;
  format?: (v: number) => string;
}) {
  const m = max ?? Math.max(1, ...rows.map((r) => r.value));
  return (
    <div className="barlist">
      {rows.map((r, i) => (
        <div className="bl-row" key={i} title={r.title}>
          <div className="bl-label">{r.label}</div>
          <div className="bl-track">
            <div className="bl-fill" style={{ width: `${(r.value / m) * 100}%`, background: r.color || color }} />
          </div>
          <div className="bl-val">{format(r.value)}</div>
        </div>
      ))}
    </div>
  );
}

// ------------------------------------------------------------ segmented bar
export function SegBar({ parts }: { parts: { label: string; value: number; color: string }[] }) {
  const total = parts.reduce((a, p) => a + p.value, 0);
  return (
    <div>
      <div className="segbar" role="img" aria-label={parts.map((p) => `${p.label} ${p.value}`).join(", ")}>
        {total === 0 ? null : parts.filter((p) => p.value > 0).map((p) => (
          <span key={p.label} style={{ flexGrow: p.value, background: p.color }} title={`${p.label}: ${p.value}`} />
        ))}
      </div>
      <div className="legend" style={{ marginTop: 8, marginBottom: 0 }}>
        {parts.map((p) => (
          <span key={p.label}>
            <i style={{ background: p.color }} />
            {p.label} <b className="tnum" style={{ color: "var(--text)" }}>{p.value}</b>
          </span>
        ))}
      </div>
    </div>
  );
}

// ------------------------------------------------------------ heatmap
const SEQ = ["var(--seq-0)", "var(--seq-1)", "var(--seq-2)", "var(--seq-3)", "var(--seq-4)"];

export function Heatmap({
  rows,
  cols,
  value,
  format = (v) => String(v),
  rowLabel = (r) => r,
  colLabel = (c) => c,
  min = 0,
  max = 100,
}: {
  rows: string[];
  cols: string[];
  value: (r: string, c: string) => number | null;
  format?: (v: number) => string;
  rowLabel?: (r: string) => ReactNode;
  colLabel?: (c: string) => ReactNode;
  min?: number;
  max?: number;
}) {
  const [hover, setHover] = useState<string | null>(null);
  const step = (v: number) => Math.min(4, Math.max(0, Math.floor(((v - min) / Math.max(1, max - min)) * 5)));
  return (
    <div className="table-wrap">
      <table className="table" style={{ borderCollapse: "separate", borderSpacing: 3 }}>
        <thead>
          <tr>
            <th style={{ position: "static" }}>Red ↓ / Blue →</th>
            {cols.map((c) => (
              <th key={c} style={{ position: "static", textAlign: "center" }}>
                {colLabel(c)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((r) => (
            <tr key={r} style={{ background: "none" }}>
              <td style={{ border: "none", fontWeight: 550, whiteSpace: "nowrap" }}>{rowLabel(r)}</td>
              {cols.map((c) => {
                const v = value(r, c);
                const s = v === null ? -1 : step(v);
                const k = `${r}:${c}`;
                return (
                  <td
                    key={c}
                    onMouseEnter={() => setHover(k)}
                    onMouseLeave={() => setHover(null)}
                    title={v === null ? "not run" : `${r} vs ${c}: ${format(v)}`}
                    style={{
                      border: "none",
                      borderRadius: 6,
                      textAlign: "center",
                      height: 46,
                      minWidth: 76,
                      fontWeight: 650,
                      fontVariantNumeric: "tabular-nums",
                      background: v === null ? "var(--surface-2)" : SEQ[s],
                      color: v === null ? "var(--muted)" : "var(--text)",
                      outline: hover === k ? "2px solid var(--text)" : "none",
                      outlineOffset: -2,
                    }}
                  >
                    <span className="hm-val" data-step={s}>
                      {v === null ? "—" : format(v)}
                    </span>
                  </td>
                );
              })}
            </tr>
          ))}
        </tbody>
      </table>
      <div className="legend" style={{ marginTop: 6 }}>
        <span className="muted">Mean resilience</span>
        {SEQ.map((c, i) => (
          <span key={i}>
            <i style={{ background: c }} />
            {Math.round(min + ((max - min) / 5) * i)}–{Math.round(min + ((max - min) / 5) * (i + 1))}
          </span>
        ))}
      </div>
    </div>
  );
}

export function useSeries() {
  return useMemo(
    () => ({
      red: { key: "red", label: "Red score", color: "var(--red)" },
      blue: { key: "blue", label: "Blue score", color: "var(--blue)" },
      resilience: { key: "resilience", label: "Resilience", color: "var(--text-2)" },
    }),
    []
  );
}
