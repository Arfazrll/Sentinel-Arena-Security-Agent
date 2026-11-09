"use client";

import { ReactNode, useState } from "react";
import { AlertTriangle, CheckCircle2, CircleDashed, OctagonX, Table2, BarChart3 } from "lucide-react";
import type { Severity } from "@/lib/api";
import type { Tone } from "@/lib/format";

export function Card({
  title,
  sub,
  actions,
  children,
  className = "",
  bodyClass = "card-body",
  table,
}: {
  title?: ReactNode;
  sub?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  bodyClass?: string;
  /** When provided, the card gets a chart/table toggle (accessible data view). */
  table?: ReactNode;
}) {
  const [asTable, setAsTable] = useState(false);
  return (
    <section className={`card ${className}`}>
      {(title || actions || table) && (
        <div className="card-head">
          <div style={{ minWidth: 0 }}>
            {title && <h3>{title}</h3>}
            {sub && <div className="sub">{sub}</div>}
          </div>
          <div className="actions">
            {actions}
            {table && (
              <button
                className="btn ghost sm icon"
                title={asTable ? "Show chart" : "Show data table"}
                aria-label={asTable ? "Show chart" : "Show data table"}
                onClick={() => setAsTable((v) => !v)}
              >
                {asTable ? <BarChart3 size={14} /> : <Table2 size={14} />}
              </button>
            )}
          </div>
        </div>
      )}
      <div className={bodyClass}>{asTable && table ? <div className="table-wrap">{table}</div> : children}</div>
    </section>
  );
}

export function Stat({
  label,
  value,
  unit,
  foot,
  icon,
  tone,
}: {
  label: ReactNode;
  value: ReactNode;
  unit?: string;
  foot?: ReactNode;
  icon?: ReactNode;
  tone?: Tone;
}) {
  const color =
    tone === "good" ? "var(--good-text)" : tone === "critical" ? "var(--critical-text)" : tone === "warning" ? "var(--warning)" : undefined;
  return (
    <div className="card stat">
      <div className="label">
        {icon}
        {label}
      </div>
      <div className="value" style={color ? { color } : undefined}>
        {value}
        {unit && <small>{unit}</small>}
      </div>
      <div className="foot">{foot}</div>
    </div>
  );
}

const TONE_ICON: Record<Tone, ReactNode> = {
  good: <CheckCircle2 size={12} />,
  warning: <AlertTriangle size={12} />,
  critical: <OctagonX size={12} />,
  neutral: <CircleDashed size={12} />,
};

export function StatusPill({ tone, children, live }: { tone: Tone; children: ReactNode; live?: boolean }) {
  return (
    <span className={`pill ${tone}${live ? " live" : ""}`}>
      {live ? <span className="dot" /> : TONE_ICON[tone]}
      {children}
    </span>
  );
}

export function Pill({ children, className = "" }: { children: ReactNode; className?: string }) {
  return <span className={`pill ${className}`}>{children}</span>;
}

export function Sev({ s }: { s: Severity | string }) {
  return (
    <span className={`sev sev-${s}`}>
      <i />
      {s.charAt(0).toUpperCase() + s.slice(1)}
    </span>
  );
}

export function Empty({
  icon,
  title,
  children,
  action,
}: {
  icon: ReactNode;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
}) {
  return (
    <div className="empty">
      <div className="icon">{icon}</div>
      <h3>{title}</h3>
      {children && <p>{children}</p>}
      {action}
    </div>
  );
}

export function Skeleton({ h = 16, w = "100%", style }: { h?: number; w?: number | string; style?: React.CSSProperties }) {
  return <div className="skeleton" style={{ height: h, width: w, ...style }} />;
}

export function Tabs<T extends string>({
  tabs,
  value,
  onChange,
}: {
  tabs: { id: T; label: string; icon?: ReactNode; count?: number }[];
  value: T;
  onChange: (t: T) => void;
}) {
  return (
    <div className="tabs" role="tablist">
      {tabs.map((t) => (
        <button
          key={t.id}
          role="tab"
          aria-selected={value === t.id}
          className={`tab ${value === t.id ? "active" : ""}`}
          onClick={() => onChange(t.id)}
        >
          {t.icon}
          {t.label}
          {t.count !== undefined && <span className="count">{t.count}</span>}
        </button>
      ))}
    </div>
  );
}

export function Seg<T extends string | number>({
  options,
  value,
  onChange,
  label,
}: {
  options: { value: T; label: string }[];
  value: T;
  onChange: (v: T) => void;
  label?: string;
}) {
  return (
    <div className="seg" role="group" aria-label={label}>
      {options.map((o) => (
        <button key={String(o.value)} className={o.value === value ? "on" : ""} onClick={() => onChange(o.value)}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function PageHead({ title, sub, actions }: { title: string; sub?: ReactNode; actions?: ReactNode }) {
  return (
    <div className="page-head">
      <div>
        <h1>{title}</h1>
        {sub && <p>{sub}</p>}
      </div>
      {actions && <div className="row">{actions}</div>}
    </div>
  );
}

export function ErrorBanner({ error, onRetry }: { error: string; onRetry?: () => void }) {
  return (
    <div className="banner error" role="alert">
      <OctagonX size={16} style={{ color: "var(--critical-text)", flex: "none", marginTop: 2 }} />
      <div style={{ flex: 1 }}>
        <b>Couldn't load data.</b> {error}
        <div className="muted" style={{ marginTop: 4 }}>
          Start the API with <code>uvicorn sentinel_arena.api.server:app</code>
        </div>
      </div>
      {onRetry && (
        <button className="btn sm" onClick={onRetry}>
          Retry
        </button>
      )}
    </div>
  );
}
