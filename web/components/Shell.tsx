"use client";

import { ReactNode, createContext, useCallback, useContext, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import {
  Activity,
  Bot,
  CheckCircle2,
  ClipboardList,
  FlaskConical,
  History,
  LayoutDashboard,
  Menu,
  Moon,
  Search,
  ShieldCheck,
  Sun,
  Swords,
  Trophy,
  X,
} from "lucide-react";
import { useApiHealth } from "@/lib/hooks";
import { API_BASE, EngagementSummary, api } from "@/lib/api";

// ------------------------------------------------------------ toasts
type Toast = { id: number; text: ReactNode };
const ToastCtx = createContext<(t: ReactNode) => void>(() => {});
export const useToast = () => useContext(ToastCtx);

const NAV = [
  { group: "Operate", items: [
    { href: "/", label: "Overview", icon: LayoutDashboard },
    { href: "/arena", label: "Live arena", icon: Swords },
    { href: "/engagements", label: "Engagements", icon: History },
  ] },
  { group: "Analyze", items: [
    { href: "/leaderboard", label: "Benchmarks", icon: Trophy },
    { href: "/remediation", label: "Remediation", icon: ClipboardList },
  ] },
  { group: "Configure", items: [
    { href: "/scenarios", label: "Scenarios", icon: FlaskConical },
    { href: "/agents", label: "Agents", icon: Bot },
    { href: "/governance", label: "Trust & safety", icon: ShieldCheck },
  ] },
];

const TITLES: Record<string, string> = {
  "": "Overview",
  arena: "Live arena",
  engagements: "Engagements",
  leaderboard: "Benchmarks",
  remediation: "Remediation",
  scenarios: "Scenarios",
  agents: "Agents",
  governance: "Trust & safety",
  compare: "Compare runs",
  report: "Report",
};

export default function Shell({ children }: { children: ReactNode }) {
  const pathname = usePathname() || "/";
  const router = useRouter();
  const { health, online } = useApiHealth();
  const [navOpen, setNavOpen] = useState(false);
  const [palette, setPalette] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">("dark");
  const [toasts, setToasts] = useState<Toast[]>([]);

  // The inline script in layout.tsx already applied the theme before paint.
  useEffect(() => {
    const t = document.documentElement.dataset.theme;
    if (t === "light" || t === "dark") setTheme(t);
  }, []);
  const chooseTheme = (t: "dark" | "light") => {
    setTheme(t);
    document.documentElement.dataset.theme = t;
    try {
      localStorage.setItem("sa-theme", t);
    } catch {}
  };

  useEffect(() => setNavOpen(false), [pathname]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setPalette((p) => !p);
      }
      if (e.key === "Escape") setPalette(false);
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const toast = useCallback((text: ReactNode) => {
    const id = Date.now() + Math.random();
    setToasts((t) => [...t, { id, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), 4200);
  }, []);

  const seg = pathname.split("/")[1] || "";
  const isActive = (href: string) => (href === "/" ? pathname === "/" : pathname.startsWith(href));

  return (
    <ToastCtx.Provider value={toast}>
      <div className="shell">
        <aside className={`sidebar ${navOpen ? "open" : ""}`} aria-label="Main navigation">
          <div className="brand">
            <span className="brand-mark">
              <Swords size={15} />
            </span>
            <div>
              Sentinel Arena
              <small>Security resilience lab</small>
            </div>
            <button className="btn ghost sm icon mobile-nav" style={{ marginLeft: "auto" }} onClick={() => setNavOpen(false)} aria-label="Close menu">
              <X size={15} />
            </button>
          </div>
          {NAV.map((g) => (
            <div key={g.group}>
              <div className="nav-group">{g.group}</div>
              {g.items.map((it) => (
                <Link key={it.href} href={it.href} className={`nav-link ${isActive(it.href) ? "active" : ""}`}>
                  <it.icon size={16} />
                  {it.label}
                  {it.href === "/arena" && health && health.running > 0 && (
                    <span className="count pill live red" style={{ height: 18 }}>
                      <span className="dot" />
                      {health.running}
                    </span>
                  )}
                  {it.href === "/engagements" && health && <span className="count">{health.engagements}</span>}
                </Link>
              ))}
            </div>
          ))}
          <div className="sidebar-foot">
            <div className="row" style={{ gap: 6, marginBottom: 4, color: "var(--text-2)" }}>
              <ShieldCheck size={13} /> Authorized targets only
            </div>
            Every request passes the ownership gate and lands in a hash-chained audit log.
          </div>
        </aside>

        <div className="main">
          <header className="topbar">
            <button className="btn ghost icon mobile-nav" onClick={() => setNavOpen(true)} aria-label="Open menu">
              <Menu size={17} />
            </button>
            <div className="crumbs">
              <span className="crumb-root">Sentinel Arena /</span>
              <b>{TITLES[seg] ?? seg}</b>
            </div>
            <div className="spacer" />
            <button className="search-btn" onClick={() => setPalette(true)} aria-label="Search and run commands">
              <Search size={14} />
              <span className="label">Search or jump to…</span>
              <kbd>Ctrl K</kbd>
            </button>
            <ApiPill online={online} version={health?.version} />
            <button
              className="btn ghost icon"
              onClick={() => chooseTheme(theme === "dark" ? "light" : "dark")}
              aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
              title="Toggle theme"
            >
              {theme === "dark" ? <Sun size={16} /> : <Moon size={16} />}
            </button>
            <Link href="/arena" className="btn primary">
              <Swords size={14} /> <span className="hide-sm">New engagement</span>
            </Link>
          </header>

          <main className="page">
            {online === false && (
              <div className="banner error" role="alert">
                <Activity size={16} style={{ color: "var(--critical-text)", marginTop: 2, flex: "none" }} />
                <div>
                  <b>API offline.</b> The web app can't reach <code>{API_BASE}</code>. Start it from the repo root:{" "}
                  <code>uv run uvicorn sentinel_arena.api.server:app</code>
                </div>
              </div>
            )}
            {children}
          </main>
        </div>
      </div>

      {palette && <CommandPalette onClose={() => setPalette(false)} go={(href) => { setPalette(false); router.push(href); }} />}

      <div className="toasts" aria-live="polite">
        {toasts.map((t) => (
          <div className="toast" key={t.id}>
            <CheckCircle2 size={15} style={{ color: "var(--good-text)", flex: "none" }} />
            <div>{t.text}</div>
          </div>
        ))}
      </div>
    </ToastCtx.Provider>
  );
}

function ApiPill({ online, version }: { online: boolean | null; version?: string }) {
  if (online === null) return <span className="pill">Connecting…</span>;
  return online ? (
    <span className="pill good live" title={`API ${API_BASE}`}>
      <span className="dot" /> <span className="hide-sm">API {version ? `v${version}` : "online"}</span>
    </span>
  ) : (
    <span className="pill critical">
      <span className="dot" /> <span className="hide-sm">API offline</span>
    </span>
  );
}

function CommandPalette({ onClose, go }: { onClose: () => void; go: (href: string) => void }) {
  const [q, setQ] = useState("");
  const [sel, setSel] = useState(0);
  const [recent, setRecent] = useState<EngagementSummary[]>([]);

  useEffect(() => {
    api.engagements().then((e) => setRecent(e.slice(0, 8))).catch(() => {});
  }, []);

  const items = useMemo(() => {
    const base = [
      ...NAV.flatMap((g) => g.items.map((i) => ({ label: i.label, href: i.href, group: "Go to" }))),
      { label: "Run: Methodical attacker vs Real-time SOC", href: "/arena?red=scripted&blue=scripted", group: "Run" },
      { label: "Run: Rush attacker vs Real-time SOC", href: "/arena?red=rush&blue=scripted", group: "Run" },
      { label: "Run: Methodical attacker vs No defense", href: "/arena?red=scripted&blue=noop", group: "Run" },
      { label: "Run full benchmark", href: "/leaderboard?run=1", group: "Run" },
      ...recent.map((e) => ({
        label: `${e.scenario_name || e.scenario} · ${e.red_label || e.red} vs ${e.blue_label || e.blue} · seed ${e.seed}`,
        href: `/engagements/${e.id}`,
        group: e.result ? `Resilience ${e.result.resilience}` : e.status,
      })),
    ];
    const s = q.trim().toLowerCase();
    return s ? base.filter((i) => (i.label + i.group).toLowerCase().includes(s)) : base;
  }, [q, recent]);

  useEffect(() => setSel(0), [q]);

  return (
    <div className="overlay" onClick={onClose}>
      <div className="palette" role="dialog" aria-label="Command palette" onClick={(e) => e.stopPropagation()}>
        <input
          autoFocus
          placeholder="Jump to a page, run a matchup, open an engagement…"
          value={q}
          onChange={(e) => setQ(e.target.value)}
          onKeyDown={(e) => {
            if (e.key === "ArrowDown") { e.preventDefault(); setSel((s) => Math.min(items.length - 1, s + 1)); }
            if (e.key === "ArrowUp") { e.preventDefault(); setSel((s) => Math.max(0, s - 1)); }
            if (e.key === "Enter" && items[sel]) go(items[sel].href);
          }}
        />
        <ul role="listbox">
          {items.length === 0 && <li>No matches</li>}
          {items.map((it, i) => (
            <li key={it.href + it.label} className={i === sel ? "on" : ""} onMouseEnter={() => setSel(i)} onClick={() => go(it.href)} role="option" aria-selected={i === sel}>
              {it.label}
              <span className="grp">{it.group}</span>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
