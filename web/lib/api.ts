// Typed client for the Sentinel Arena FastAPI backend.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8000";
export const WS_BASE = API_BASE.replace(/^http/, "ws");

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

async function call<T>(path: string, init?: RequestInit): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${API_BASE}${path}`, { cache: "no-store", ...init });
  } catch {
    throw new ApiError(0, "Can't reach the API. Is it running on " + API_BASE + "?");
  }
  if (!res.ok) {
    let msg = `${res.status}`;
    try {
      const body = await res.json();
      msg = typeof body.detail === "string" ? body.detail : body.error || msg;
    } catch {}
    throw new ApiError(res.status, msg.replace(/^"|"$/g, ""));
  }
  return res.json();
}

// ---------------------------------------------------------------- types
export type ArenaEvent = {
  ts: string;
  tick: number;
  kind: string;
  team: string;
  actor: string;
  summary: string;
  data: Record<string, any>;
};

export type ResultBrief = {
  resilience: number;
  red: number;
  blue: number;
  flag_captured: boolean;
  ended: string;
  report: string;
  error?: string;
};

export type EngagementStatus = "running" | "done" | "stopped" | "error";

export type EngagementSummary = {
  id: string;
  status: EngagementStatus;
  scenario: string;
  seed: number;
  red: string;
  blue: string;
  created_at: string;
  result: ResultBrief | null;
  error: string | null;
  scenario_name?: string;
  red_label?: string;
  blue_label?: string;
  finished_at?: string;
  ticks_run?: number;
  max_ticks?: number;
  duration_s?: number;
  findings?: number;
  severity?: Record<string, number>;
  time_to_detect?: number | null;
  time_to_contain?: number | null;
  dwell_ticks?: number | null;
  attacker_block_rate?: number;
  false_blocks?: number;
  events?: number;
};

export type Controls = { nist_csf: string[]; iso27001: string[]; pci_dss: string[]; soc2: string[] };

export type Finding = {
  id: string;
  title: string;
  owasp: string;
  owasp_title: string;
  severity: Severity;
  description: string;
  evidence: string;
  mitigation: string;
  url: string;
  tick: number;
  rule_id: string;
  cwe: string[];
  controls: Controls;
  cvss_band: string;
  risk_score: number;
  priority: "P1" | "P2" | "P3" | "P4";
  fix_sla_days: number;
  effort: "S" | "M" | "L";
};

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type Technique = {
  id: string;
  name: string;
  tactic: string;
  uses: number;
  first_tick: number;
  succeeded: number;
};

export type Kpis = {
  first_red_tick: number | null;
  first_malicious_tick: number | null;
  detect_tick: number | null;
  contain_tick: number | null;
  time_to_detect: number | null;
  time_to_contain: number | null;
  dwell_ticks: number;
  red_actions: number;
  red_success_rate: number;
  blue_actions: number;
  blue_success_rate: number;
  rejected_actions: number;
  requests: Record<string, number>;
  attacker_block_rate: number;
  sla_fail_ticks: number;
  techniques: Technique[];
  traffic: TrafficTick[];
};

export type TrafficTick = {
  tick: number;
  legit_ok?: number;
  legit_blocked?: number;
  red_ok?: number;
  red_blocked?: number;
  system_ok?: number;
  system_blocked?: number;
};

export type Scoreboard = {
  red: { recon: number; paths_found: number; findings_weight: number; flag_captured: boolean };
  blue: {
    true_positive_detections: number;
    ticks_to_first_detection: number | null;
    blocked_attacker_before_flag: boolean;
    sla_uptime: number;
    legit_availability: number;
    false_blocks: number;
  };
  resilience: number;
};

export type EngagementResult = {
  scenario: string;
  seed: number;
  ended: string;
  ticks_run: number;
  max_ticks?: number;
  scoreboard: Scoreboard;
  findings: Finding[];
  duration_s: number;
  meta?: {
    scenario_name: string;
    red: string;
    red_label: string;
    blue: string;
    blue_label: string;
    started_at: string;
    finished_at: string;
    tick_delay_s: number;
    host: string;
    operator: string;
    scope_fingerprint: string;
    environment: string;
    rate_cap: string;
  };
  kpis?: Kpis;
  timeline?: { tick: number; red: number; blue: number; resilience: number; findings: number }[];
};

export type AgentInfo = {
  name: string;
  team: "red" | "blue";
  label: string;
  kind: "scripted" | "llm" | "baseline";
  description: string;
  strategy: string[];
  benchmark: boolean;
  available: boolean;
  actions: string[];
};

export type ScenarioInfo = {
  id: string;
  name: string;
  description: string;
  max_ticks: number;
  randomize: string[];
  health_path: string;
  weaknesses: { id: string; owasp: string; severity: Severity; title: string; detect: string; mitigation: string }[];
};

export type MatchupRow = {
  red: string;
  blue: string;
  red_label: string;
  blue_label: string;
  runs: number;
  flag_capture_rate: number;
  mean_resilience: number;
  mean_red_score: number;
  mean_blue_score: number;
  mean_ticks_to_detection: number | null;
  mean_duration_s: number;
  resilience_runs: number[];
  mean_false_blocks: number;
  mean_sla_uptime: number;
  mean_ticks_run: number;
};

export type BenchmarkJob = {
  id: string;
  status: "running" | "done" | "error";
  scenario: string;
  seeds: number[];
  done: number;
  total: number;
  current: string;
  rows: MatchupRow[];
  started_at: string;
  finished_at?: string;
  error?: string;
};

export type CampaignVuln = {
  rule_id: string;
  title: string;
  owasp: string;
  owasp_title: string;
  severity: Severity;
  cwe: string[];
  cvss_band: string;
  risk_score: number;
  priority: "P1" | "P2" | "P3" | "P4";
  fix_sla_days: number;
  effort: "S" | "M" | "L";
  mitigation: string;
  controls: Controls;
  occurrences: number;
  example_evidence: string;
  example_url: string;
};

export type CampaignMatchup = {
  red: string;
  blue: string;
  red_label: string;
  blue_label: string;
  runs: number;
  attacker_win_rate: number;
  mean_resilience: number;
  worst_resilience: number;
  mean_ticks_to_detect: number | null;
};

export type CampaignResult = {
  id: string;
  target: string;
  label: string;
  depth: string;
  created_at: string;
  runs: number;
  scenarios: string[];
  reds: string[];
  blues: string[];
  seeds: number[];
  posture_grade: "A" | "B" | "C" | "D" | "F";
  mean_resilience: number;
  worst_resilience: number;
  best_resilience: number;
  attacker_win_rate: number;
  vulnerabilities: CampaignVuln[];
  severity_counts: Record<string, number>;
  owasp_coverage: Record<string, number>;
  matchups: CampaignMatchup[];
};

export type CampaignJob = {
  id: string;
  status: "running" | "done" | "error";
  target: string;
  depth: string;
  label: string;
  done: number;
  total: number;
  current: string;
  result: CampaignResult | null;
  started_at: string;
  finished_at?: string;
  error?: string;
};

export type CampaignBrief = {
  id: string;
  status: "running" | "done" | "error";
  target: string;
  depth: string;
  label: string;
  done: number;
  total: number;
  started_at: string;
  finished_at?: string;
  grade?: string;
  worst_resilience?: number;
  findings?: number;
};

export type AuditEntry = {
  seq: number;
  timestamp: string;
  actor: string;
  action: string;
  host: string;
  scope_fingerprint: string;
  outcome: "allow" | "deny" | "info";
  detail: Record<string, any>;
  prev_hash: string;
  entry_hash: string;
};

export type AuditTrail = {
  verified: boolean;
  error: string | null;
  total: number;
  counts: Record<string, number>;
  tip: string | null;
  entries: AuditEntry[];
};

export type AggregatedFinding = Finding & {
  occurrences: number;
  engagements: string[];
  first_seen: string;
  last_seen: string;
};

export type Health = {
  status: string;
  version: string;
  uptime_s: number;
  engagements: number;
  running: number;
  max_concurrent: number;
};

// ---------------------------------------------------------------- calls
export const api = {
  health: () => call<Health>("/healthz"),
  agents: () => call<{ agents: AgentInfo[] }>("/agents").then((d) => d.agents),
  scenarios: () => call<{ items: ScenarioInfo[] }>("/scenarios").then((d) => d.items),
  engagements: () =>
    call<{ engagements: EngagementSummary[]; total: number }>("/engagements").then((d) => d.engagements),
  engagement: (id: string) => call<EngagementSummary>(`/engagements/${id}`),
  start: (p: { scenario: string; seed: number; red: string; blue: string; pace_ms: number }) =>
    call<{ id: string }>(
      `/engagements?${new URLSearchParams({
        scenario: p.scenario,
        seed: String(p.seed),
        red: p.red,
        blue: p.blue,
        pace_ms: String(p.pace_ms),
      })}`,
      { method: "POST" }
    ),
  stop: (id: string) =>
    call<{ stopped: boolean }>(`/engagements/${id}/stop?reason=operator%20kill%20switch`, { method: "POST" }),
  result: (id: string) => call<EngagementResult>(`/engagements/${id}/result`),
  events: (id: string) => call<{ events: ArenaEvent[] }>(`/engagements/${id}/events`).then((d) => d.events),
  audit: (id: string) => call<AuditTrail>(`/engagements/${id}/audit?limit=2000`),
  findings: () => call<{ findings: AggregatedFinding[] }>("/findings").then((d) => d.findings),
  startBenchmark: (seeds: string, reds: string[], blues: string[]) =>
    call<{ id: string; total: number }>(
      `/benchmarks?${new URLSearchParams({ seeds, reds: reds.join(","), blues: blues.join(",") })}`,
      { method: "POST" }
    ),
  benchmark: (id: string) => call<BenchmarkJob>(`/benchmarks/${id}`),
  latestBenchmark: () => call<BenchmarkJob>("/benchmarks/latest"),
  startCampaign: (p: { target: string; depth: string; scenarios: string[]; label: string; i_own_this: boolean }) =>
    call<{ id: string; total: number }>(
      `/campaigns?${new URLSearchParams({
        target: p.target,
        depth: p.depth,
        scenarios_csv: p.scenarios.join(","),
        label: p.label,
        i_own_this: String(p.i_own_this),
      })}`,
      { method: "POST" }
    ),
  campaign: (id: string) => call<CampaignJob>(`/campaigns/${id}`),
  campaigns: () => call<CampaignBrief[]>("/campaigns"),
};

export const campaignReportUrl = (id: string) => `${API_BASE}/campaigns/${id}/report`;

export const exportUrl = (id: string, fmt: string) => `${API_BASE}/engagements/${id}/export/${fmt}`;
export const reportUrl = (id: string) => `${API_BASE}/engagements/${id}/report`;
