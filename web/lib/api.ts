// Client-side API helpers for the Sentinel Arena backend.

export const API_BASE =
  process.env.NEXT_PUBLIC_API_BASE || "http://127.0.0.1:8000";
export const WS_BASE = API_BASE.replace(/^http/, "ws");

export type ArenaEvent = {
  ts: string;
  tick: number;
  kind: string;
  team: string;
  actor: string;
  summary: string;
  data: Record<string, any>;
};

export type EngagementResult = {
  resilience: number;
  red: number;
  blue: number;
  flag_captured: boolean;
  ended: string;
  report: string;
};

export type LeaderboardRow = {
  red: string;
  blue: string;
  runs: number;
  flag_capture_rate: number;
  mean_resilience: number;
  mean_red_score: number;
  mean_blue_score: number;
  mean_ticks_to_detection: number | null;
  mean_duration_s: number;
};

export async function startEngagement(
  scenario: string,
  seed: number,
  blue: string
): Promise<{ id: string }> {
  const res = await fetch(
    `${API_BASE}/engagements?scenario=${scenario}&seed=${seed}&blue=${blue}`,
    { method: "POST" }
  );
  if (!res.ok) throw new Error(`start failed: ${res.status}`);
  return res.json();
}

export async function fetchScenarios(): Promise<string[]> {
  const res = await fetch(`${API_BASE}/scenarios`);
  const data = await res.json();
  return data.scenarios ?? [];
}

export async function fetchLeaderboard(
  seeds: string
): Promise<{ scenario: string; seeds: number[]; rows: LeaderboardRow[] }> {
  const res = await fetch(`${API_BASE}/leaderboard?seeds=${seeds}`);
  if (!res.ok) throw new Error(`leaderboard failed: ${res.status}`);
  return res.json();
}

export async function fetchResult(id: string): Promise<any> {
  const res = await fetch(`${API_BASE}/engagements/${id}/result`);
  if (!res.ok) throw new Error(`result not ready: ${res.status}`);
  return res.json();
}

export function reportUrl(id: string): string {
  return `${API_BASE}/engagements/${id}/report`;
}
