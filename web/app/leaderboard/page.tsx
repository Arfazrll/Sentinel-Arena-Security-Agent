"use client";

import { useCallback, useState } from "react";
import { LeaderboardRow, fetchLeaderboard } from "@/lib/api";

export default function LeaderboardPage() {
  const [rows, setRows] = useState<LeaderboardRow[]>([]);
  const [seeds, setSeeds] = useState("42,7,101");
  const [loading, setLoading] = useState(false);
  const [status, setStatus] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setStatus("running benchmark…");
    try {
      const data = await fetchLeaderboard(seeds);
      setRows(data.rows);
      setStatus(`${data.rows.length} matchups over ${data.seeds.length} seeds`);
    } catch (err: any) {
      setStatus("error: " + err.message + " (is the API running on :8000?)");
    } finally {
      setLoading(false);
    }
  }, [seeds]);

  return (
    <div className="wrap">
      <h1>Leaderboard</h1>
      <div className="sub">
        Red × blue agents compared across seeds. Agents are registry entries, so
        a future LLM/MCP agent appears here the same way.
      </div>

      <div className="controls">
        <input
          value={seeds}
          onChange={(e) => setSeeds(e.target.value)}
          style={{
            background: "var(--panel)",
            color: "var(--fg)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            padding: "8px 12px",
          }}
        />
        <button className="go" onClick={load} disabled={loading}>
          {loading ? "Running…" : "Run benchmark"}
        </button>
        <span className="badge">{status}</span>
      </div>

      {rows.length > 0 && (
        <table>
          <thead>
            <tr>
              <th>Red</th>
              <th>Blue</th>
              <th className="num">Runs</th>
              <th className="num">Attacker win %</th>
              <th className="num">Mean resilience</th>
              <th className="num">Mean red</th>
              <th className="num">Mean blue</th>
              <th className="num">Ticks to detect</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r, i) => (
              <tr key={i}>
                <td>{r.red}</td>
                <td>{r.blue}</td>
                <td className="num">{r.runs}</td>
                <td className="num">{(r.flag_capture_rate * 100).toFixed(0)}%</td>
                <td className="num">{r.mean_resilience}</td>
                <td className="num">{r.mean_red_score}</td>
                <td className="num">{r.mean_blue_score}</td>
                <td className="num">
                  {r.mean_ticks_to_detection ?? "–"}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
