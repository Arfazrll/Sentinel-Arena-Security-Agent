"use client";

import { useCallback, useMemo, useRef, useState } from "react";
import Link from "next/link";
import {
  ArenaEvent,
  EngagementResult,
  WS_BASE,
  startEngagement,
  reportUrl,
} from "@/lib/api";
import Timeline from "@/components/Timeline";
import NetworkGraph from "@/components/NetworkGraph";

const NODE_KEYS = ["/", "/search", "/config.json", "/error", "admin", "flag"];

export default function ArenaPage() {
  const [events, setEvents] = useState<ArenaEvent[]>([]);
  const [status, setStatus] = useState("idle");
  const [result, setResult] = useState<EngagementResult | null>(null);
  const [engagementId, setEngagementId] = useState<string | null>(null);
  const [blue, setBlue] = useState("scripted");
  const [seed, setSeed] = useState("42");
  const [running, setRunning] = useState(false);
  const wsRef = useRef<WebSocket | null>(null);

  const score = useMemo(() => {
    let s = { resilience: "—", red: 0, blue: 0, tick: "—" as string | number };
    for (const e of events) {
      if (e.tick >= 0) s.tick = e.tick;
      if (e.kind === "score" && e.data) {
        s.resilience = String(e.data.resilience);
        s.red = e.data.red;
        s.blue = e.data.blue;
      }
    }
    if (result) {
      s.resilience = String(result.resilience);
      s.red = result.red;
      s.blue = result.blue;
    }
    return s;
  }, [events, result]);

  const lit = useMemo(() => {
    const set = new Set<string>(["operator", "target"]);
    for (const e of events) {
      const hay = (e.summary || "") + JSON.stringify(e.data || {});
      for (const k of NODE_KEYS) if (hay.includes(k)) set.add(k);
      if (hay.includes("admin")) set.add("admin");
      if (hay.includes("flag")) set.add("flag");
    }
    return set;
  }, [events]);

  const run = useCallback(async () => {
    setEvents([]);
    setResult(null);
    setRunning(true);
    setStatus("starting…");
    try {
      const { id } = await startEngagement("shop-01", Number(seed), blue);
      setEngagementId(id);
      setStatus("running " + id);
      const ws = new WebSocket(`${WS_BASE}/ws/${id}`);
      wsRef.current = ws;
      ws.onmessage = (m) => {
        const msg = JSON.parse(m.data);
        if (msg.type === "event") {
          setEvents((prev) => [...prev, msg.event as ArenaEvent]);
        } else if (msg.type === "done") {
          setResult(msg.result as EngagementResult);
          setStatus("done");
          setRunning(false);
          ws.close();
        }
      };
      ws.onerror = () => {
        setStatus("websocket error");
        setRunning(false);
      };
    } catch (err: any) {
      setStatus("error: " + err.message + " (is the API running on :8000?)");
      setRunning(false);
    }
  }, [blue, seed]);

  const resColor =
    score.resilience === "—"
      ? "var(--fg)"
      : Number(score.resilience) >= 70
      ? "var(--green)"
      : Number(score.resilience) >= 40
      ? "var(--amber)"
      : "var(--red)";

  return (
    <div className="wrap">
      <h1>Live Arena</h1>
      <div className="sub">
        Red vs blue on the bundled sandbox target, streamed over WebSocket.
      </div>

      <div className="controls">
        <select value={blue} onChange={(e) => setBlue(e.target.value)}>
          <option value="scripted">Blue: scripted</option>
          <option value="noop">Blue: passive (no-op)</option>
        </select>
        <select value={seed} onChange={(e) => setSeed(e.target.value)}>
          <option>42</option>
          <option>7</option>
          <option>101</option>
        </select>
        <button className="go" onClick={run} disabled={running}>
          {running ? "Running…" : "Run engagement"}
        </button>
        <span className="badge">{status}</span>
      </div>

      <div className="score">
        <div>
          <div className="dial" style={{ color: resColor }}>
            {score.resilience}
          </div>
          <div className="stat">resilience / 100</div>
        </div>
        <div className="stat">
          <b>{score.red}</b>red
        </div>
        <div className="stat">
          <b>{score.blue}</b>blue
        </div>
        <div className="stat">
          <b>{result ? (result.flag_captured ? "captured" : "held") : "—"}</b>flag
        </div>
        <div className="stat">
          <b>{score.tick}</b>tick
        </div>
        {engagementId && result && (
          <div className="controls" style={{ marginLeft: "auto" }}>
            <Link className="badge" href={`/report/${engagementId}`}>
              resilience report →
            </Link>
            <a className="badge" href={reportUrl(engagementId)} target="_blank" rel="noreferrer">
              full HTML report ↗
            </a>
          </div>
        )}
      </div>

      <NetworkGraph lit={lit} />
      <Timeline events={events} />
    </div>
  );
}
