"use client";

import { ArenaEvent } from "@/lib/api";

function Feed({ team, events }: { team: "red" | "blue"; events: ArenaEvent[] }) {
  const mine = events.filter((e) => e.team === team).slice().reverse();
  return (
    <div className={`feed ${team}`}>
      <h2>{team === "red" ? "Red — attacker" : "Blue — defender"}</h2>
      {mine.length === 0 && <div className="stat">waiting…</div>}
      {mine.map((e, i) => (
        <div key={i} className={`ev ${team}`}>
          <div className="t">
            tick {e.tick} · {e.kind}
          </div>
          {e.summary}
          {e.data?.attack_technique && (
            <div className="att">
              ATT&amp;CK {e.data.attack_technique} · {e.data.tactic}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}

export default function Timeline({ events }: { events: ArenaEvent[] }) {
  return (
    <div className="split">
      <Feed team="red" events={events} />
      <Feed team="blue" events={events} />
    </div>
  );
}
