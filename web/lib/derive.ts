// Pure derivation: an engagement's event stream (optionally cut at a tick)
// -> everything the arena visuals need. Used by both the live view and replay,
// so the two can never disagree.

import type { ArenaEvent, Severity } from "./api";

export type NodeId =
  | "attacker"
  | "users"
  | "soc"
  | "gateway"
  | "app"
  | "home"
  | "search"
  | "config"
  | "error"
  | "health"
  | "admin"
  | "flag";

export type NodeState = "idle" | "probed" | "vulnerable" | "blocked" | "breached";

export type NodeInfo = {
  state: NodeState;
  redHits: number;
  legitHits: number;
  activeNow: boolean;
  blockedNow: boolean;
  finding?: { title: string; severity: Severity };
  path?: string;
};

export type AgentAction = {
  tick: number;
  kind: string;
  ok: boolean;
  summary: string;
  rationale: string;
  technique?: string;
  techniqueName?: string;
  tactic?: string;
};

export type AgentStatus = "standby" | "active" | "blocked" | "won" | "held" | "stopped";

export type Stage = { key: string; label: string; done: boolean; tick: number | null; active: boolean };

export type Moment = {
  tick: number;
  kind: "finding" | "detect" | "block" | "flag" | "kill" | "false_block";
  label: string;
};

export type TechniqueUse = {
  id: string;
  name: string;
  tactic: string;
  team: "red" | "blue";
  count: number;
  ok: number;
  firstTick: number;
};

export type TrafficRow = {
  tick: number;
  legit_ok: number;
  legit_blocked: number;
  red_ok: number;
  red_blocked: number;
  system: number;
};

export type ScorePoint = { tick: number; red: number; blue: number; resilience: number };

export type DerivedState = {
  tick: number;
  lastTick: number;
  started: boolean;
  finished: boolean;
  ended: string | null;
  resilience: number | null;
  red: number;
  blue: number;
  flagCaptured: boolean;
  series: ScorePoint[];
  nodes: Record<NodeId, NodeInfo>;
  adminPath: string | null;
  flagPath: string | null;
  traffic: TrafficRow[];
  red_actions: AgentAction[];
  blue_actions: AgentAction[];
  redStatus: AgentStatus;
  blueStatus: AgentStatus;
  redStages: Stage[];
  blueStages: Stage[];
  techniques: TechniqueUse[];
  findings: { title: string; owasp: string; severity: Severity; tick: number; url: string }[];
  blocked: string[];
  detected: string[];
  moments: Moment[];
  requestsThisTick: number;
  redBlockedNow: boolean;
  slaOk: boolean;
};

const ENDPOINTS: Record<string, NodeId> = {
  "/": "home",
  "/search": "search",
  "/config.json": "config",
  "/error": "error",
  "/health": "health",
};

const ALL_NODES: NodeId[] = [
  "attacker", "users", "soc", "gateway", "app",
  "home", "search", "config", "error", "health", "admin", "flag",
];

function blankNode(): NodeInfo {
  return { state: "idle", redHits: 0, legitHits: 0, activeNow: false, blockedNow: false };
}

const RANK: Record<NodeState, number> = { idle: 0, probed: 1, blocked: 2, vulnerable: 3, breached: 4 };
function raise(n: NodeInfo, s: NodeState) {
  if (RANK[s] > RANK[n.state]) n.state = s;
}

export function derive(events: ArenaEvent[], uptoTick = Infinity, maxTicks = 12): DerivedState {
  const nodes = Object.fromEntries(ALL_NODES.map((n) => [n, blankNode()])) as Record<NodeId, NodeInfo>;
  const st: DerivedState = {
    tick: -1,
    lastTick: -1,
    started: false,
    finished: false,
    ended: null,
    resilience: null,
    red: 0,
    blue: 0,
    flagCaptured: false,
    series: [],
    nodes,
    adminPath: null,
    flagPath: null,
    traffic: [],
    red_actions: [],
    blue_actions: [],
    redStatus: "standby",
    blueStatus: "standby",
    redStages: [],
    blueStages: [],
    techniques: [],
    findings: [],
    blocked: [],
    detected: [],
    moments: [],
    requestsThisTick: 0,
    redBlockedNow: false,
    slaOk: true,
  };

  // Learn the randomized paths from the whole stream first (they only label
  // nodes; state still respects the cut-off below).
  for (const e of events) {
    if (e.kind === "action" && e.data?.admin_path) st.adminPath = e.data.admin_path;
    if (e.kind === "action" && e.data?.flag_path) st.flagPath = e.data.flag_path;
    if (e.tick > st.lastTick && e.kind !== "request") st.lastTick = e.tick;
  }

  const traffic = new Map<number, TrafficRow>();
  const techniques = new Map<string, TechniqueUse>();
  const blocked = new Set<string>();
  const detected = new Set<string>();
  const stageTick: Record<string, number> = {};
  let currentTick = -1;

  const nodeForPath = (raw: string): NodeId | null => {
    const path = raw.split("?")[0];
    if (ENDPOINTS[path]) return ENDPOINTS[path];
    if (st.adminPath && path === st.adminPath) return "admin";
    if (path.endsWith("-admin")) return "admin";
    if (st.flagPath && path === st.flagPath) return "flag";
    if (path.startsWith("/.well-known")) return null;
    return "flag";
  };

  for (const e of events) {
    if (e.tick > uptoTick) continue;
    if (e.kind === "tick") {
      currentTick = e.tick;
      st.started = true;
    }
    if (e.kind === "engagement_start") st.started = true;
    const t = e.tick >= 0 ? e.tick : currentTick;
    const d = e.data || {};

    switch (e.kind) {
      case "request": {
        const actor = e.actor || "";
        const isBlocked = d.marker === "blocked";
        if (t >= 0) {
          const row = traffic.get(t) || { tick: t, legit_ok: 0, legit_blocked: 0, red_ok: 0, red_blocked: 0, system: 0 };
          if (actor === "red") isBlocked ? row.red_blocked++ : row.red_ok++;
          else if (actor.startsWith("legit")) isBlocked ? row.legit_blocked++ : row.legit_ok++;
          else row.system++;
          traffic.set(t, row);
        }
        const nid = nodeForPath(String(d.path || ""));
        if (!nid) break;
        const n = nodes[nid];
        n.path = String(d.path || "").split("?")[0];
        if (actor === "red") {
          n.redHits++;
          raise(n, isBlocked ? "blocked" : "probed");
        } else if (actor.startsWith("legit")) {
          n.legitHits++;
        }
        break;
      }
      case "finding": {
        const f = {
          title: e.summary,
          owasp: d.owasp,
          severity: d.severity as Severity,
          tick: t,
          url: String(d.url || ""),
        };
        st.findings.push(f);
        st.moments.push({ tick: t, kind: "finding", label: `${d.owasp} ${e.summary}` });
        let path = "/";
        try {
          path = new URL(f.url).pathname;
        } catch {}
        const nid = nodeForPath(path) || "home";
        nodes[nid].finding = { title: f.title, severity: f.severity };
        raise(nodes[nid], "vulnerable");
        break;
      }
      case "action": {
        const a: AgentAction = {
          tick: t,
          kind: d.kind,
          ok: !!d.ok,
          summary: e.summary,
          rationale: d.rationale || "",
          technique: d.attack_technique || undefined,
          techniqueName: d.technique_name || undefined,
          tactic: d.tactic || undefined,
        };
        if (e.team === "red") st.red_actions.push(a);
        else st.blue_actions.push(a);

        if (a.technique) {
          const key = `${e.team}:${a.technique}`;
          const tu = techniques.get(key) || {
            id: a.technique,
            name: a.techniqueName || a.technique,
            tactic: a.tactic || "",
            team: e.team as "red" | "blue",
            count: 0,
            ok: 0,
            firstTick: t,
          };
          tu.count++;
          if (a.ok) tu.ok++;
          techniques.set(key, tu);
        }

        if (e.team === "red") {
          if (d.kind === "recon" && stageTick.recon === undefined) stageTick.recon = t;
          if (d.kind === "enumerate_paths" && stageTick.enumerate === undefined) stageTick.enumerate = t;
          if (d.kind === "detect" && a.ok && stageTick.detect === undefined) stageTick.detect = t;
          if (d.kind === "capture_flag" && a.ok) {
            stageTick.flag = t;
            st.flagCaptured = true;
            nodes.flag.state = "breached";
            nodes.admin.state = "breached";
            st.moments.push({ tick: t, kind: "flag", label: "Flag captured" });
          }
        } else {
          if (d.kind === "query_logs" && stageTick.monitor === undefined) stageTick.monitor = t;
          const suspects: string[] = d.suspects || [];
          for (const s of d.new || []) {
            detected.add(s);
            st.moments.push({ tick: t, kind: "detect", label: `Flagged ${s}` });
          }
          suspects.forEach((s) => detected.add(s));
          if (suspects.includes("red") && stageTick.detectRed === undefined) stageTick.detectRed = t;
          if ((d.kind === "block_ip" || d.kind === "isolate_host") && a.ok) {
            const who = d.actor || "suspects";
            blocked.add(who);
            const legit = String(who).startsWith("legit") || who === "anonymous";
            st.moments.push({
              tick: t,
              kind: legit ? "false_block" : "block",
              label: legit ? `Blocked real user ${who}` : `Blocked ${who}`,
            });
            if (who === "red" && stageTick.contain === undefined) stageTick.contain = t;
          }
        }
        break;
      }
      case "score_tick": {
        st.series.push({ tick: t, red: d.red, blue: d.blue, resilience: d.resilience });
        st.resilience = d.resilience;
        st.red = d.red;
        st.blue = d.blue;
        st.slaOk = d.sla_ok !== false;
        break;
      }
      case "score": {
        st.finished = true;
        st.ended = d.ended || null;
        st.resilience = d.resilience;
        st.red = d.red;
        st.blue = d.blue;
        if (String(d.ended || "").startsWith("killswitch")) {
          st.moments.push({ tick: t, kind: "kill", label: "Kill switch" });
        }
        break;
      }
    }
  }

  st.tick = Math.min(currentTick, uptoTick);
  st.traffic = Array.from(traffic.values()).sort((a, b) => a.tick - b.tick);
  st.techniques = Array.from(techniques.values());
  st.blocked = Array.from(blocked);
  st.detected = Array.from(detected);

  // "Now" highlights: what happened in the current tick.
  const nowRow = traffic.get(st.tick);
  st.requestsThisTick = nowRow ? nowRow.legit_ok + nowRow.legit_blocked + nowRow.red_ok + nowRow.red_blocked + nowRow.system : 0;
  st.redBlockedNow = !!nowRow && nowRow.red_blocked > 0;
  for (const e of events) {
    if (e.kind !== "request" || e.tick !== st.tick || e.tick > uptoTick) continue;
    const nid = nodeForPath(String(e.data?.path || ""));
    if (!nid) continue;
    if (e.actor === "red") {
      nodes[nid].activeNow = true;
      if (e.data?.marker === "blocked") nodes[nid].blockedNow = true;
    }
  }
  nodes.attacker.activeNow = st.red_actions.some((a) => a.tick === st.tick);
  nodes.soc.activeNow = st.blue_actions.some((a) => a.tick === st.tick);
  nodes.users.activeNow = !!nowRow && nowRow.legit_ok + nowRow.legit_blocked > 0;
  nodes.gateway.activeNow = st.requestsThisTick > 0;
  nodes.app.activeNow = st.requestsThisTick > 0;
  if (blocked.has("red")) nodes.attacker.state = "blocked";
  else if (st.red_actions.length) nodes.attacker.state = "probed";
  if (st.flagCaptured) nodes.attacker.state = "breached";
  if (detected.size) nodes.soc.state = "probed";
  if (Array.from(blocked).some((b) => b.startsWith("legit") || b === "anonymous")) nodes.users.state = "blocked";

  // Status + stages
  const stopped = !!st.ended && st.ended.startsWith("killswitch");
  st.redStatus = st.flagCaptured
    ? "won"
    : stopped
    ? "stopped"
    : blocked.has("red")
    ? "blocked"
    : st.red_actions.length
    ? "active"
    : "standby";
  st.blueStatus = stopped
    ? "stopped"
    : st.finished && !st.flagCaptured
    ? "held"
    : st.blue_actions.length
    ? "active"
    : "standby";

  const stage = (key: string, label: string): Stage => ({
    key,
    label,
    done: stageTick[key] !== undefined,
    tick: stageTick[key] ?? null,
    active: false,
  });
  st.redStages = [
    stage("recon", "Recon"),
    stage("enumerate", "Enumerate"),
    stage("detect", "Find weakness"),
    stage("flag", "Capture flag"),
  ];
  st.blueStages = [
    stage("monitor", "Monitor"),
    stage("detectRed", "Detect"),
    stage("contain", "Contain"),
    { key: "hold", label: "Hold to end", done: st.finished && !st.flagCaptured, tick: st.finished && !st.flagCaptured ? st.lastTick : null, active: false },
  ];
  for (const list of [st.redStages, st.blueStages]) {
    const next = list.find((s) => !s.done);
    if (next && st.started && !st.finished) next.active = true;
  }
  void maxTicks;
  return st;
}

export function nodeLabel(id: NodeId, st: DerivedState): string {
  switch (id) {
    case "admin":
      return st.adminPath || "/admin (hidden)";
    case "flag":
      return st.flagPath || "/??? (flag)";
    case "home":
      return "/";
    case "search":
      return "/search";
    case "config":
      return "/config.json";
    case "error":
      return "/error";
    case "health":
      return "/health";
    default:
      return id;
  }
}
