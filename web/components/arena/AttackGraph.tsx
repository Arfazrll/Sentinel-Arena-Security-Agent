"use client";

import { memo, useMemo } from "react";
import ReactFlow, { Background, Controls, Edge, Handle, Node, NodeProps, Position } from "reactflow";
import {
  Crosshair,
  FileJson,
  Flag,
  Home,
  KeyRound,
  Network,
  Search,
  Server,
  ShieldHalf,
  TriangleAlert,
  Users,
  HeartPulse,
} from "lucide-react";
import { DerivedState, NodeId, nodeLabel } from "@/lib/derive";

type NData = {
  title: string;
  sub: string;
  icon: React.ReactNode;
  cls: string;
  badge?: { text: string; color: string; title: string };
};

const SaNode = memo(function SaNode({ data }: NodeProps<NData>) {
  return (
    <div className={`node ${data.cls}`} title={data.badge?.title}>
      <Handle type="target" position={Position.Left} />
      <span className="n-icon">{data.icon}</span>
      <div>
        <div className="n-title">{data.title}</div>
        <div className="n-sub">{data.sub}</div>
      </div>
      {data.badge && (
        <span className="n-badge" style={{ background: data.badge.color }}>
          {data.badge.text}
        </span>
      )}
      <Handle type="source" position={Position.Right} />
      <Handle type="source" id="b" position={Position.Bottom} />
      <Handle type="target" id="t" position={Position.Top} />
    </div>
  );
});

const nodeTypes = { sa: SaNode };

const LAYOUT: Record<NodeId, { x: number; y: number; icon: React.ReactNode }> = {
  attacker: { x: 0, y: 60, icon: <Crosshair size={14} /> },
  users: { x: 0, y: 290, icon: <Users size={14} /> },
  gateway: { x: 200, y: 175, icon: <Network size={14} /> },
  soc: { x: 200, y: 370, icon: <ShieldHalf size={14} /> },
  app: { x: 400, y: 175, icon: <Server size={14} /> },
  home: { x: 610, y: -10, icon: <Home size={14} /> },
  search: { x: 610, y: 80, icon: <Search size={14} /> },
  config: { x: 610, y: 170, icon: <FileJson size={14} /> },
  error: { x: 610, y: 260, icon: <TriangleAlert size={14} /> },
  health: { x: 610, y: 350, icon: <HeartPulse size={14} /> },
  admin: { x: 820, y: 40, icon: <KeyRound size={14} /> },
  flag: { x: 1020, y: 40, icon: <Flag size={14} /> },
};

const SEV_COLOR: Record<string, string> = {
  critical: "var(--critical)",
  high: "var(--serious)",
  medium: "var(--warning)",
  low: "var(--blue)",
  info: "var(--system)",
};

const STATE_WORD: Record<string, string> = {
  idle: "untouched",
  probed: "probed by red",
  vulnerable: "weakness found",
  blocked: "red blocked here",
  breached: "breached",
};

export default function AttackGraph({
  st,
  redLabel,
  blueLabel,
}: {
  st: DerivedState;
  redLabel: string;
  blueLabel: string;
}) {
  const redBlocked = st.blocked.includes("red");
  const usersBlocked = st.nodes.users.state === "blocked";

  const nodes: Node<NData>[] = useMemo(() => {
    return (Object.keys(LAYOUT) as NodeId[]).map((id) => {
      const n = st.nodes[id];
      const L = LAYOUT[id];
      let title = nodeLabel(id, st);
      let sub = STATE_WORD[n.state];
      let cls: string = n.state;
      let badge: NData["badge"];
      if (id === "attacker") {
        title = "Red agent";
        sub = st.flagCaptured ? "captured the flag" : redBlocked ? "blocked at the edge" : redLabel;
        cls = `actor-red ${n.state === "blocked" ? "blocked" : n.state === "breached" ? "breached" : ""}`;
      } else if (id === "users") {
        title = "Real users";
        sub = usersBlocked ? "wrongly blocked" : `${st.traffic.reduce((a, r) => a + r.legit_ok, 0)} requests served`;
        cls = `actor-legit ${usersBlocked ? "blocked" : ""}`;
      } else if (id === "soc") {
        title = "Blue SOC";
        sub = st.detected.length ? `tracking ${st.detected.join(", ")}` : blueLabel;
        cls = "actor-blue";
      } else if (id === "gateway") {
        title = "Edge filter";
        sub = st.blocked.length ? `${st.blocked.length} blocked` : "allow all";
        cls = st.blocked.length ? "blocked" : "";
        if (st.blocked.length) badge = { text: String(st.blocked.length), color: "var(--blue)", title: `Blocked: ${st.blocked.join(", ")}` };
      } else if (id === "app") {
        title = "Corner Shop";
        sub = st.slaOk ? "127.0.0.1 · healthy" : "127.0.0.1 · health failing";
        cls = st.flagCaptured ? "breached" : "";
      }
      if (n.finding) {
        badge = {
          text: "!",
          color: SEV_COLOR[n.finding.severity] || "var(--serious)",
          title: `${n.finding.severity.toUpperCase()}: ${n.finding.title}`,
        };
      } else if (!badge && n.redHits > 0 && !["attacker", "users", "soc", "gateway", "app"].includes(id)) {
        badge = { text: String(n.redHits), color: "var(--red)", title: `${n.redHits} red request(s)` };
      }
      if (n.activeNow) cls += " active";
      if (n.blockedNow) cls += " hit-blocked";
      return {
        id,
        type: "sa",
        position: { x: L.x, y: L.y },
        data: { title, sub, icon: L.icon, cls, badge },
        draggable: true,
      };
    });
  }, [st, redLabel, blueLabel, redBlocked, usersBlocked]);

  const edges: Edge[] = useMemo(() => {
    const N = st.nodes;
    const e: Edge[] = [
      {
        id: "a-g",
        source: "attacker",
        target: "gateway",
        className: redBlocked ? "cut-edge" : "red-edge",
        animated: N.attacker.activeNow && !redBlocked,
        label: redBlocked ? "blocked" : undefined,
      },
      {
        id: "u-g",
        source: "users",
        target: "gateway",
        className: usersBlocked ? "cut-edge" : "legit-edge",
        animated: N.users.activeNow && !usersBlocked,
        label: usersBlocked ? "false block" : undefined,
      },
      { id: "g-a", source: "gateway", target: "app", animated: N.app.activeNow, className: N.attacker.activeNow && !redBlocked ? "red-edge" : "" },
      { id: "app-soc", source: "app", sourceHandle: "b", target: "soc", className: "blue-edge", animated: N.soc.activeNow, label: "logs" },
      { id: "soc-g", source: "soc", target: "gateway", targetHandle: "t", className: "blue-edge", label: "blocks", animated: st.blue_actions.some((a) => a.tick === st.tick && a.kind === "block_ip") },
    ];
    for (const id of ["home", "search", "config", "error", "health"] as NodeId[]) {
      e.push({
        id: `app-${id}`,
        source: "app",
        target: id,
        className: N[id].activeNow ? "red-edge" : "",
        animated: N[id].activeNow,
      });
    }
    e.push({
      id: "home-admin",
      source: "home",
      target: "admin",
      label: st.adminPath ? "leaks hidden path" : undefined,
      className: N.admin.state === "breached" ? "breach-edge" : N.admin.activeNow ? "red-edge" : "",
      animated: N.admin.activeNow,
    });
    e.push({
      id: "admin-flag",
      source: "admin",
      target: "flag",
      label: st.flagCaptured ? "flag read" : undefined,
      className: st.flagCaptured ? "breach-edge" : N.flag.activeNow ? "red-edge" : "",
      animated: N.flag.activeNow,
    });
    return e;
  }, [st, redBlocked, usersBlocked]);

  return (
    <div className="graph-box">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.08 }}
        minZoom={0.3}
        maxZoom={1.6}
        proOptions={{ hideAttribution: true }}
        nodesConnectable={false}
        elementsSelectable={false}
        panOnScroll={false}
        zoomOnScroll={false}
      >
        <Background gap={20} size={1} />
        <Controls showInteractive={false} position="bottom-right" />
      </ReactFlow>
    </div>
  );
}
