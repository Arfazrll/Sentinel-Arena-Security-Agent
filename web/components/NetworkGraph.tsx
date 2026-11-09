"use client";

import { useMemo } from "react";
import ReactFlow, { Background, Controls, Edge, Node } from "reactflow";

// Fixed topology of the sandbox target. Nodes light up as the engagement
// reaches them (derived from the event stream).
const BASE_NODES: { id: string; label: string; x: number; y: number }[] = [
  { id: "operator", label: "operator", x: 0, y: 120 },
  { id: "target", label: "127.0.0.1", x: 180, y: 120 },
  { id: "/", label: "/", x: 380, y: 20 },
  { id: "/search", label: "/search", x: 380, y: 80 },
  { id: "/config.json", label: "/config.json", x: 380, y: 140 },
  { id: "/error", label: "/error", x: 380, y: 200 },
  { id: "admin", label: "admin", x: 560, y: 110 },
  { id: "flag", label: "flag", x: 720, y: 110 },
];

const BASE_EDGES: Edge[] = [
  { id: "e0", source: "operator", target: "target", animated: true },
  { id: "e1", source: "target", target: "/" },
  { id: "e2", source: "target", target: "/search" },
  { id: "e3", source: "target", target: "/config.json" },
  { id: "e4", source: "target", target: "/error" },
  { id: "e5", source: "/", target: "admin", label: "leak" },
  { id: "e6", source: "admin", target: "flag", label: "leak" },
];

export default function NetworkGraph({ lit }: { lit: Set<string> }) {
  const nodes: Node[] = useMemo(
    () =>
      BASE_NODES.map((n) => {
        const isLit = lit.has(n.id);
        const isFlag = n.id === "flag";
        const accent = isFlag ? "#ef4444" : "#3b82f6";
        return {
          id: n.id,
          position: { x: n.x, y: n.y },
          data: { label: n.label },
          style: {
            fontSize: 11,
            padding: "6px 10px",
            borderRadius: 8,
            border: `1px solid ${isLit ? accent : "#232833"}`,
            background: isLit ? "#1e293b" : "#13161d",
            color: isLit ? "#e8eaed" : "#8b93a1",
            boxShadow: isLit ? `0 0 0 1px ${accent}` : "none",
          },
        };
      }),
    [lit]
  );

  return (
    <div className="graphbox">
      <ReactFlow
        nodes={nodes}
        edges={BASE_EDGES}
        fitView
        proOptions={{ hideAttribution: true }}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable={false}
      >
        <Background color="#232833" gap={18} />
        <Controls showInteractive={false} />
      </ReactFlow>
    </div>
  );
}
