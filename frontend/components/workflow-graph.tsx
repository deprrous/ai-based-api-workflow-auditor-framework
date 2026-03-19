"use client";

import {
  Background,
  Controls,
  Handle,
  MarkerType,
  MiniMap,
  Panel,
  Position,
  ReactFlow,
  type Edge,
  type Node,
  type NodeProps,
} from "@xyflow/react";
import { useMemo } from "react";

import { formatNodeType, formatPhase, formatStatus } from "@/lib/format";
import type { WorkflowGraph, WorkflowNodeStatus, WorkflowNodeType } from "@/lib/types";

type AuditNodeData = Record<string, unknown> & {
  label: string;
  type: WorkflowNodeType;
  phase: string;
  detail: string | null;
  status: WorkflowNodeStatus;
};

function AuditNode({ data }: NodeProps<Node<AuditNodeData>>) {
  return (
    <div className={`audit-node audit-node--${data.status}`}>
      <Handle type="target" position={Position.Left} style={{ opacity: 0 }} />
      <div className="audit-node__body">
        <div className="audit-node__topline">
          <span className="audit-node__type">{formatNodeType(data.type)}</span>
          <span className={`badge badge--node-${data.status}`}>{formatStatus(data.status)}</span>
        </div>
        <h3 className="node-title">{data.label}</h3>
        {data.detail ? <p className="audit-node__detail">{data.detail}</p> : null}
        <span className="audit-node__phase">Phase: {formatPhase(data.phase)}</span>
      </div>
      <Handle type="source" position={Position.Right} style={{ opacity: 0 }} />
    </div>
  );
}

const nodeTypes = {
  audit: AuditNode,
};

interface WorkflowGraphProps {
  graph: WorkflowGraph;
}

export function WorkflowGraphView({ graph }: WorkflowGraphProps) {
  const nodes = useMemo<Node<AuditNodeData>[]>(
    () =>
      graph.nodes.map((node) => ({
        id: node.id,
        type: "audit",
        draggable: false,
        selectable: true,
        position: { x: node.x, y: node.y },
        data: {
          label: node.label,
          type: node.type,
          phase: node.phase,
          detail: node.detail,
          status: node.status,
        },
      })),
    [graph.nodes],
  );

  const edges = useMemo<Edge[]>(
    () =>
      graph.edges.map((edge, index) => ({
        id: `${edge.source}-${edge.target}-${index}`,
        source: edge.source,
        target: edge.target,
        label: edge.label ?? undefined,
        animated: edge.animated,
        markerEnd: {
          type: MarkerType.ArrowClosed,
          color: "#587164",
        },
        style:
          edge.style === "dashed"
            ? { stroke: "#587164", strokeWidth: 1.6, strokeDasharray: "7 7" }
            : { stroke: "#587164", strokeWidth: 1.8 },
        labelStyle: {
          fill: "#44564d",
          fontWeight: 600,
          fontSize: 12,
        },
        labelBgStyle: {
          fill: "rgba(255,255,255,0.92)",
          fillOpacity: 1,
          stroke: "rgba(19,35,29,0.12)",
        },
        labelBgBorderRadius: 10,
        labelBgPadding: [6, 4],
      })),
    [graph.edges],
  );

  return (
    <div className="graph-frame">
      <ReactFlow
        nodes={nodes}
        edges={edges}
        nodeTypes={nodeTypes}
        fitView
        fitViewOptions={{ padding: 0.16 }}
        minZoom={0.15}
        maxZoom={1.3}
        nodesDraggable={false}
        nodesConnectable={false}
        elementsSelectable
        proOptions={{ hideAttribution: true }}
      >
        <Background gap={18} size={1.2} color="rgba(18,35,29,0.08)" />
        <MiniMap
          pannable
          zoomable
          nodeStrokeColor={(node) => {
            const status = (node.data as unknown as AuditNodeData).status;
            if (status === "critical") return "#b54036";
            if (status === "high") return "#b85d16";
            if (status === "review") return "#c27820";
            if (status === "safe") return "#0d8f74";
            return "#126b52";
          }}
          nodeColor={(node) => {
            const status = (node.data as unknown as AuditNodeData).status;
            if (status === "critical") return "rgba(181,64,54,0.18)";
            if (status === "high") return "rgba(184,93,22,0.18)";
            if (status === "review") return "rgba(194,120,32,0.18)";
            if (status === "safe") return "rgba(13,143,116,0.18)";
            return "rgba(18,107,82,0.18)";
          }}
        />
        <Controls showInteractive={false} />
        <Panel position="top-left">{graph.kind === "scan_run" ? "Scan workflow" : "Framework principle"}</Panel>
      </ReactFlow>
    </div>
  );
}
