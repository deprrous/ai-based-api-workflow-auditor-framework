import Link from "next/link";

import { WorkflowGraphView } from "@/components/workflow-graph";
import { countNodeStates, formatDateTime, formatPhase, formatStatus } from "@/lib/format";
import type { ScanRunSummary, WorkflowGraph } from "@/lib/types";

interface WorkflowScreenProps {
  scan: ScanRunSummary;
  graph: WorkflowGraph;
  backHref: string;
  backLabel: string;
}

export function WorkflowScreen({ scan, graph, backHref, backLabel }: WorkflowScreenProps) {
  const nodeCounts = countNodeStates(graph.nodes.map((node) => node.status));
  const topPhases = Array.from(new Set(graph.nodes.map((node) => node.phase)));

  return (
    <main className="page page-grid">
      <div>
        <Link href={backHref} className="back-link">
          ← {backLabel}
        </Link>
      </div>

      <section className="hero-card">
        <div className="hero-row">
          <div className="hero-summary">
            <span className="eyebrow">{graph.kind === "scan_run" ? "Persisted scan workflow" : "Framework work principle"}</span>
            <h1 className="page-title">{graph.title}</h1>
            <p className="lead">{graph.description}</p>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <div>
                <h2 className="panel-title">Run Snapshot</h2>
                <p className="panel-copy">The graph and summary cards use the same backend payloads served by the FastAPI API.</p>
              </div>
            </div>
            <div className="badge-row">
              <span className={`badge badge--status-${scan.status}`}>{formatStatus(scan.status)}</span>
              <span className={`badge badge--risk-${scan.risk}`}>{formatStatus(scan.risk)} risk</span>
              <span className="badge">Stage: {formatPhase(scan.current_stage)}</span>
            </div>
            <dl className="detail-list">
              <div>
                <strong>Target</strong>: {scan.target ?? "No target configured"}
              </div>
              <div>
                <strong>Updated</strong>: {formatDateTime(graph.updated_at)}
              </div>
              <div>
                <strong>Findings</strong>: {scan.findings_count}
              </div>
              <div>
                <strong>Flagged paths</strong>: {scan.flagged_paths}
              </div>
            </dl>
          </div>
        </div>

        <div className="metric-grid">
          <article className="metric-card">
            <span className="metric-label">Nodes</span>
            <strong className="metric-value">{graph.stats.node_count}</strong>
            <span className="metric-note">Workflow units rendered in the graph.</span>
          </article>
          <article className="metric-card">
            <span className="metric-label">Edges</span>
            <strong className="metric-value">{graph.stats.edge_count}</strong>
            <span className="metric-note">Transitions between API actions and evidence.</span>
          </article>
          <article className="metric-card">
            <span className="metric-label">Critical nodes</span>
            <strong className="metric-value">{graph.stats.critical_nodes}</strong>
            <span className="metric-note">Places with confirmed or likely high-impact exposure.</span>
          </article>
          <article className="metric-card">
            <span className="metric-label">Phases</span>
            <strong className="metric-value">{topPhases.length}</strong>
            <span className="metric-note">Distinct phases represented in this workflow.</span>
          </article>
        </div>
      </section>

      <section className="workflow-layout">
        <section className="graph-card">
          <div className="section-heading">
            <div>
              <h2 className="section-title">Workflow Graph</h2>
              <p className="section-copy">Rendered with React Flow from the persisted graph model returned by the backend.</p>
            </div>
          </div>

          <WorkflowGraphView graph={graph} />
        </section>

        <aside className="legend-card">
          <div className="section-heading">
            <div>
              <h2 className="section-title">Status Legend</h2>
              <p className="section-copy">Use node states to quickly locate where the auditor found exploitable or risky behavior.</p>
            </div>
          </div>

          <div className="legend-grid">
            <div className="legend-item">
              <span className="legend-swatch legend-swatch--safe" />
              <strong>Safe</strong>
              <p className="muted-copy">Expected path with no active issue at the node.</p>
            </div>
            <div className="legend-item">
              <span className="legend-swatch legend-swatch--active" />
              <strong>Active</strong>
              <p className="muted-copy">Currently used for correlation, replay, or graph assembly.</p>
            </div>
            <div className="legend-item">
              <span className="legend-swatch legend-swatch--review" />
              <strong>Review</strong>
              <p className="muted-copy">Interesting path or action that still needs confirmation.</p>
            </div>
            <div className="legend-item">
              <span className="legend-swatch legend-swatch--critical" />
              <strong>Critical</strong>
              <p className="muted-copy">Confirmed or strongly evidenced exploit path.</p>
            </div>
          </div>

          <div className="panel" style={{ marginTop: 18 }}>
            <div className="section-heading">
              <div>
                <h2 className="section-title">Node State Counts</h2>
                <p className="section-copy">Quick distribution of the current graph status.</p>
              </div>
            </div>

            <div className="badge-row">
              <span className="badge badge--node-safe">Safe {nodeCounts.safe}</span>
              <span className="badge badge--node-active">Active {nodeCounts.active}</span>
              <span className="badge badge--node-review">Review {nodeCounts.review}</span>
              <span className="badge badge--node-high">High {nodeCounts.high}</span>
              <span className="badge badge--node-critical">Critical {nodeCounts.critical}</span>
            </div>
          </div>

          <div className="panel" style={{ marginTop: 18 }}>
            <div className="section-heading">
              <div>
                <h2 className="section-title">Phase Coverage</h2>
                <p className="section-copy">The same graph can mix auth, read, action, verification, and reporting phases.</p>
              </div>
            </div>

            <ul className="phase-list">
              {topPhases.map((phase) => (
                <li key={phase}>{formatPhase(phase)}</li>
              ))}
            </ul>
          </div>
        </aside>
      </section>
    </main>
  );
}
