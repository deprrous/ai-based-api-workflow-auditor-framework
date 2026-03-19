import Link from "next/link";

import { formatDateTime, formatPhase, formatStatus } from "@/lib/format";
import type { ScanRunSummary, WorkflowGraph } from "@/lib/types";

interface DashboardHomeProps {
  scans: ScanRunSummary[];
  frameworkGraph: WorkflowGraph;
}

export function DashboardHome({ scans, frameworkGraph }: DashboardHomeProps) {
  return (
    <main className="page page-grid">
      <section className="hero-card">
        <div className="hero-row">
          <div className="hero-summary">
            <span className="eyebrow">Workflow-driven agentic auditing</span>
            <h1 className="page-title">Powerful API audit flows that stay understandable.</h1>
            <p className="lead">
              The dashboard is now wired to real backend scan runs. Each run owns its own persisted workflow graph,
              while the framework principle remains available as a separate reference view.
            </p>
          </div>

          <div className="panel">
            <div className="panel-heading">
              <div>
                <h2 className="panel-title">Framework Principle</h2>
                <p className="panel-copy">Use the framework view to explain how the orchestrator reasons, acts, and reflects.</p>
              </div>
              <Link href="/framework" className="link-chip">
                Open principle graph
              </Link>
            </div>
            <div className="metric-grid">
              <article className="metric-card">
                <span className="metric-label">Nodes</span>
                <strong className="metric-value">{frameworkGraph.stats.node_count}</strong>
                <span className="metric-note">Core stages in the framework loop.</span>
              </article>
              <article className="metric-card">
                <span className="metric-label">Edges</span>
                <strong className="metric-value">{frameworkGraph.stats.edge_count}</strong>
                <span className="metric-note">Reasoning and observation transitions.</span>
              </article>
              <article className="metric-card">
                <span className="metric-label">Critical Nodes</span>
                <strong className="metric-value">{frameworkGraph.stats.critical_nodes}</strong>
                <span className="metric-note">Places where confirmed risk becomes visible.</span>
              </article>
              <article className="metric-card">
                <span className="metric-label">Flagged Paths</span>
                <strong className="metric-value">{frameworkGraph.stats.flagged_paths}</strong>
                <span className="metric-note">High-risk routes through the principle graph.</span>
              </article>
            </div>
          </div>
        </div>
      </section>

      <section className="dashboard-layout">
        <div className="panel">
          <div className="section-heading">
            <div>
              <h2 className="section-title">Active and Historical Scan Runs</h2>
              <p className="section-copy">Each scan now owns a backend workflow model instead of reusing the demo graph.</p>
            </div>
          </div>

          <div className="scan-list">
            {scans.map((scan) => (
              <article className="scan-card" key={scan.id}>
                <div className="scan-topline">
                  <div>
                    <h3 className="scan-title">{scan.name}</h3>
                    <div className="scan-meta">
                      {scan.target ?? "No target"} · updated {formatDateTime(scan.created_at)}
                    </div>
                  </div>
                </div>

                <div className="badge-row">
                  <span className={`badge badge--status-${scan.status}`}>{formatStatus(scan.status)}</span>
                  <span className={`badge badge--risk-${scan.risk}`}>{formatStatus(scan.risk)} risk</span>
                  <span className="badge">Stage: {formatPhase(scan.current_stage)}</span>
                </div>

                <div className="metric-row scan-meta">
                  <span>{scan.findings_count} findings</span>
                  <span>·</span>
                  <span>{scan.flagged_paths} flagged paths</span>
                  <span>·</span>
                  <span>{scan.workflow_id}</span>
                </div>

                <div className="scan-footer">
                  <Link href={`/workflows/${scan.id}`} className="link-chip">
                    Open workflow
                  </Link>
                </div>
              </article>
            ))}
          </div>
        </div>

        <aside className="legend-card">
          <div className="section-heading">
            <div>
              <h2 className="section-title">What Changed</h2>
              <p className="section-copy">The frontend is now connected to persisted workflow data served by the FastAPI backend.</p>
            </div>
          </div>

          <div className="note-grid">
            <article className="legend-item">
              <strong>Real scan linkage</strong>
              <p className="muted-copy">Workflow pages fetch `GET /api/v1/scans/{'{scanId}'}/workflow` instead of rendering a static demo.</p>
            </article>
            <article className="legend-item">
              <strong>Framework principle preserved</strong>
              <p className="muted-copy">The framework diagram still exists, but it is now treated as a separate explanatory view.</p>
            </article>
            <article className="legend-item">
              <strong>React Flow ready</strong>
              <p className="muted-copy">Nodes carry positions, statuses, and phases so the graph UI can render immediately.</p>
            </article>
          </div>
        </aside>
      </section>
    </main>
  );
}
