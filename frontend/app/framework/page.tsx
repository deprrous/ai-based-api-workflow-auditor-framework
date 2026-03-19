import { WorkflowScreen } from "@/features/workflow/workflow-screen";
import { getFrameworkPrincipleGraph } from "@/lib/api";
import type { ScanEvent } from "@/lib/types";
import type { ScanRunSummary } from "@/lib/types";

export const dynamic = "force-dynamic";

const frameworkEvents: ScanEvent[] = [];

const frameworkScanStub: ScanRunSummary = {
  id: "framework-principle",
  name: "Framework Principle",
  status: "completed",
  target: "reference-view",
  created_at: new Date("2026-03-19T00:00:00.000Z").toISOString(),
  current_stage: "reporting",
  findings_count: 0,
  flagged_paths: 3,
  risk: "safe",
  workflow_id: "framework-principle",
};

export default async function FrameworkPrinciplePage() {
  const graph = await getFrameworkPrincipleGraph();

  return (
    <WorkflowScreen
      initialScan={frameworkScanStub}
      initialGraph={graph}
      initialEvents={frameworkEvents}
      backHref="/"
      backLabel="Back to dashboard"
    />
  );
}
