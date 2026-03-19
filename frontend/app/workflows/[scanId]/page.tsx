import { notFound } from "next/navigation";

import { WorkflowScreen } from "@/features/workflow/workflow-screen";
import { getScan, getScanEvents, getScanWorkflow } from "@/lib/api";

export const dynamic = "force-dynamic";

interface WorkflowPageProps {
  params: Promise<{
    scanId: string;
  }>;
}

export default async function WorkflowPage({ params }: WorkflowPageProps) {
  const { scanId } = await params;

  try {
    const [scan, graph, events] = await Promise.all([getScan(scanId), getScanWorkflow(scanId), getScanEvents(scanId)]);

    return (
      <WorkflowScreen
        initialScan={scan}
        initialGraph={graph}
        initialEvents={events}
        backHref="/"
        backLabel="Back to dashboard"
      />
    );
  } catch {
    notFound();
  }
}
