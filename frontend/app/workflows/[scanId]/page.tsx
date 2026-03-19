import { notFound } from "next/navigation";

import { WorkflowScreen } from "@/features/workflow/workflow-screen";
import { getScan, getScanWorkflow } from "@/lib/api";

export const dynamic = "force-dynamic";

interface WorkflowPageProps {
  params: Promise<{
    scanId: string;
  }>;
}

export default async function WorkflowPage({ params }: WorkflowPageProps) {
  const { scanId } = await params;

  try {
    const [scan, graph] = await Promise.all([getScan(scanId), getScanWorkflow(scanId)]);

    return <WorkflowScreen scan={scan} graph={graph} backHref="/" backLabel="Back to dashboard" />;
  } catch {
    notFound();
  }
}
