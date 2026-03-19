import { DashboardHome } from "@/features/dashboard/dashboard-home";
import { getFrameworkPrincipleGraph, listScans } from "@/lib/api";

export const dynamic = "force-dynamic";

export default async function HomePage() {
  const [scans, frameworkGraph] = await Promise.all([listScans(), getFrameworkPrincipleGraph()]);

  return <DashboardHome scans={scans} frameworkGraph={frameworkGraph} />;
}
