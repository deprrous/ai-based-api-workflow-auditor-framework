import Link from "next/link";

export default function NotFoundPage() {
  return (
    <main className="page page-grid">
      <section className="hero-card">
        <span className="eyebrow">Not found</span>
        <h1 className="page-title">That workflow view does not exist yet.</h1>
        <p className="lead">The scan id may be wrong, or the backend has not created a workflow graph for it yet.</p>
        <div className="toolbar-row">
          <Link href="/" className="link-chip">
            Return to dashboard
          </Link>
        </div>
      </section>
    </main>
  );
}
