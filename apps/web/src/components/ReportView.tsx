const REPORT_SECTIONS = [
  "Observations",
  "Evidence",
  "Inferences",
  "Unknowns",
  "Confidence",
  "Recommended Next Steps",
] as const;

export function ReportView() {
  return (
    <section className="panel" aria-labelledby="report-heading">
      <h2 id="report-heading">Investigation report</h2>
      <p className="muted">
        No analysis yet. After Analyze is wired, results will appear in the
        sections below. Refreshing the page clears everything — nothing is
        saved.
      </p>

      <div className="report-sections">
        {REPORT_SECTIONS.map((title) => (
          <article key={title} className="report-section">
            <h3>{title}</h3>
            <p className="placeholder">Waiting for analysis.</p>
          </article>
        ))}
      </div>
    </section>
  );
}
