import type { InvestigationReport } from "@signaltrace/shared";

type ReportViewProps = {
  status: "idle" | "submitting" | "success" | "error";
  error: string | null;
  report: InvestigationReport | null;
};

export function ReportView({ status, error, report }: ReportViewProps) {
  return (
    <section className="panel" aria-labelledby="report-heading">
      <h2 id="report-heading">Investigation report</h2>

      {status === "idle" && (
        <p className="muted">
          No analysis yet. Submit a message to see a mock structured report.
          Refreshing the page clears everything — nothing is saved.
        </p>
      )}

      {status === "submitting" && (
        <p className="muted">Running mock analysis…</p>
      )}

      {status === "error" && (
        <p className="error" role="alert">
          {error ?? "Analyze failed."}
        </p>
      )}

      {report ? (
        <div className="report-sections">
          <ReportArtifacts artifacts={report.artifacts} />

          <ReportListSection
            title="Observations"
            items={report.observations.map((item) => ({
              primary: item.text,
              quote: item.quote,
            }))}
          />

          <ReportListSection
            title="Evidence"
            items={report.evidence.map((item) => ({
              primary: item.text,
              quote: item.quote,
            }))}
          />

          <ReportListSection
            title="Inferences"
            items={report.inferences.map((item) => ({
              primary: item.text,
              meta: `Confidence: ${item.confidence}`,
            }))}
          />

          <ReportListSection
            title="Unknowns"
            items={report.unknowns.map((item) => ({
              primary: item.text,
            }))}
          />

          <article className="report-section">
            <h3>Confidence</h3>
            <p>
              <strong>{report.confidence.level}</strong>
            </p>
            <p>{report.confidence.rationale}</p>
          </article>

          <ReportListSection
            title="Recommended Next Steps"
            items={report.recommended_next_steps.map((item) => ({
              primary: item.text,
              meta: `Priority: ${item.priority}`,
            }))}
          />
        </div>
      ) : (
        status !== "error" &&
        status !== "submitting" && (
          <div className="report-sections">
            {[
              "Observations",
              "Evidence",
              "Inferences",
              "Unknowns",
              "Confidence",
              "Recommended Next Steps",
            ].map((title) => (
              <article key={title} className="report-section">
                <h3>{title}</h3>
                <p className="placeholder">Waiting for analysis.</p>
              </article>
            ))}
          </div>
        )
      )}
    </section>
  );
}

type ListItem = {
  primary: string;
  quote?: string | null;
  meta?: string;
};

function ReportListSection({
  title,
  items,
}: {
  title: string;
  items: ListItem[];
}) {
  return (
    <article className="report-section">
      <h3>{title}</h3>
      {items.length === 0 ? (
        <p className="placeholder">None listed.</p>
      ) : (
        <ul className="report-list">
          {items.map((item, index) => (
            <li key={`${title}-${index}`}>
              <p>{item.primary}</p>
              {item.meta ? <p className="meta">{item.meta}</p> : null}
              {item.quote ? <blockquote>{item.quote}</blockquote> : null}
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function ReportArtifacts({
  artifacts,
}: {
  artifacts: InvestigationReport["artifacts"];
}) {
  const groups: Array<[string, string[]]> = [
    ["URLs (not visited)", artifacts.urls],
    ["Domains (not resolved)", artifacts.domains],
    ["Emails", artifacts.emails],
    ["Phones", artifacts.phones],
  ];

  const hasAny = groups.some(([, values]) => values.length > 0);
  if (!hasAny) {
    return null;
  }

  return (
    <article className="report-section">
      <h3>Extracted artifacts</h3>
      <p className="muted">
        Listed from the pasted text only. SignalTrace did not visit or look up
        these values.
      </p>
      {groups.map(([label, values]) =>
        values.length > 0 ? (
          <div key={label} className="artifact-group">
            <p className="meta">{label}</p>
            <ul className="report-list">
              {values.map((value) => (
                <li key={`${label}-${value}`}>
                  <code>{value}</code>
                </li>
              ))}
            </ul>
          </div>
        ) : null,
      )}
    </article>
  );
}
