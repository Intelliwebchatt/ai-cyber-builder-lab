import type { InvestigationReport } from "@signaltrace/shared";

type ReportViewProps = {
  status: "idle" | "submitting" | "success" | "error";
  error: string | null;
  errorCode?: string | null;
  report: InvestigationReport | null;
};

export function ReportView({ status, error, errorCode, report }: ReportViewProps) {
  return (
    <section className="panel" aria-labelledby="report-heading">
      <h2 id="report-heading">Investigation report</h2>

      {status === "idle" && (
        <p className="muted">
          No analysis yet. Submit a message to generate a structured report.
          Refreshing the page clears everything — nothing is saved.
        </p>
      )}

      {status === "submitting" && (
        <p className="muted" aria-live="polite">
          Contacting Gemini and validating the investigation report…
        </p>
      )}

      {status === "error" && (
        <div className="error" role="alert">
          <p>{error ?? "Analyze failed."}</p>
          {errorCode ? <p className="meta">Error code: {errorCode}</p> : null}
          {errorCode === "rate_limited" ? (
            <p className="meta">
              Gemini rate-limited this request. Wait before trying again —
              SignalTrace does not silently retry 429 responses.
            </p>
          ) : null}
          {errorCode === "missing_credentials" ? (
            <p className="meta">
              Configure `GEMINI_API_KEY` and `GEMINI_MODEL` in
              `apps/server/.env`, then restart the server.
            </p>
          ) : null}
        </div>
      )}

      {report ? (
        <div className="report-sections">
          <AnalysisScope scope={report.analysis_scope} />
          <ReportArtifacts artifacts={report.artifacts} />
          <ObservationsSection observations={report.observations} />

          <ReportListSection
            title="Inferences"
            items={report.inferences.map((item) => ({
              primary: item.text,
              meta: `Confidence: ${item.confidence} · Based on: ${item.based_on.join(", ")}`,
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
              "Analysis Scope",
              "Observations (with nested Evidence)",
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

function ObservationsSection({
  observations,
}: {
  observations: InvestigationReport["observations"];
}) {
  return (
    <article className="report-section">
      <h3>Observations</h3>
      <p className="muted">
        Evidence is nested under each observation to keep support traceable.
      </p>
      {observations.length === 0 ? (
        <p className="placeholder">None listed.</p>
      ) : (
        <ul className="report-list">
          {observations.map((observation) => (
            <li key={observation.id}>
              <p>
                <span className="id-chip">{observation.id}</span>{" "}
                {observation.text}
              </p>
              {observation.quote ? (
                <blockquote>{observation.quote}</blockquote>
              ) : null}

              <div className="nested-evidence">
                <p className="meta">Evidence</p>
                {observation.evidence.length === 0 ? (
                  <p className="placeholder">No supporting evidence listed.</p>
                ) : (
                  <ul className="report-list">
                    {observation.evidence.map((item) => (
                      <li key={item.id}>
                        <p>
                          <span className="id-chip">{item.id}</span> {item.text}
                        </p>
                        {item.quote ? <blockquote>{item.quote}</blockquote> : null}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </li>
          ))}
        </ul>
      )}
    </article>
  );
}

function AnalysisScope({
  scope,
}: {
  scope: InvestigationReport["analysis_scope"];
}) {
  return (
    <article className="report-section">
      <h3>Analysis Scope</h3>
      <div className="scope-grid">
        <div>
          <p className="meta">Performed</p>
          <ul className="report-list">
            {scope.performed.map((item) => (
              <li key={`performed-${item}`}>{item}</li>
            ))}
          </ul>
        </div>
        <div>
          <p className="meta">Not performed</p>
          <ul className="report-list">
            {scope.not_performed.map((item) => (
              <li key={`not-performed-${item}`}>{item}</li>
            ))}
          </ul>
        </div>
      </div>
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
        Extracted on the server from the pasted text only. SignalTrace did not
        visit or look up these values.
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
