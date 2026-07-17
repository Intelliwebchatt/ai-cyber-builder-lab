import { useState } from "react";
import type { InvestigationReport } from "@signaltrace/shared";
import { AnalyzeForm } from "./components/AnalyzeForm";
import { Disclaimer } from "./components/Disclaimer";
import { ReportView } from "./components/ReportView";

type AppStatus = "idle" | "submitting" | "success" | "error";

const API_BASE = import.meta.env.VITE_API_BASE ?? "http://localhost:8787";

export default function App() {
  const [message, setMessage] = useState("");
  const [context, setContext] = useState("");
  const [status, setStatus] = useState<AppStatus>("idle");
  const [error, setError] = useState<string | null>(null);
  const [errorCode, setErrorCode] = useState<string | null>(null);
  const [report, setReport] = useState<InvestigationReport | null>(null);

  async function handleAnalyze() {
    setStatus("submitting");
    setError(null);
    setErrorCode(null);

    try {
      const response = await fetch(`${API_BASE}/api/analyze`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          message,
          context: context.trim() ? context : undefined,
        }),
      });

      const payload = (await response.json()) as {
        report?: InvestigationReport;
        error?: string;
        code?: string;
      };

      if (!response.ok || !payload.report) {
        setErrorCode(payload.code ?? `http_${response.status}`);
        throw new Error(payload.error ?? "Analyze request failed.");
      }

      setReport(payload.report);
      setStatus("success");
    } catch (err) {
      setReport(null);
      setStatus("error");
      setError(
        err instanceof Error ? err.message : "Analyze request failed.",
      );
    }
  }

  return (
    <div className="app">
      <header className="app-header">
        <p className="brand">SignalTrace</p>
        <h1>Investigate a suspicious message</h1>
        <p className="lede">
          Paste an email, SMS, or website text. SignalTrace returns a structured
          investigation report — without visiting links or scanning domains.
        </p>
        <p className="mode-banner">
          Current mode: <strong>Google Gemini</strong> (server-side only). Set
          `ANALYZE_MODE=mock` on the server for offline mock analysis.
        </p>
      </header>

      <Disclaimer />

      <main className="app-main">
        <AnalyzeForm
          message={message}
          context={context}
          submitting={status === "submitting"}
          onMessageChange={setMessage}
          onContextChange={setContext}
          onAnalyze={handleAnalyze}
        />
        <ReportView
          status={status}
          error={error}
          errorCode={errorCode}
          report={report}
        />
      </main>
    </div>
  );
}
