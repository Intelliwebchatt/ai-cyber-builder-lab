import { useState } from "react";
import { AnalyzeForm } from "./components/AnalyzeForm";
import { Disclaimer } from "./components/Disclaimer";
import { ReportView } from "./components/ReportView";

export default function App() {
  const [message, setMessage] = useState("");
  const [context, setContext] = useState("");

  return (
    <div className="app">
      <header className="app-header">
        <p className="brand">SignalTrace</p>
        <h1>Investigate a suspicious message</h1>
        <p className="lede">
          Paste an email, SMS, or website text. SignalTrace returns a structured
          investigation report — without visiting links or scanning domains.
        </p>
      </header>

      <Disclaimer />

      <main className="app-main">
        <AnalyzeForm
          message={message}
          context={context}
          onMessageChange={setMessage}
          onContextChange={setContext}
        />
        <ReportView />
      </main>
    </div>
  );
}
