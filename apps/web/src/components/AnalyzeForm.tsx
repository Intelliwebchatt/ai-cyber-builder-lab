import type { FormEvent } from "react";

type AnalyzeFormProps = {
  message: string;
  context: string;
  submitting: boolean;
  onMessageChange: (value: string) => void;
  onContextChange: (value: string) => void;
  onAnalyze: () => void | Promise<void>;
};

export function AnalyzeForm({
  message,
  context,
  submitting,
  onMessageChange,
  onContextChange,
  onAnalyze,
}: AnalyzeFormProps) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    void onAnalyze();
  }

  return (
    <section className="panel" aria-labelledby="analyze-heading">
      <h2 id="analyze-heading">Analyze</h2>
      <form className="analyze-form" onSubmit={handleSubmit}>
        <label className="field">
          <span>Suspicious message</span>
          <textarea
            name="message"
            rows={12}
            value={message}
            onChange={(event) => onMessageChange(event.target.value)}
            placeholder="Paste the email body, SMS text, or website copy here."
            required
            disabled={submitting}
          />
        </label>

        <label className="field">
          <span>Optional context</span>
          <textarea
            name="context"
            rows={3}
            value={context}
            onChange={(event) => onContextChange(event.target.value)}
            placeholder='Example: "Claimed to be from my bank."'
            disabled={submitting}
          />
        </label>

        <button type="submit" disabled={submitting || message.trim().length === 0}>
          {submitting ? "Analyzing…" : "Analyze (mock)"}
        </button>
      </form>
    </section>
  );
}
