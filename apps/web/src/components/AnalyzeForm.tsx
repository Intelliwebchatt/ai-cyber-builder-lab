import type { FormEvent } from "react";

type AnalyzeFormProps = {
  message: string;
  context: string;
  onMessageChange: (value: string) => void;
  onContextChange: (value: string) => void;
};

export function AnalyzeForm({
  message,
  context,
  onMessageChange,
  onContextChange,
}: AnalyzeFormProps) {
  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    // Issue #1: UI shell only. Analyze wiring arrives in later issues.
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
          />
        </label>

        <button type="submit" disabled>
          Analyze (coming in a later issue)
        </button>
      </form>
    </section>
  );
}
