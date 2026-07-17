export function Disclaimer() {
  return (
    <aside className="disclaimer" role="note">
      <h2 className="disclaimer-title">Before you paste</h2>
      <ul>
        <li>
          Current Analyze mode is a <strong>local mock</strong> and does not
          call Gemini. When live analysis is enabled later, submitted text will
          be sent to <strong>Google Gemini</strong>. Remove passwords, one-time
          codes, Social Security numbers, and other unnecessary sensitive
          information before using live analysis.
        </li>
        <li>
          Phase 1 does <strong>not</strong> visit links, resolve DNS, query
          WHOIS, or call reputation services. URLs in your paste are treated as
          text only.
        </li>
        <li>
          SignalTrace is an educational and investigative aid — not legal advice
          and not a definitive determination. You remain responsible for your
          decisions.
        </li>
        <li>
          Free-tier Gemini data handling may differ from paid-tier handling.
          Review Google&apos;s current Gemini API / Google AI terms before use.
        </li>
      </ul>
    </aside>
  );
}
