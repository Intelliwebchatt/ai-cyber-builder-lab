# AI security and governance

This track examines security, privacy, reliability, and governance across AI-enabled systems.

## Active portfolio project: SignalTrace

[SignalTrace](../README.md) is the active Phase 1 AI-enabled application at the repository root. It calls Google Gemini only through the local server and produces a structured investigation report. The controls below are already implemented; this track does not claim additional AI-security work beyond the current product.

### Existing AI-security and governance controls

- **Provider boundary:** live analysis uses Google Gemini only (`@google/genai`); the API key remains on the local server.
- **Structured output + schema validation:** model JSON is constrained and validated; unexpected keys are rejected.
- **One controlled repair:** if the first response fails validation, exactly one repair attempt is allowed; further failures return 422.
- **Server-enforced invariants:** artifacts are extracted server-side from the pasted text; `analysis_scope` is overwritten to Phase 1 performed / not-performed lists.
- **Unsupported-verification screening:** validation checks key report fields for defined phrases that suggest unperformed WHOIS, DNS, reputation, link-visit, or external-verification claims.
- **Prompt versioning:** analysis uses an explicit prompt version (`v1`) with a dedicated repair prompt.
- **Evaluation fixtures:** `fixtures/` covers scam, benign, ambiguous, injection, URL/no-URL, privacy, hallucination, malformed JSON, and false-reassurance cases; automated tests use mocked/scripted Gemini responses; live provider calls are not required.
- **Privacy disclosure:** the product warns that submitted text is sent to Google when Analyze runs in live mode, and asks users to strip passwords, OTPs, SSNs, and other sensitive data first.
- **Investigation doctrine:** observation before interpretation, evidence before conclusion, unknowns allowed, confidence is not proof, and no automatic side effects on URLs or domains.

## Planned projects

- AI system and data inventory beyond the current Phase 1 surface
- expanded prompt-injection and sensitive-data-disclosure test plans
- tool-permission and excessive-agency assessment (when tools are introduced)
- evaluation dataset and human-review controls beyond the current fixture set
- NIST AI RMF risk profile
- responsible-use, retention, and incident policies

**Status:** SignalTrace Phase 1 is active. Broader AI security and governance labs remain planned and will use owned or authorized AI applications and synthetic data.
