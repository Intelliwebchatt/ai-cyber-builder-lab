# Application security

This track applies security engineering to full-stack and AI-enabled applications.

## Active portfolio project: SignalTrace

[SignalTrace](../README.md) is the active Phase 1 application at the repository root (`apps/`, `packages/`, `fixtures/`). It is a local-first, AI-assisted scam investigation aid. The controls below are already implemented in the current codebase; this track does not claim additional controls beyond what ships today.

### Existing application-security controls

- **Input bounds:** pasted message and optional context are capped (`MAX_MESSAGE_CHARS` / `MAX_CONTEXT_CHARS`) before analysis.
- **Strict response contract:** every model response is validated with a shared Zod schema that rejects unexpected keys.
- **Server-side invariants:** artifact extraction overwrites model-supplied artifacts, and `analysis_scope` is fixed to Phase 1 limits (no URL visit, DNS, WHOIS, reputation, or OSINT).
- **Browser-origin policy:** CORS response headers are configured for `WEB_ORIGIN`; this is browser-enforced and does not replace authentication or server-side authorization.
- **Secrets stay server-only:** `GEMINI_API_KEY` is read from the local server environment and must never be placed in frontend env vars.
- **Fail closed:** missing or placeholder Gemini credentials return 503; there is no silent mock fallback in live mode.
- **Local Phase 1 scope:** no authentication database, saved cases, or public deployment in this phase.

## Planned projects

- application threat model and data-flow diagram
- authentication and authorization tests
- API rate-limiting review
- secrets and dependency-management controls beyond current local `.env` handling
- database access-policy assessment (when persistence is introduced)
- OWASP-aligned findings, remediation, and regression tests

**Status:** SignalTrace Phase 1 is active. Broader AppSec labs remain planned and will use owned applications or purpose-built local labs.
