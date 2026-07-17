# SignalTrace

Local-first, AI-assisted scam investigation aid. Paste a suspicious email, SMS, or website text and receive a structured report that separates **Observations**, **Evidence**, **Inferences**, **Unknowns**, **Confidence**, and **Recommended Next Steps**.

Phase 1 is an educational / investigative aid for self-help review. It is **not** legal advice, not law-enforcement tooling, and not a definitive determination. You remain responsible for your decisions.

## What Phase 1 does

- Accepts pasted plain text (and optional short context)
- Calls **Google Gemini only** through the local server (`@google/genai`)
- Validates every model response with the shared Zod schema (strict; unexpected keys rejected)
- Allows **one** controlled repair attempt if the first response fails validation
- Overwrites artifacts via server-side extraction and fixes `analysis_scope` to Phase 1 limits
- Runs as a local web app + local API on your machine

## What Phase 1 does not do

- No link visiting, DNS, WHOIS, reputation lookups, browsing, or OSINT
- No authentication, database, or saved cases
- No multi-provider AI support
- No public deployment in this phase

## Privacy warning

**Submitted text is sent to Google (Gemini API)** when Analyze runs in live mode.

Before pasting, remove:

- passwords
- one-time codes
- Social Security numbers
- other unnecessary sensitive information

**Free-tier Gemini data handling may differ from paid-tier handling.** Review Google’s current Gemini API / Google AI terms and data-use documentation for the tier your API key uses. Do not assume training or retention guarantees without checking those terms.

The Gemini API key stays on the **local server only** (`GEMINI_API_KEY`). It must never be placed in frontend env vars.

## Repository status (Issue #3)

- `packages/shared` — Zod report contract + finalize helpers
- `apps/server` — Gemini analyze path, prompt `v1`, structured JSON output, repair-once validation
- `apps/web` — live analyze loading/error states
- `fixtures/` — 10 evaluation fixtures (scam, benign, ambiguous, injection, URL/no-URL, privacy, hallucination, malformed JSON, false reassurance)
- Explicit offline mock only when `ANALYZE_MODE=mock`

## Prerequisites

- Node.js 20+
- npm
- A Google Gemini API key and model id

## Setup

```bash
npm install
npm run build -w @signaltrace/shared
cp apps/server/.env.example apps/server/.env
# Edit apps/server/.env:
#   GEMINI_API_KEY=...
#   GEMINI_MODEL=...   # exact current model id for your free/paid tier
```

## Run locally (two terminals)

Terminal 1 — API:

```bash
npm run dev:server
```

API listens on `http://localhost:8787` by default.

- Health: `GET http://localhost:8787/api/health`
- Analyze: `POST http://localhost:8787/api/analyze` with JSON `{ "message": "...", "context": "..." }`

Terminal 2 — Web:

```bash
npm run dev:web
```

Open `http://localhost:5173`.

### Offline mock (optional)

```bash
ANALYZE_MODE=mock npm run dev:server
```

## Tests

```bash
npm test
npm run build
```

CI uses mocked/scripted Gemini responses. Live provider calls are not required for the default test suite.

## Environment variables

See `apps/server/.env.example`:

| Variable | Purpose |
|----------|---------|
| `GEMINI_API_KEY` | Server-only Gemini API key |
| `GEMINI_MODEL` | Exact Gemini model identifier (configurable as Google changes availability) |
| `PORT` | Local API port (default `8787`) |
| `WEB_ORIGIN` | CORS allowlist for the Vite app (default `http://localhost:5173`) |
| `ANALYZE_MODE` | Set to `mock` for offline mock analysis; omit for live Gemini |

Optional web:

| Variable | Purpose |
|----------|---------|
| `VITE_API_BASE` | API base URL (default `http://localhost:8787`) |

## Error handling (live mode)

| Condition | HTTP | Notes |
|-----------|------|-------|
| Missing/placeholder Gemini credentials | 503 | Fail closed; no silent mock fallback |
| Gemini HTTP 429 / rate limit | 429 | Clear error; no repeated silent retries |
| Provider failure | 502 | Surfaced to the UI |
| Invalid model JSON/schema after one repair | 422 | One repair attempt only |

## Investigation doctrine (product rules)

- Observation before interpretation
- Evidence before conclusion
- Unknown is an acceptable answer
- Confidence is not proof
- No automatic side effects on URLs or domains in Phase 1
