# SignalTrace

Local-first, AI-assisted scam investigation aid. Paste a suspicious email, SMS, or website text and receive a structured report that separates **Observations**, **Evidence**, **Inferences**, **Unknowns**, **Confidence**, and **Recommended Next Steps**.

Phase 1 is an educational / investigative aid for self-help review. It is **not** legal advice, not law-enforcement tooling, and not a definitive determination. You remain responsible for your decisions.

## What Phase 1 does

- Accepts pasted plain text (and optional short context)
- Returns a structured investigation report through `POST /api/analyze`
- Runs as a local web app + local API on your machine
- Will call **Google Gemini only** in a later issue (not yet wired)

## What Phase 1 does not do

- No link visiting, DNS, WHOIS, reputation lookups, or OSINT
- No authentication, database, or saved cases
- No multi-provider AI support
- **No Gemini / model calls in the current Issue #2 mock mode**

## Privacy warning

**Mock mode (current):** Analyze does not send text to Google.

**When live Gemini analysis is enabled later:** submitted text will be sent to Google (Gemini API).

Before using live analysis, remove:

- passwords
- one-time codes
- Social Security numbers
- other unnecessary sensitive information

**Free-tier Gemini data handling may differ from paid-tier handling.** Review Google’s current Gemini API / Google AI terms and data-use documentation for the tier your API key uses. Do not assume training or retention guarantees without checking those terms.

The Gemini API key stays on the **local server only** (`GEMINI_API_KEY`). It must never be placed in frontend env vars.

## Repository status (Issue #2)

- `packages/shared` — Zod investigation report + analyze request schemas
- `apps/server` — `GET /api/health`, mocked `POST /api/analyze`
- `apps/web` — Analyze form wired to mock API; renders all report sections
- Schema validation tests in shared + mocked analyze route tests on server
- No Gemini SDK and no real model calls

## Prerequisites

- Node.js 20+
- npm
- A Google Gemini API key (needed for later issues; unused by mock analyze)

## Setup

```bash
npm install
npm run build -w @signaltrace/shared
cp apps/server/.env.example apps/server/.env
# GEMINI_* values are unused in mock mode; required in a later issue
```

## Run locally (two terminals)

Terminal 1 — API:

```bash
npm run dev:server
```

API listens on `http://localhost:8787` by default.

- Health: `GET http://localhost:8787/api/health`
- Analyze (mock): `POST http://localhost:8787/api/analyze` with JSON `{ "message": "...", "context": "..." }`

Terminal 2 — Web:

```bash
npm run dev:web
```

Open `http://localhost:5173`.

## Tests

```bash
npm test
```

## Environment variables

See `apps/server/.env.example`:

| Variable | Purpose |
|----------|---------|
| `GEMINI_API_KEY` | Server-only Gemini API key (later issue) |
| `GEMINI_MODEL` | Exact Gemini model identifier (later issue) |
| `PORT` | Local API port (default `8787`) |
| `WEB_ORIGIN` | CORS allowlist for the Vite app (default `http://localhost:5173`) |

Optional web:

| Variable | Purpose |
|----------|---------|
| `VITE_API_BASE` | API base URL (default `http://localhost:8787`) |

## Investigation doctrine (product rules)

- Observation before interpretation
- Evidence before conclusion
- Unknown is an acceptable answer
- Confidence is not proof
- No automatic side effects on URLs or domains in Phase 1
