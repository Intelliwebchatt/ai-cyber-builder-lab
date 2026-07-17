# SignalTrace

Local-first, AI-assisted scam investigation aid. Paste a suspicious email, SMS, or website text and receive a structured report that separates **Observations**, **Evidence**, **Inferences**, **Unknowns**, **Confidence**, and **Recommended Next Steps**.

Phase 1 is an educational / investigative aid for self-help review. It is **not** legal advice, not law-enforcement tooling, and not a definitive determination. You remain responsible for your decisions.

## What Phase 1 does

- Accepts pasted plain text (and optional short context)
- Will call **Google Gemini only** (wired in a later issue) to produce a structured report
- Runs as a local web app + local API on your machine

## What Phase 1 does not do

- No link visiting, DNS, WHOIS, reputation lookups, or OSINT
- No authentication, database, or saved cases
- No multi-provider AI support

## Privacy warning

When Analyze is enabled, **submitted text is sent to Google (Gemini API)**.

Before pasting, remove:

- passwords
- one-time codes
- Social Security numbers
- other unnecessary sensitive information

**Free-tier Gemini data handling may differ from paid-tier handling.** Review Google’s current Gemini API / Google AI terms and data-use documentation for the tier your API key uses. Do not assume training or retention guarantees without checking those terms.

The Gemini API key stays on the **local server only** (`GEMINI_API_KEY`). It must never be placed in frontend env vars.

## Repository status (Issue #1)

Scaffold only:

- `apps/web` — Vite + React + TypeScript UI shell
- `apps/server` — Hono API with `/api/health`
- No model calls yet; Analyze button is disabled

## Prerequisites

- Node.js 20+
- npm
- A Google Gemini API key (needed for later issues; not used in Issue #1)

## Setup

```bash
npm install
cp apps/server/.env.example apps/server/.env
# Edit apps/server/.env and set GEMINI_API_KEY and GEMINI_MODEL
# (required for later issues; unused by the Issue #1 health server)
```

## Run locally (two terminals)

Terminal 1 — API:

```bash
npm run dev:server
```

API listens on `http://localhost:8787` by default.  
Health check: `GET http://localhost:8787/api/health`

Terminal 2 — Web:

```bash
npm run dev:web
```

Open `http://localhost:5173`.

## Environment variables

See `apps/server/.env.example`:

| Variable | Purpose |
|----------|---------|
| `GEMINI_API_KEY` | Server-only Gemini API key |
| `GEMINI_MODEL` | Exact Gemini model identifier (configurable) |
| `PORT` | Local API port (default `8787`) |
| `WEB_ORIGIN` | CORS allowlist for the Vite app (default `http://localhost:5173`) |

## Investigation doctrine (product rules)

- Observation before interpretation
- Evidence before conclusion
- Unknown is an acceptable answer
- Confidence is not proof
- No automatic side effects on URLs or domains in Phase 1
