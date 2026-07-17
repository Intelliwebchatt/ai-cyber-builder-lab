import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { readGeminiCredentialsFromEnv } from "./ai/geminiClient.js";

const port = Number(process.env.PORT ?? 8787);
const webOrigin = process.env.WEB_ORIGIN ?? "http://localhost:5173";
const allowMock = process.env.ANALYZE_MODE?.trim() === "mock";
const credentials = readGeminiCredentialsFromEnv();

const app = createApp({ webOrigin, allowMock });

console.log(`SignalTrace server listening on http://localhost:${port}`);
console.log(`CORS web origin: ${webOrigin}`);
if (allowMock) {
  console.log("Analyze mode: mock (ANALYZE_MODE=mock)");
} else if (credentials) {
  console.log(`Analyze mode: gemini (model=${credentials.model})`);
} else {
  console.log(
    "Analyze mode: gemini — WARNING: GEMINI_API_KEY/GEMINI_MODEL not configured; /api/analyze will return 503",
  );
}

serve({
  fetch: app.fetch,
  port,
});
