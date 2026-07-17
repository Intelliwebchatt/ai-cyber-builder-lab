import { serve } from "@hono/node-server";
import { createApp } from "./app.js";

const port = Number(process.env.PORT ?? 8787);
const webOrigin = process.env.WEB_ORIGIN ?? "http://localhost:5173";
const app = createApp(webOrigin);

console.log(`SignalTrace server listening on http://localhost:${port}`);
console.log(`CORS web origin: ${webOrigin}`);
console.log("Analyze mode: mock (no Gemini calls)");

serve({
  fetch: app.fetch,
  port,
});
