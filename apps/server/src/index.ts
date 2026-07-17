import { serve } from "@hono/node-server";
import { Hono } from "hono";
import { cors } from "hono/cors";
import { health } from "./routes/health.js";

const port = Number(process.env.PORT ?? 8787);
const webOrigin = process.env.WEB_ORIGIN ?? "http://localhost:5173";

const app = new Hono();

app.use(
  "*",
  cors({
    origin: webOrigin,
    allowMethods: ["GET", "POST", "OPTIONS"],
    allowHeaders: ["Content-Type"],
  }),
);

app.route("/api/health", health);

app.get("/", (c) =>
  c.json({
    name: "SignalTrace API",
    status: "ok",
    phase: "issue-1-scaffold",
  }),
);

console.log(`SignalTrace server listening on http://localhost:${port}`);
console.log(`CORS web origin: ${webOrigin}`);

serve({
  fetch: app.fetch,
  port,
});
