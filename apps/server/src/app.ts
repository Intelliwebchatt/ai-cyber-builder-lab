import { Hono } from "hono";
import { cors } from "hono/cors";
import { analyze } from "./routes/analyze.js";
import { health } from "./routes/health.js";

export function createApp(webOrigin = process.env.WEB_ORIGIN ?? "http://localhost:5173") {
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
  app.route("/api/analyze", analyze);

  app.get("/", (c) =>
    c.json({
      name: "SignalTrace API",
      status: "ok",
      phase: "issue-2-mocked-analyze",
      analyze_mode: "mock",
    }),
  );

  return app;
}
