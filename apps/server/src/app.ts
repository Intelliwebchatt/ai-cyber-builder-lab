import { Hono } from "hono";
import { cors } from "hono/cors";
import {
  createGeminiAnalyzeService,
  type AnalyzeService,
} from "./ai/analyzeService.js";
import {
  createGeminiLlmClient,
  readGeminiCredentialsFromEnv,
} from "./ai/geminiClient.js";
import { createAnalyzeRoute } from "./routes/analyze.js";
import { health } from "./routes/health.js";

export type CreateAppOptions = {
  webOrigin?: string;
  analyzeService?: AnalyzeService | null;
  allowMock?: boolean;
};

export function createApp(options: CreateAppOptions = {}) {
  const webOrigin =
    options.webOrigin ?? process.env.WEB_ORIGIN ?? "http://localhost:5173";
  const allowMock =
    options.allowMock ?? process.env.ANALYZE_MODE?.trim() === "mock";

  let analyzeService: AnalyzeService | null;
  if (options.analyzeService !== undefined) {
    analyzeService = options.analyzeService;
  } else if (allowMock) {
    analyzeService = null;
  } else {
    const credentials = readGeminiCredentialsFromEnv();
    analyzeService = credentials
      ? createGeminiAnalyzeService(createGeminiLlmClient(credentials))
      : null;
  }

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
  app.route(
    "/api/analyze",
    createAnalyzeRoute({
      analyzeService,
      allowMock,
    }),
  );

  app.get("/", (c) =>
    c.json({
      name: "SignalTrace API",
      status: "ok",
      phase: "issue-3-gemini-analyze",
      analyze_mode: allowMock ? "mock" : "gemini",
      gemini_configured: Boolean(analyzeService) || allowMock,
    }),
  );

  return app;
}
