import {
  analyzeRequestSchema,
  parseInvestigationReport,
  withServerExtractedArtifacts,
  type AnalyzeRequest,
  type InvestigationReport,
} from "@signaltrace/shared";
import { Hono } from "hono";
import { buildMockReport } from "../mock/buildMockReport.js";

export const analyze = new Hono();

analyze.post("/", async (c) => {
  let body: unknown;

  try {
    body = await c.req.json();
  } catch {
    return c.json({ error: "Request body must be valid JSON." }, 400);
  }

  const parsedRequest = analyzeRequestSchema.safeParse(body);
  if (!parsedRequest.success) {
    return c.json(
      {
        error: "Invalid analyze request.",
        details: parsedRequest.error.flatten(),
      },
      400,
    );
  }

  const request: AnalyzeRequest = parsedRequest.data;

  // Artifacts are always reconciled from server-side extraction, never trusted
  // from a model-authored payload (mock today; Gemini later).
  const mockWithoutArtifacts = buildMockReport(request);
  const mockReport = withServerExtractedArtifacts(
    mockWithoutArtifacts,
    request.message,
  );

  let report: InvestigationReport;
  try {
    report = parseInvestigationReport(mockReport);
  } catch {
    return c.json(
      {
        error: "Mock report failed schema validation.",
      },
      500,
    );
  }

  return c.json({
    report,
    meta: {
      mode: "mock",
      provider: "none",
      artifacts_source: "server_extraction",
    },
  });
});
