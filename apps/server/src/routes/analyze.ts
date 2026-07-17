import {
  PHASE1_ANALYSIS_SCOPE,
  analyzeRequestSchema,
  parseInvestigationReport,
  withServerExtractedArtifacts,
  type AnalyzeRequest,
} from "@signaltrace/shared";
import { Hono } from "hono";
import type { AnalyzeService } from "../ai/analyzeService.js";
import { AnalyzeServiceError } from "../ai/types.js";
import { buildMockReport } from "../mock/buildMockReport.js";

export type AnalyzeRouteOptions = {
  analyzeService: AnalyzeService | null;
  /** Explicit offline mock only when ANALYZE_MODE=mock. Never a silent fallback. */
  allowMock: boolean;
};

function statusForAnalyzeError(
  error: AnalyzeServiceError,
): 422 | 429 | 502 | 503 {
  switch (error.code) {
    case "missing_credentials":
      return 503;
    case "rate_limited":
      return 429;
    case "invalid_model_response":
      return 422;
    case "provider_failure":
    default:
      return 502;
  }
}

export function createAnalyzeRoute(options: AnalyzeRouteOptions) {
  const analyze = new Hono();

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

    if (options.allowMock) {
      const mockReport = parseInvestigationReport(
        withServerExtractedArtifacts(
          {
            ...buildMockReport(request),
            analysis_scope: {
              performed: [...PHASE1_ANALYSIS_SCOPE.performed],
              not_performed: [...PHASE1_ANALYSIS_SCOPE.not_performed],
            },
          },
          request.message,
        ),
      );

      return c.json({
        report: mockReport,
        meta: {
          mode: "mock",
          provider: "none",
          artifacts_source: "server_extraction",
          analysis_scope_source: "phase1_fixed",
          repair_attempted: false,
        },
      });
    }

    if (!options.analyzeService) {
      return c.json(
        {
          error:
            "Gemini is not configured. Set GEMINI_API_KEY and GEMINI_MODEL in apps/server/.env (server-only). SignalTrace will not call Gemini without credentials.",
          code: "missing_credentials",
        },
        503,
      );
    }

    try {
      const result = await options.analyzeService.analyze(request);
      return c.json(result);
    } catch (error) {
      if (error instanceof AnalyzeServiceError) {
        return c.json(
          {
            error: error.message,
            code: error.code,
          },
          statusForAnalyzeError(error),
        );
      }

      return c.json(
        {
          error: "Unexpected analyze failure.",
          code: "provider_failure",
        },
        502,
      );
    }
  });

  return analyze;
}
