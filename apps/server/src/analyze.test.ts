import { describe, expect, it } from "vitest";
import {
  createGeminiAnalyzeService,
  type AnalyzeService,
} from "./ai/analyzeService.js";
import { AnalyzeServiceError, type LlmClient } from "./ai/types.js";
import { createApp } from "./app.js";

function validReportJson(message = "hello"): string {
  return JSON.stringify({
    observations: [
      {
        id: "O1",
        text: "The pasted message was received.",
        quote: message.slice(0, 40),
        evidence: [
          {
            id: "E1",
            text: "Analysis is limited to the pasted text.",
            quote: null,
          },
        ],
      },
    ],
    inferences: [
      {
        text: "No definitive determination is made from this minimal paste.",
        confidence: "low",
        based_on: ["O1", "E1"],
      },
    ],
    unknowns: [
      {
        text: "Sender authenticity was not verified.",
      },
    ],
    confidence: {
      level: "low",
      rationale: "No external verification was performed.",
    },
    recommended_next_steps: [
      {
        text: "Seek official channels if action seems required.",
        priority: "optional",
      },
    ],
    artifacts: { urls: [], domains: [], emails: [], phones: [] },
    analysis_scope: {
      performed: ["x"],
      not_performed: ["y"],
    },
  });
}

function createService(llm: LlmClient): AnalyzeService {
  return createGeminiAnalyzeService(llm);
}

describe("POST /api/analyze (gemini)", () => {
  it("returns a Gemini-backed report when the analyze service is provided", async () => {
    const app = createApp({
      analyzeService: createService({
        async generateJson() {
          return validReportJson(
            "Visit https://example-live.invalid/path for details",
          );
        },
      }),
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "Visit https://example-live.invalid/path for details",
      }),
    });

    expect(response.status).toBe(200);
    const payload = await response.json();
    expect(payload.meta.mode).toBe("gemini");
    expect(payload.meta.provider).toBe("google_gemini");
    expect(payload.meta.artifacts_source).toBe("server_extraction");
    expect(payload.meta.analysis_scope_source).toBe("phase1_fixed");
    expect(payload.report.artifacts.urls).toContain(
      "https://example-live.invalid/path",
    );
    expect(payload.report.unknowns.length).toBeGreaterThan(0);
    expect(payload.report).not.toHaveProperty("verdict");
  });

  it("returns 503 when Gemini credentials/service are missing", async () => {
    const app = createApp({
      analyzeService: null,
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello" }),
    });

    expect(response.status).toBe(503);
    const payload = await response.json();
    expect(payload.code).toBe("missing_credentials");
  });

  it("returns 429 on rate limit without silent multi-retry", async () => {
    let calls = 0;
    const app = createApp({
      analyzeService: createService({
        async generateJson() {
          calls += 1;
          throw new AnalyzeServiceError(
            "rate_limited",
            "Gemini rate limit reached. Wait and try again later. SignalTrace does not silently retry repeated 429 responses.",
          );
        },
      }),
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello" }),
    });

    expect(response.status).toBe(429);
    expect(calls).toBe(1);
    const payload = await response.json();
    expect(payload.code).toBe("rate_limited");
  });

  it("returns 502 on provider failure", async () => {
    const app = createApp({
      analyzeService: createService({
        async generateJson() {
          throw new AnalyzeServiceError(
            "provider_failure",
            "Gemini provider error (HTTP 500).",
          );
        },
      }),
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello" }),
    });

    expect(response.status).toBe(502);
    const payload = await response.json();
    expect(payload.code).toBe("provider_failure");
  });

  it("returns 422 for invalid model responses after repair exhaustion", async () => {
    const app = createApp({
      analyzeService: createService({
        async generateJson() {
          return "{\"verdict\":\"safe\"}";
        },
      }),
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "hello" }),
    });

    expect(response.status).toBe(422);
    const payload = await response.json();
    expect(payload.code).toBe("invalid_model_response");
  });

  it("still supports explicit ANALYZE_MODE=mock via allowMock", async () => {
    const app = createApp({
      analyzeService: null,
      allowMock: true,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "Gift cards required for jury duty fine.",
      }),
    });

    expect(response.status).toBe(200);
    const payload = await response.json();
    expect(payload.meta.mode).toBe("mock");
  });

  it("rejects an empty message", async () => {
    const app = createApp({
      analyzeService: createService({
        async generateJson() {
          return validReportJson();
        },
      }),
      allowMock: false,
    });

    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "" }),
    });

    expect(response.status).toBe(400);
  });
});
