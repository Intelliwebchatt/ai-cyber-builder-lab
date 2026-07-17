import { describe, expect, it } from "vitest";
import { PHASE1_ANALYSIS_SCOPE } from "./reportSchema.js";
import { finalizeModelReport } from "./finalizeReport.js";

describe("finalizeModelReport", () => {
  it("overwrites artifacts and analysis_scope then validates", () => {
    const result = finalizeModelReport(
      {
        observations: [
          {
            id: "O1",
            text: "A URL appears in the paste.",
            quote: "https://example.invalid",
            evidence: [
              {
                id: "E1",
                text: "URL substring observed.",
                quote: "https://example.invalid",
              },
            ],
          },
        ],
        inferences: [
          {
            text: "Destination is unverified.",
            confidence: "low",
            based_on: ["O1", "E1"],
          },
        ],
        unknowns: [{ text: "No live checks were performed." }],
        confidence: {
          level: "low",
          rationale: "Text only.",
        },
        recommended_next_steps: [
          { text: "Do not click unfamiliar links.", priority: "now" },
        ],
        artifacts: {
          urls: ["https://model-lie.invalid"],
          domains: ["model-lie.invalid"],
          emails: [],
          phones: [],
        },
        analysis_scope: {
          performed: ["WHOIS"],
          not_performed: [],
        },
        verdict: "safe",
      },
      "See https://example.invalid for info",
    );

    // Extra key "verdict" should fail strict schema.
    expect(result.ok).toBe(false);
  });

  it("accepts a strict report and forces Phase 1 scope + server artifacts", () => {
    const result = finalizeModelReport(
      {
        observations: [
          {
            id: "O1",
            text: "A URL appears in the paste.",
            quote: "https://example.invalid",
            evidence: [
              {
                id: "E1",
                text: "URL substring observed.",
                quote: "https://example.invalid",
              },
            ],
          },
        ],
        inferences: [
          {
            text: "Destination is unverified.",
            confidence: "low",
            based_on: ["O1", "E1"],
          },
        ],
        unknowns: [{ text: "No live checks were performed." }],
        confidence: {
          level: "low",
          rationale: "Text only.",
        },
        recommended_next_steps: [
          { text: "Do not click unfamiliar links.", priority: "now" },
        ],
        artifacts: {
          urls: ["https://model-lie.invalid"],
          domains: ["model-lie.invalid"],
          emails: [],
          phones: [],
        },
        analysis_scope: {
          performed: ["WHOIS"],
          not_performed: [],
        },
      },
      "See https://example.invalid for info",
    );

    expect(result.ok).toBe(true);
    if (!result.ok) {
      return;
    }
    expect(result.report.artifacts.urls).toEqual(["https://example.invalid"]);
    expect(result.report.analysis_scope).toEqual({
      performed: [...PHASE1_ANALYSIS_SCOPE.performed],
      not_performed: [...PHASE1_ANALYSIS_SCOPE.not_performed],
    });
  });

  it("rejects fabricated external verification claims", () => {
    const result = finalizeModelReport(
      {
        observations: [
          {
            id: "O1",
            text: "WHOIS shows the domain is safe.",
            quote: null,
            evidence: [],
          },
        ],
        inferences: [
          {
            text: "Likely fine.",
            confidence: "high",
            based_on: ["O1"],
          },
        ],
        unknowns: [{ text: "None" }],
        confidence: {
          level: "high",
          rationale: "Checked.",
        },
        recommended_next_steps: [
          { text: "Proceed.", priority: "optional" },
        ],
        artifacts: { urls: [], domains: [], emails: [], phones: [] },
        analysis_scope: {
          performed: ["x"],
          not_performed: ["y"],
        },
      },
      "hello",
    );

    expect(result.ok).toBe(false);
  });
});
