import { describe, expect, it } from "vitest";
import {
  analyzeRequestSchema,
  investigationReportSchema,
  safeParseInvestigationReport,
} from "./reportSchema.js";

function validReport(overrides: Record<string, unknown> = {}) {
  return {
    observations: [
      {
        text: "The message asks the recipient to click a link.",
        quote: "Click here to verify",
      },
    ],
    evidence: [
      {
        text: "The paste contains a URL string.",
        quote: "https://example-login.invalid/verify",
      },
    ],
    inferences: [
      {
        text: "The message may be attempting credential theft.",
        confidence: "medium",
      },
    ],
    unknowns: [
      {
        text: "The linked domain was not resolved or reputation-checked.",
      },
    ],
    confidence: {
      level: "low",
      rationale:
        "No external verification was performed; assessment is based only on the pasted text.",
    },
    recommended_next_steps: [
      {
        text: "Do not click the link or enter credentials.",
        priority: "now",
      },
    ],
    artifacts: {
      urls: ["https://example-login.invalid/verify"],
      domains: ["example-login.invalid"],
      emails: [],
      phones: [],
    },
    ...overrides,
  };
}

describe("investigationReportSchema", () => {
  it("accepts a valid report", () => {
    const result = safeParseInvestigationReport(validReport());
    expect(result.success).toBe(true);
  });

  it("rejects reports with a top-level verdict field", () => {
    const result = safeParseInvestigationReport(
      validReport({ verdict: "scam" }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects reports with is_scam or threat_score fields", () => {
    expect(
      safeParseInvestigationReport(validReport({ is_scam: true })).success,
    ).toBe(false);
    expect(
      safeParseInvestigationReport(validReport({ threat_score: 0.9 })).success,
    ).toBe(false);
  });

  it("requires unknowns when urls are present", () => {
    const result = safeParseInvestigationReport(
      validReport({
        unknowns: [],
        artifacts: {
          urls: ["https://example.invalid"],
          domains: [],
          emails: [],
          phones: [],
        },
      }),
    );
    expect(result.success).toBe(false);
  });

  it("requires unknowns when domains are present", () => {
    const result = safeParseInvestigationReport(
      validReport({
        unknowns: [],
        artifacts: {
          urls: [],
          domains: ["example.invalid"],
          emails: [],
          phones: [],
        },
      }),
    );
    expect(result.success).toBe(false);
  });

  it("allows empty unknowns when no urls or domains are present", () => {
    const result = safeParseInvestigationReport(
      validReport({
        unknowns: [],
        evidence: [
          {
            text: "The message mentions an urgent payment request.",
            quote: "Pay now",
          },
        ],
        artifacts: {
          urls: [],
          domains: [],
          emails: [],
          phones: [],
        },
      }),
    );
    expect(result.success).toBe(true);
  });

  it("rejects invalid confidence levels", () => {
    const result = investigationReportSchema.safeParse(
      validReport({
        confidence: { level: "certain", rationale: "Because I said so." },
      }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects empty observation text", () => {
    const result = safeParseInvestigationReport(
      validReport({
        observations: [{ text: "", quote: null }],
      }),
    );
    expect(result.success).toBe(false);
  });
});

describe("analyzeRequestSchema", () => {
  it("accepts a message with optional context", () => {
    const result = analyzeRequestSchema.safeParse({
      message: "Suspicious text",
      context: "Claimed to be my bank",
    });
    expect(result.success).toBe(true);
  });

  it("rejects an empty message", () => {
    const result = analyzeRequestSchema.safeParse({ message: "   " });
    expect(result.success).toBe(false);
  });

  it("rejects unexpected keys", () => {
    const result = analyzeRequestSchema.safeParse({
      message: "Hello",
      enrich: true,
    });
    expect(result.success).toBe(false);
  });
});
