import { describe, expect, it } from "vitest";
import {
  MAX_MESSAGE_CHARS,
  analyzeRequestSchema,
  extractArtifacts,
  investigationReportSchema,
  safeParseInvestigationReport,
  withServerExtractedArtifacts,
} from "./reportSchema.js";

function validReport(overrides: Record<string, unknown> = {}) {
  return {
    observations: [
      {
        id: "O1",
        text: "The message asks the recipient to click a link.",
        quote: "Click here to verify",
        evidence: [
          {
            id: "E1",
            text: "The paste contains a URL string.",
            quote: "https://example-login.invalid/verify",
          },
        ],
      },
    ],
    inferences: [
      {
        text: "The message may be attempting credential theft.",
        confidence: "medium",
        based_on: ["O1", "E1"],
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
    analysis_scope: {
      performed: ["Local text review"],
      not_performed: ["URL fetching", "DNS resolution"],
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

  it("rejects unsupported extra keys on nested objects", () => {
    const result = safeParseInvestigationReport(
      validReport({
        observations: [
          {
            id: "O1",
            text: "Text",
            quote: null,
            evidence: [],
            note: "extra",
          },
        ],
        inferences: [
          {
            text: "Inference",
            confidence: "low",
            based_on: ["O1"],
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects a top-level evidence array (evidence is nested under observations)", () => {
    const result = safeParseInvestigationReport(
      validReport({
        evidence: [{ id: "E9", text: "orphan", quote: null }],
      }),
    );
    expect(result.success).toBe(false);
  });

  it("requires at least one unknown even without network artifacts", () => {
    const result = safeParseInvestigationReport(
      validReport({
        unknowns: [],
        artifacts: {
          urls: [],
          domains: [],
          emails: [],
          phones: [],
        },
      }),
    );
    expect(result.success).toBe(false);
  });

  it("accepts unknowns without network artifacts when at least one is present", () => {
    const result = safeParseInvestigationReport(
      validReport({
        observations: [
          {
            id: "O1",
            text: "The message mentions an urgent payment request.",
            quote: "Pay now",
            evidence: [
              {
                id: "E1",
                text: "Urgency language appears in the paste.",
                quote: "Pay now",
              },
            ],
          },
        ],
        inferences: [
          {
            text: "Pressure tactics may be present.",
            confidence: "low",
            based_on: ["O1", "E1"],
          },
        ],
        unknowns: [
          {
            text: "Sender authenticity was not verified.",
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

  it("requires analysis_scope with performed and not_performed", () => {
    const missing = safeParseInvestigationReport(
      validReport({ analysis_scope: undefined }),
    );
    expect(missing.success).toBe(false);

    const emptyPerformed = safeParseInvestigationReport(
      validReport({
        analysis_scope: {
          performed: [],
          not_performed: ["URL fetching"],
        },
      }),
    );
    expect(emptyPerformed.success).toBe(false);

    const valid = safeParseInvestigationReport(
      validReport({
        analysis_scope: {
          performed: ["Local text review"],
          not_performed: ["WHOIS lookups"],
        },
      }),
    );
    expect(valid.success).toBe(true);
  });

  it("rejects missing based_on on inferences", () => {
    const result = safeParseInvestigationReport(
      validReport({
        inferences: [
          {
            text: "Unanchored inference",
            confidence: "low",
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects empty based_on arrays", () => {
    const result = safeParseInvestigationReport(
      validReport({
        inferences: [
          {
            text: "Unanchored inference",
            confidence: "low",
            based_on: [],
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
  });

  it("rejects based_on references that do not match observation or evidence ids", () => {
    const result = safeParseInvestigationReport(
      validReport({
        inferences: [
          {
            text: "Bad reference",
            confidence: "low",
            based_on: ["O1", "E999"],
          },
        ],
      }),
    );
    expect(result.success).toBe(false);
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
        observations: [
          {
            id: "O1",
            text: "",
            quote: null,
            evidence: [],
          },
        ],
        inferences: [
          {
            text: "Cannot support this",
            confidence: "low",
            based_on: ["O1"],
          },
        ],
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

  it(`enforces the ${MAX_MESSAGE_CHARS}-character message limit`, () => {
    const tooLong = "a".repeat(MAX_MESSAGE_CHARS + 1);
    expect(analyzeRequestSchema.safeParse({ message: tooLong }).success).toBe(
      false,
    );
    expect(
      analyzeRequestSchema.safeParse({
        message: "a".repeat(MAX_MESSAGE_CHARS),
      }).success,
    ).toBe(true);
  });
});

describe("server artifact extraction", () => {
  it("extracts urls, domains, emails, and phones from message text", () => {
    const artifacts = extractArtifacts(
      "Contact pay@example.invalid or +1 555-010-9988 via https://pay.example.invalid/now",
    );
    expect(artifacts.urls).toContain("https://pay.example.invalid/now");
    expect(artifacts.domains).toContain("pay.example.invalid");
    expect(artifacts.emails).toContain("pay@example.invalid");
    expect(artifacts.phones.length).toBeGreaterThan(0);
  });

  it("overwrites report artifacts with server extraction", () => {
    const report = validReport({
      artifacts: {
        urls: ["https://model-claimed.invalid"],
        domains: ["model-claimed.invalid"],
        emails: [],
        phones: [],
      },
    });

    const reconciled = withServerExtractedArtifacts(
      report as never,
      "Visit https://real-from-paste.invalid/path",
    );

    expect(reconciled.artifacts.urls).toEqual([
      "https://real-from-paste.invalid/path",
    ]);
    expect(reconciled.artifacts.domains).toEqual(["real-from-paste.invalid"]);
    expect(reconciled.artifacts.urls).not.toContain(
      "https://model-claimed.invalid",
    );
  });
});
