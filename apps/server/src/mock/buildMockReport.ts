import {
  PHASE1_ANALYSIS_SCOPE,
  type AnalyzeRequest,
  type InvestigationReport,
} from "@signaltrace/shared";

/** Deterministic mock report for Issue #2. No model calls. */
export function buildMockReport(
  request: AnalyzeRequest,
): Omit<InvestigationReport, "artifacts"> {
  const message = request.message;
  const context = request.context?.trim() || null;

  const observations: InvestigationReport["observations"] = [
    {
      id: "O1",
      text: "The submitted text was accepted for local mock analysis only.",
      quote: message.slice(0, 160) || null,
      evidence: [
        {
          id: "E1",
          text: "Analysis input is limited to the pasted text and optional context.",
          quote: null,
        },
      ],
    },
  ];

  if (context) {
    observations.push({
      id: "O2",
      text: "The user supplied optional context with the message.",
      quote: context.slice(0, 160),
      evidence: [
        {
          id: "E2",
          text: "Optional context was provided alongside the pasted message.",
          quote: context.slice(0, 160),
        },
      ],
    });
  }

  const hasUrl = /\bhttps?:\/\//i.test(message);
  if (hasUrl) {
    const urlMatch = message.match(/\bhttps?:\/\/[^\s<>"']+/i);
    observations.push({
      id: "O3",
      text: "One or more URL strings appear in the pasted text.",
      quote: urlMatch?.[0] ?? null,
      evidence: [
        {
          id: "E3",
          text: "A URL-like substring was observed in the paste (not visited).",
          quote: urlMatch?.[0] ?? null,
        },
      ],
    });
  }

  const basedOn = observations.flatMap((observation) => [
    observation.id,
    ...observation.evidence.map((item) => item.id),
  ]);

  const inferences: InvestigationReport["inferences"] = [
    {
      text: "This mock response does not determine whether the message is a scam.",
      confidence: "low",
      based_on: basedOn.slice(0, 2),
    },
  ];

  if (hasUrl) {
    inferences.push({
      text: "Links in the text are unverified because Phase 1 performs no external lookups.",
      confidence: "high",
      based_on: ["O3", "E3"],
    });
  }

  return {
    observations,
    inferences,
    unknowns: [
      {
        text: "No external verification was performed, so sender authenticity, destination safety, and delivery-channel legitimacy remain unknown.",
      },
    ],
    confidence: {
      level: "low",
      rationale:
        "Issue #2 returns a deterministic mock report. No Gemini call or external verification was performed.",
    },
    recommended_next_steps: [
      {
        text: "Treat this output as a schema/UI exercise until real Gemini analysis is enabled.",
        priority: "now",
      },
      {
        text: "Do not click unfamiliar links or share credentials based on this mock report.",
        priority: "now",
      },
      {
        text: "Remove passwords, one-time codes, and other sensitive data before any future live analysis.",
        priority: "soon",
      },
    ],
    analysis_scope: {
      performed: [...PHASE1_ANALYSIS_SCOPE.performed],
      not_performed: [...PHASE1_ANALYSIS_SCOPE.not_performed],
    },
  };
}
