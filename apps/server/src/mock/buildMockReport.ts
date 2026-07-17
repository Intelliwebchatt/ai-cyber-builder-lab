import type { AnalyzeRequest, InvestigationReport } from "@signaltrace/shared";

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_PATTERN = /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g;

function unique(values: string[]): string[] {
  return [...new Set(values)];
}

function extractDomain(url: string): string | null {
  try {
    return new URL(url).hostname || null;
  } catch {
    return null;
  }
}

/** Deterministic mock report for Issue #2. No model calls. */
export function buildMockReport(request: AnalyzeRequest): InvestigationReport {
  const message = request.message;
  const context = request.context?.trim() || null;

  const urls = unique(message.match(URL_PATTERN) ?? []);
  const domains = unique(
    urls
      .map(extractDomain)
      .filter((value): value is string => Boolean(value)),
  );
  const emails = unique(message.match(EMAIL_PATTERN) ?? []);
  const phones = unique(message.match(PHONE_PATTERN) ?? []);

  const observations: InvestigationReport["observations"] = [
    {
      text: "The submitted text was accepted for local mock analysis only.",
      quote: message.slice(0, 160) || null,
    },
  ];

  if (context) {
    observations.push({
      text: "The user supplied optional context with the message.",
      quote: context.slice(0, 160),
    });
  }

  if (urls.length > 0) {
    observations.push({
      text: "One or more URL strings appear in the pasted text.",
      quote: urls[0] ?? null,
    });
  }

  const evidence: InvestigationReport["evidence"] = [
    {
      text: "Analysis is based solely on the pasted text and optional context.",
      quote: null,
    },
  ];

  if (emails.length > 0) {
    evidence.push({
      text: "An email address string appears in the pasted text.",
      quote: emails[0] ?? null,
    });
  }

  const inferences: InvestigationReport["inferences"] = [
    {
      text: "This mock response does not determine whether the message is a scam.",
      confidence: "low",
    },
  ];

  if (urls.length > 0 || domains.length > 0) {
    inferences.push({
      text: "Links or domains in the text are unverified because Phase 1 performs no external lookups.",
      confidence: "high",
    });
  }

  const unknowns: InvestigationReport["unknowns"] = [];

  if (urls.length > 0 || domains.length > 0) {
    unknowns.push({
      text: "Destination, ownership, and reputation of listed URLs/domains were not checked.",
    });
  }

  unknowns.push({
    text: "Sender identity and delivery channel authenticity were not verified.",
  });

  return {
    observations,
    evidence,
    inferences,
    unknowns,
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
    artifacts: {
      urls,
      domains,
      emails,
      phones,
    },
  };
}
