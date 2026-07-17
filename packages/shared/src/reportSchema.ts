import { z } from "zod";

export const MAX_MESSAGE_CHARS = 12_000;
export const MAX_CONTEXT_CHARS = 2_000;

export const confidenceLevelSchema = z.enum(["low", "medium", "high"]);
export const nextStepPrioritySchema = z.enum(["now", "soon", "optional"]);

const evidenceItemSchema = z
  .object({
    id: z.string().min(1),
    text: z.string().min(1),
    quote: z.string().nullable(),
  })
  .strict();

const observationSchema = z
  .object({
    id: z.string().min(1),
    text: z.string().min(1),
    quote: z.string().nullable(),
    evidence: z.array(evidenceItemSchema),
  })
  .strict();

const inferenceSchema = z
  .object({
    text: z.string().min(1),
    confidence: confidenceLevelSchema,
    based_on: z.array(z.string().min(1)).min(1),
  })
  .strict();

const unknownSchema = z
  .object({
    text: z.string().min(1),
  })
  .strict();

const nextStepSchema = z
  .object({
    text: z.string().min(1),
    priority: nextStepPrioritySchema,
  })
  .strict();

export const artifactsSchema = z
  .object({
    urls: z.array(z.string()),
    domains: z.array(z.string()),
    emails: z.array(z.string()),
    phones: z.array(z.string()),
  })
  .strict();

export type Artifacts = z.infer<typeof artifactsSchema>;

export const analysisScopeSchema = z
  .object({
    performed: z.array(z.string().min(1)).min(1),
    not_performed: z.array(z.string().min(1)).min(1),
  })
  .strict();

/** Phase 1 scope: text-only local analysis; no external verification. */
export const PHASE1_ANALYSIS_SCOPE = {
  performed: [
    "Accepted pasted message text and optional user context",
    "Deterministic local artifact extraction from pasted text",
    "Structured report assembly without side effects",
  ],
  not_performed: [
    "URL fetching or link visiting",
    "DNS resolution",
    "WHOIS lookups",
    "Domain or URL reputation checks",
    "OSINT enrichment",
    "Sender or channel authenticity verification",
  ],
} as const satisfies z.infer<typeof analysisScopeSchema>;

export const investigationReportSchema = z
  .object({
    observations: z.array(observationSchema),
    inferences: z.array(inferenceSchema),
    unknowns: z.array(unknownSchema).min(1),
    confidence: z
      .object({
        level: confidenceLevelSchema,
        rationale: z.string().min(1),
      })
      .strict(),
    recommended_next_steps: z.array(nextStepSchema),
    artifacts: artifactsSchema,
    analysis_scope: analysisScopeSchema,
  })
  .strict()
  .superRefine((report, ctx) => {
    const observationIds = new Set<string>();
    const evidenceIds = new Set<string>();

    for (const [obsIndex, observation] of report.observations.entries()) {
      if (observationIds.has(observation.id) || evidenceIds.has(observation.id)) {
        ctx.addIssue({
          code: z.ZodIssueCode.custom,
          message: `duplicate observation id: ${observation.id}`,
          path: ["observations", obsIndex, "id"],
        });
      }
      observationIds.add(observation.id);

      for (const [evIndex, evidence] of observation.evidence.entries()) {
        if (
          evidenceIds.has(evidence.id) ||
          observationIds.has(evidence.id)
        ) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `duplicate evidence id: ${evidence.id}`,
            path: ["observations", obsIndex, "evidence", evIndex, "id"],
          });
        }
        evidenceIds.add(evidence.id);
      }
    }

    const validIds = new Set([...observationIds, ...evidenceIds]);

    for (const [infIndex, inference] of report.inferences.entries()) {
      for (const [refIndex, ref] of inference.based_on.entries()) {
        if (!validIds.has(ref)) {
          ctx.addIssue({
            code: z.ZodIssueCode.custom,
            message: `based_on reference "${ref}" does not match an observation or evidence id`,
            path: ["inferences", infIndex, "based_on", refIndex],
          });
        }
      }
    }
  });

export type InvestigationReport = z.infer<typeof investigationReportSchema>;

export const analyzeRequestSchema = z
  .object({
    message: z.string().trim().min(1).max(MAX_MESSAGE_CHARS),
    context: z.string().trim().max(MAX_CONTEXT_CHARS).optional(),
  })
  .strict();

export type AnalyzeRequest = z.infer<typeof analyzeRequestSchema>;

const URL_PATTERN = /\bhttps?:\/\/[^\s<>"']+/gi;
const EMAIL_PATTERN = /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi;
const PHONE_PATTERN =
  /\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b/g;

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

/** Server-side deterministic artifact extraction. Not model-authored. */
export function extractArtifacts(message: string): Artifacts {
  const urls = unique(message.match(URL_PATTERN) ?? []);
  const domains = unique(
    urls
      .map(extractDomain)
      .filter((value): value is string => Boolean(value)),
  );
  const emails = unique(message.match(EMAIL_PATTERN) ?? []);
  const phones = unique(message.match(PHONE_PATTERN) ?? []);

  return { urls, domains, emails, phones };
}

/**
 * Reconcile artifacts onto a report using server extraction only.
 * Model-supplied artifact values must not be trusted without this step.
 */
export function withServerExtractedArtifacts(
  report: Omit<InvestigationReport, "artifacts"> & {
    artifacts?: Artifacts;
  },
  message: string,
): InvestigationReport {
  return {
    ...report,
    artifacts: extractArtifacts(message),
  };
}

export function parseInvestigationReport(
  value: unknown,
): InvestigationReport {
  return investigationReportSchema.parse(value);
}

export function safeParseInvestigationReport(value: unknown) {
  return investigationReportSchema.safeParse(value);
}
