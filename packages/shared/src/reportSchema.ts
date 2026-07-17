import { z } from "zod";

export const MAX_MESSAGE_CHARS = 16_000;
export const MAX_CONTEXT_CHARS = 2_000;

export const confidenceLevelSchema = z.enum(["low", "medium", "high"]);
export const nextStepPrioritySchema = z.enum(["now", "soon", "optional"]);

const quotedItemSchema = z
  .object({
    text: z.string().min(1),
    quote: z.string().nullable(),
  })
  .strict();

const inferenceSchema = z
  .object({
    text: z.string().min(1),
    confidence: confidenceLevelSchema,
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

const artifactsSchema = z
  .object({
    urls: z.array(z.string()),
    domains: z.array(z.string()),
    emails: z.array(z.string()),
    phones: z.array(z.string()),
  })
  .strict();

export const investigationReportSchema = z
  .object({
    observations: z.array(quotedItemSchema),
    evidence: z.array(quotedItemSchema),
    inferences: z.array(inferenceSchema),
    unknowns: z.array(unknownSchema),
    confidence: z
      .object({
        level: confidenceLevelSchema,
        rationale: z.string().min(1),
      })
      .strict(),
    recommended_next_steps: z.array(nextStepSchema),
    artifacts: artifactsSchema,
  })
  .strict()
  .superRefine((report, ctx) => {
    const hasUnverifiedNetworkArtifacts =
      report.artifacts.urls.length > 0 || report.artifacts.domains.length > 0;

    if (hasUnverifiedNetworkArtifacts && report.unknowns.length < 1) {
      ctx.addIssue({
        code: z.ZodIssueCode.custom,
        message:
          "unknowns must include at least one item when urls or domains are present",
        path: ["unknowns"],
      });
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

export function parseInvestigationReport(
  value: unknown,
): InvestigationReport {
  return investigationReportSchema.parse(value);
}

export function safeParseInvestigationReport(value: unknown) {
  return investigationReportSchema.safeParse(value);
}
