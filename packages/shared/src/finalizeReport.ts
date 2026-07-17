import {
  PHASE1_ANALYSIS_SCOPE,
  extractArtifacts,
  safeParseInvestigationReport,
  type InvestigationReport,
} from "@signaltrace/shared";

const FABRICATED_VERIFICATION_PATTERNS: RegExp[] = [
  /\bwhois\b/i,
  /\bi\s+visited\b/i,
  /\bwe\s+visited\b/i,
  /\bdns\s+(lookup|query|check|resolv)/i,
  /\breputation\s+(check|service|api|lookup)\b/i,
  /\blooked\s+up\s+(the\s+)?(domain|url|ip)\b/i,
  /\bexternal\s+verification\s+(confirms|shows|proves)\b/i,
];

export type FinalizeResult =
  | { ok: true; report: InvestigationReport }
  | { ok: false; issues: string[] };

/** Overwrite artifacts + analysis_scope, then Zod-validate (strict). */
export function finalizeModelReport(
  candidate: unknown,
  message: string,
): FinalizeResult {
  if (candidate === null || typeof candidate !== "object" || Array.isArray(candidate)) {
    return { ok: false, issues: ["Model output must be a JSON object."] };
  }

  const withInvariants = {
    ...(candidate as Record<string, unknown>),
    artifacts: extractArtifacts(message),
    analysis_scope: {
      performed: [...PHASE1_ANALYSIS_SCOPE.performed],
      not_performed: [...PHASE1_ANALYSIS_SCOPE.not_performed],
    },
  };

  const parsed = safeParseInvestigationReport(withInvariants);
  if (!parsed.success) {
    return {
      ok: false,
      issues: parsed.error.issues.map(
        (issue) => `${issue.path.join(".") || "(root)"}: ${issue.message}`,
      ),
    };
  }

  const policyIssues = findFabricatedVerificationClaims(parsed.data);
  if (policyIssues.length > 0) {
    return { ok: false, issues: policyIssues };
  }

  return { ok: true, report: parsed.data };
}

export function findFabricatedVerificationClaims(
  report: InvestigationReport,
): string[] {
  const issues: string[] = [];
  const samples: Array<{ path: string; text: string }> = [];

  for (const [oIndex, observation] of report.observations.entries()) {
    samples.push({
      path: `observations[${oIndex}].text`,
      text: observation.text,
    });
    for (const [eIndex, evidence] of observation.evidence.entries()) {
      samples.push({
        path: `observations[${oIndex}].evidence[${eIndex}].text`,
        text: evidence.text,
      });
    }
  }

  for (const [iIndex, inference] of report.inferences.entries()) {
    samples.push({ path: `inferences[${iIndex}].text`, text: inference.text });
  }

  samples.push({ path: "confidence.rationale", text: report.confidence.rationale });

  for (const sample of samples) {
    for (const pattern of FABRICATED_VERIFICATION_PATTERNS) {
      if (pattern.test(sample.text)) {
        issues.push(
          `${sample.path}: must not claim external verification that Phase 1 does not perform (${pattern}).`,
        );
      }
    }
  }

  return issues;
}
