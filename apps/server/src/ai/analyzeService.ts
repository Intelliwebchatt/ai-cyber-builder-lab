import {
  finalizeModelReport,
  type AnalyzeRequest,
  type InvestigationReport,
} from "@signaltrace/shared";
import {
  PROMPT_VERSION,
  SYSTEM_PROMPT_V1,
  buildRepairPrompt,
  buildUserPrompt,
} from "./prompts/v1.js";
import { buildGeminiReportJsonSchema } from "./reportJsonSchema.js";
import { AnalyzeServiceError, type LlmClient } from "./types.js";

export type AnalyzeSuccess = {
  report: InvestigationReport;
  meta: {
    mode: "gemini";
    provider: "google_gemini";
    prompt_version: typeof PROMPT_VERSION;
    artifacts_source: "server_extraction";
    analysis_scope_source: "phase1_fixed";
    repair_attempted: boolean;
  };
};

function tryParseJsonObject(
  text: string,
): { ok: true; value: unknown } | { ok: false; issue: string } {
  try {
    return { ok: true, value: JSON.parse(text) as unknown };
  } catch {
    return { ok: false, issue: "Gemini returned malformed JSON." };
  }
}

export function createGeminiAnalyzeService(llm: LlmClient) {
  const jsonSchema = buildGeminiReportJsonSchema();

  return {
    async analyze(request: AnalyzeRequest): Promise<AnalyzeSuccess> {
      const systemPrompt = SYSTEM_PROMPT_V1;
      const userPrompt = buildUserPrompt({
        message: request.message,
        context: request.context,
      });

      const firstRaw = await llm.generateJson({
        systemPrompt,
        userPrompt,
        jsonSchema,
      });

      let repairAttempted = false;
      let candidateText = firstRaw;
      let parsed = tryParseJsonObject(candidateText);
      let finalized = parsed.ok
        ? finalizeModelReport(parsed.value, request.message)
        : { ok: false as const, issues: [parsed.issue] };

      if (!finalized.ok) {
        repairAttempted = true;
        const repairPrompt = buildRepairPrompt({
          message: request.message,
          context: request.context,
          previousOutput: candidateText,
          issues: finalized.issues,
        });

        // Exactly one controlled repair attempt. No further retries.
        candidateText = await llm.generateJson({
          systemPrompt,
          userPrompt: repairPrompt,
          jsonSchema,
        });
        parsed = tryParseJsonObject(candidateText);
        if (!parsed.ok) {
          throw new AnalyzeServiceError(
            "invalid_model_response",
            `Gemini response failed SignalTrace validation after one repair attempt: ${parsed.issue}`,
          );
        }
        finalized = finalizeModelReport(parsed.value, request.message);

        if (!finalized.ok) {
          throw new AnalyzeServiceError(
            "invalid_model_response",
            `Gemini response failed SignalTrace validation after one repair attempt: ${finalized.issues.join("; ")}`,
          );
        }
      }

      return {
        report: finalized.report,
        meta: {
          mode: "gemini",
          provider: "google_gemini",
          prompt_version: PROMPT_VERSION,
          artifacts_source: "server_extraction",
          analysis_scope_source: "phase1_fixed",
          repair_attempted: repairAttempted,
        },
      };
    },
  };
}

export type AnalyzeService = ReturnType<typeof createGeminiAnalyzeService>;
