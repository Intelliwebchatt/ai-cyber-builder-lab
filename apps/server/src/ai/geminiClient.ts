import { GoogleGenAI, ApiError } from "@google/genai";
import { AnalyzeServiceError, type LlmClient, type LlmGenerateInput } from "./types.js";

export type GeminiClientOptions = {
  apiKey: string;
  model: string;
};

export function readGeminiCredentialsFromEnv(
  env: NodeJS.ProcessEnv = process.env,
): { apiKey: string; model: string } | null {
  const apiKey = env.GEMINI_API_KEY?.trim();
  const model = env.GEMINI_MODEL?.trim();
  if (!apiKey || !model || apiKey === "your_gemini_api_key_here") {
    return null;
  }
  if (model === "replace_with_current_gemini_model_id") {
    return null;
  }
  return { apiKey, model };
}

export function createGeminiLlmClient(options: GeminiClientOptions): LlmClient {
  const ai = new GoogleGenAI({ apiKey: options.apiKey });

  return {
    async generateJson(input: LlmGenerateInput): Promise<string> {
      try {
        const response = await ai.models.generateContent({
          model: options.model,
          contents: input.userPrompt,
          config: {
            systemInstruction: input.systemPrompt,
            temperature: 0.2,
            responseMimeType: "application/json",
            responseJsonSchema: input.jsonSchema,
            // Explicitly no tools / grounding / browsing / code execution.
          },
        });

        const text = response.text?.trim();
        if (!text) {
          throw new AnalyzeServiceError(
            "invalid_model_response",
            "Gemini returned an empty response.",
          );
        }

        return text;
      } catch (error) {
        if (error instanceof AnalyzeServiceError) {
          throw error;
        }

        if (error instanceof ApiError) {
          if (error.status === 429) {
            throw new AnalyzeServiceError(
              "rate_limited",
              "Gemini rate limit reached. Wait and try again later. SignalTrace does not silently retry repeated 429 responses.",
              { cause: error },
            );
          }

          throw new AnalyzeServiceError(
            "provider_failure",
            `Gemini provider error (HTTP ${error.status}).`,
            { cause: error },
          );
        }

        const message =
          error instanceof Error ? error.message : "Unknown Gemini failure.";

        if (/\b429\b/.test(message) || /rate limit/i.test(message)) {
          throw new AnalyzeServiceError(
            "rate_limited",
            "Gemini rate limit reached. Wait and try again later. SignalTrace does not silently retry repeated 429 responses.",
            { cause: error },
          );
        }

        throw new AnalyzeServiceError(
          "provider_failure",
          `Gemini provider failure: ${message}`,
          { cause: error },
        );
      }
    },
  };
}
