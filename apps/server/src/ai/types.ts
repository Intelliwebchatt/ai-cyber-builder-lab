export type LlmGenerateInput = {
  systemPrompt: string;
  userPrompt: string;
  jsonSchema: Record<string, unknown>;
};

export type LlmClient = {
  generateJson(input: LlmGenerateInput): Promise<string>;
};

export class AnalyzeServiceError extends Error {
  readonly code:
    | "missing_credentials"
    | "rate_limited"
    | "provider_failure"
    | "invalid_model_response";

  constructor(
    code: AnalyzeServiceError["code"],
    message: string,
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "AnalyzeServiceError";
    this.code = code;
  }
}
