import { investigationReportSchema } from "@signaltrace/shared";
import { zodToJsonSchema } from "zod-to-json-schema";

/** JSON Schema sent to Gemini structured output. Zod remains the app authority. */
export function buildGeminiReportJsonSchema(): Record<string, unknown> {
  const schema = zodToJsonSchema(investigationReportSchema, {
    name: "SignalTraceInvestigationReport",
    $refStrategy: "none",
  });

  // zod-to-json-schema may wrap under definitions; prefer the inline object.
  if (
    schema &&
    typeof schema === "object" &&
    "definitions" in schema &&
    schema.definitions &&
    typeof schema.definitions === "object" &&
    "SignalTraceInvestigationReport" in schema.definitions
  ) {
    return schema.definitions.SignalTraceInvestigationReport as Record<
      string,
      unknown
    >;
  }

  return schema as Record<string, unknown>;
}
