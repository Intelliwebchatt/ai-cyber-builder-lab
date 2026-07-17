import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";
import {
  PHASE1_ANALYSIS_SCOPE,
  finalizeModelReport,
} from "@signaltrace/shared";
import { createGeminiAnalyzeService } from "./analyzeService.js";
import { AnalyzeServiceError, type LlmClient } from "./types.js";

const fixturesRoot = join(
  dirname(fileURLToPath(import.meta.url)),
  "../../../../fixtures",
);

type CatalogFixture = {
  id: string;
  category: string;
  message_file: string;
  model_output_file: string;
  repair_output_file?: string;
  expect: string;
};

type Catalog = { fixtures: CatalogFixture[] };

function readFixtureText(relativePath: string): string {
  return readFileSync(join(fixturesRoot, relativePath), "utf8");
}

function loadCatalog(): Catalog {
  return JSON.parse(
    readFileSync(join(fixturesRoot, "catalog.json"), "utf8"),
  ) as Catalog;
}

function createScriptedLlmClient(outputs: string[]): LlmClient {
  let index = 0;
  return {
    async generateJson() {
      if (index >= outputs.length) {
        throw new Error("Scripted LLM ran out of outputs");
      }
      const value = outputs[index];
      index += 1;
      return value ?? "";
    },
  };
}

describe("Issue #3 evaluation fixtures", () => {
  const catalog = loadCatalog();

  it("includes at least 10 fixtures covering the required categories", () => {
    expect(catalog.fixtures.length).toBeGreaterThanOrEqual(10);
    const categories = new Set(catalog.fixtures.map((item) => item.category));
    for (const required of [
      "obvious_scam",
      "benign",
      "ambiguous",
      "prompt_injection",
      "url_present",
      "no_url",
      "privacy_sensitive",
      "hallucinated_external_verification",
      "malformed_model_json",
      "false_reassurance_risk",
    ]) {
      expect(categories.has(required)).toBe(true);
    }
  });

  for (const fixture of catalog.fixtures) {
    it(`handles ${fixture.id} (${fixture.category})`, async () => {
      const message = readFixtureText(fixture.message_file).trim();
      const firstOutput = readFixtureText(fixture.model_output_file);
      const repairOutput = fixture.repair_output_file
        ? readFixtureText(fixture.repair_output_file)
        : null;

      if (fixture.expect === "valid_after_finalize") {
        const parsed = JSON.parse(firstOutput) as unknown;
        const finalized = finalizeModelReport(parsed, message);
        expect(finalized.ok).toBe(true);
        if (!finalized.ok) {
          return;
        }
        expect(finalized.report.unknowns.length).toBeGreaterThan(0);
        expect(finalized.report.analysis_scope).toEqual({
          performed: [...PHASE1_ANALYSIS_SCOPE.performed],
          not_performed: [...PHASE1_ANALYSIS_SCOPE.not_performed],
        });
        // Model-supplied artifact values must be overwritten.
        if (fixture.category === "url_present" || fixture.category === "obvious_scam") {
          expect(finalized.report.artifacts.urls.length).toBeGreaterThan(0);
          expect(finalized.report.artifacts.urls).not.toContain(
            "https://model-should-be-overwritten.invalid",
          );
          expect(finalized.report.artifacts.urls).not.toContain(
            "https://wrong.invalid",
          );
        }

        const service = createGeminiAnalyzeService(
          createScriptedLlmClient([firstOutput]),
        );
        const result = await service.analyze({ message });
        expect(result.meta.repair_attempted).toBe(false);
        expect(result.meta.provider).toBe("google_gemini");
        expect(result.report.observations[0]?.id).toBeTruthy();
        for (const inference of result.report.inferences) {
          expect(inference.based_on.length).toBeGreaterThan(0);
        }
        return;
      }

      if (
        fixture.expect === "rejected_then_repaired" ||
        fixture.expect === "policy_or_schema_repair"
      ) {
        expect(repairOutput).toBeTruthy();
        const firstParsed = JSON.parse(firstOutput) as unknown;
        const firstFinalized = finalizeModelReport(firstParsed, message);
        expect(firstFinalized.ok).toBe(false);

        const service = createGeminiAnalyzeService(
          createScriptedLlmClient([firstOutput, repairOutput!]),
        );
        const result = await service.analyze({ message });
        expect(result.meta.repair_attempted).toBe(true);
        expect(result.report.unknowns.length).toBeGreaterThan(0);
        expect(result.report.analysis_scope.not_performed).toContain(
          "WHOIS lookups",
        );
        return;
      }

      if (fixture.expect === "malformed_then_repaired") {
        expect(repairOutput).toBeTruthy();
        const service = createGeminiAnalyzeService(
          createScriptedLlmClient([firstOutput, repairOutput!]),
        );
        const result = await service.analyze({ message });
        expect(result.meta.repair_attempted).toBe(true);
        expect(result.report.observations.length).toBeGreaterThan(0);
        return;
      }

      throw new Error(`Unhandled fixture expect: ${fixture.expect}`);
    });
  }

  it("fails closed after one unsuccessful repair", async () => {
    const service = createGeminiAnalyzeService(
      createScriptedLlmClient([
        "{bad",
        JSON.stringify({ verdict: "safe", is_scam: false }),
      ]),
    );

    await expect(service.analyze({ message: "test" })).rejects.toMatchObject({
      code: "invalid_model_response",
    } satisfies Partial<AnalyzeServiceError>);
  });

  it("maps scripted provider rate limits to AnalyzeServiceError", async () => {
    const llm: LlmClient = {
      async generateJson() {
        throw new AnalyzeServiceError(
          "rate_limited",
          "Gemini rate limit reached. Wait and try again later. SignalTrace does not silently retry repeated 429 responses.",
        );
      },
    };

    const service = createGeminiAnalyzeService(llm);
    await expect(service.analyze({ message: "hello" })).rejects.toMatchObject({
      code: "rate_limited",
    });
  });
});
