import { describe, expect, it } from "vitest";
import { createApp } from "./app.js";

const app = createApp("http://localhost:5173");

describe("POST /api/analyze (mock)", () => {
  it("returns a schema-valid mock report with nested evidence and scope", async () => {
    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message:
          "Your account is locked. Visit https://secure-help.invalid/login now.",
        context: "Claimed to be from my bank",
      }),
    });

    expect(response.status).toBe(200);
    const payload = await response.json();
    expect(payload.meta.mode).toBe("mock");
    expect(payload.meta.artifacts_source).toBe("server_extraction");
    expect(payload.report.observations.length).toBeGreaterThan(0);
    expect(payload.report.observations[0].id).toBeTruthy();
    expect(payload.report.observations[0].evidence.length).toBeGreaterThan(0);
    expect(payload.report).not.toHaveProperty("evidence");
    expect(payload.report.inferences.length).toBeGreaterThan(0);
    expect(payload.report.inferences[0].based_on.length).toBeGreaterThan(0);
    expect(payload.report.unknowns.length).toBeGreaterThan(0);
    expect(payload.report.confidence.level).toBe("low");
    expect(payload.report.recommended_next_steps.length).toBeGreaterThan(0);
    expect(payload.report.analysis_scope.performed.length).toBeGreaterThan(0);
    expect(payload.report.analysis_scope.not_performed.length).toBeGreaterThan(
      0,
    );
    expect(payload.report.artifacts.urls).toContain(
      "https://secure-help.invalid/login",
    );
    expect(payload.report).not.toHaveProperty("verdict");
    expect(payload.report).not.toHaveProperty("is_scam");
  });

  it("always includes unknowns even without URLs", async () => {
    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        message: "Please send gift cards to settle your account today.",
      }),
    });

    expect(response.status).toBe(200);
    const payload = await response.json();
    expect(payload.report.artifacts.urls).toEqual([]);
    expect(payload.report.unknowns.length).toBeGreaterThan(0);
  });

  it("rejects an empty message", async () => {
    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "" }),
    });

    expect(response.status).toBe(400);
  });

  it("rejects messages over the 12000-character limit", async () => {
    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ message: "a".repeat(12_001) }),
    });

    expect(response.status).toBe(400);
  });

  it("rejects non-JSON bodies", async () => {
    const response = await app.request("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{not-json",
    });

    expect(response.status).toBe(400);
  });
});
