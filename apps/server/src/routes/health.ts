import { Hono } from "hono";

export const health = new Hono();

health.get("/", (c) =>
  c.json({
    ok: true,
    service: "signaltrace-server",
    timestamp: new Date().toISOString(),
  }),
);
