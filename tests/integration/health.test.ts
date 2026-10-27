import request from "supertest";
import { describe, expect, it } from "vitest";

import { createApp } from "../../apps/server/src/app.js";

describe("Health endpoint", () => {
  it("returns the service status", async () => {
    const response = await request(createApp()).get("/health");

    expect(response.status).toBe(200);

    expect(response.body).toEqual({
      status: "ok",
      service: "autharis",
    });
  });
});
