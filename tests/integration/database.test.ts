import { sql } from "drizzle-orm";
import request from "supertest";
import { describe, expect, it } from "vitest";

import { createApp } from "../../apps/server/src/app.js";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import { runMigrations } from "../../apps/server/src/infrastructure/database/migrate.js";

describe("database", () => {
  it("answers a trivial query", async () => {
    const result = await db.execute(sql`select 1 as one`);
    expect(result.rows[0]).toEqual({ one: 1 });
  });

  it("reports ready", async () => {
    const res = await request(createApp()).get("/ready");
    expect(res.status).toBe(200);
  });

  it("applies migrations idempotently", async () => {
    await runMigrations();
    await runMigrations();
  });
});
