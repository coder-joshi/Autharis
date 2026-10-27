import "dotenv/config";
import { afterAll } from "vitest";

const url = process.env.TEST_DATABASE_URL;
if (!url) throw new Error("TEST_DATABASE_URL is not set (see .env.example)");
if (!new URL(url).pathname.endsWith("_test")) {
  throw new Error("Refusing to run tests: database name must end with _test");
}

process.env.NODE_ENV = "test";
process.env.AUTHARIS_ISSUER = "http://localhost:3000";
process.env.DATABASE_URL = url;

afterAll(async () => {
  const { closeDatabase } = await import("../../apps/server/src/infrastructure/database/db.js");
  await closeDatabase();
});
