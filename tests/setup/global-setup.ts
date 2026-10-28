import "dotenv/config";

export default async function setup() {
  const url = process.env.TEST_DATABASE_URL;
  if (!url) throw new Error("TEST_DATABASE_URL is not set (see .env.example)");
  if (!new URL(url).pathname.endsWith("_test")) {
    throw new Error("Refusing to run tests: database name must end with _test");
  }

  process.env.NODE_ENV = "test";
  process.env.AUTHARIS_ISSUER = "http://localhost:3000";
  process.env.DATABASE_URL = url;

  const { db, closeDatabase } = await import("../../apps/server/src/infrastructure/database/db.js");
  const { sql } = await import("drizzle-orm");

  await db.execute(
    sql`DROP SCHEMA IF EXISTS public CASCADE; CREATE SCHEMA public; DROP SCHEMA IF EXISTS drizzle CASCADE;`,
  );

  const { runMigrations } =
    await import("../../apps/server/src/infrastructure/database/migrate.js");

  await runMigrations();
  await closeDatabase();
}
