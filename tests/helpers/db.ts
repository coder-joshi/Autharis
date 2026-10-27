import { sql } from "drizzle-orm";
import { db } from "../../apps/server/src/infrastructure/database/db.js";

/** Empties every table in the public schema. Call in beforeEach. */
export async function resetDatabase(): Promise<void> {
  const result = await db.execute(sql`select tablename from pg_tables where schemaname = 'public'`);
  const tables = result.rows.map((r) => `"public"."${String(r.tablename)}"`);
  if (tables.length === 0) return;
  await db.execute(sql.raw(`TRUNCATE ${tables.join(", ")} RESTART IDENTITY CASCADE`));
}
