import { drizzle } from "drizzle-orm/node-postgres";
import type { NodePgQueryResultHKT } from "drizzle-orm/node-postgres";
import type { PgDatabase } from "drizzle-orm/pg-core";
import pg from "pg";
import { env } from "../../config/env.js";
import * as schema from "./schema.js";

export const pool = new pg.Pool({
  connectionString: env.DATABASE_URL,
  max: env.DB_POOL_MAX,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 5_000,
});

pool.on("error", (err) => {
  console.error("Idle PostgreSQL client error", err.message);
});

export const db = drizzle({ client: pool, schema });

/** Accepts either `db` or a transaction object. Repositories take this type. */
export type DbOrTx = PgDatabase<NodePgQueryResultHKT, typeof schema>;

export async function closeDatabase(): Promise<void> {
  await pool.end();
}
