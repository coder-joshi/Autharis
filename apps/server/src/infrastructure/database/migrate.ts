import { migrate } from "drizzle-orm/node-postgres/migrator";
import { db } from "./db.js";

export async function runMigrations(): Promise<void> {
  await migrate(db, { migrationsFolder: "./drizzle" });
}
