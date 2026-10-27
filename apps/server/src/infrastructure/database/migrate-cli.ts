import { closeDatabase } from "./db.js";
import { runMigrations } from "./migrate.js";

try {
  await runMigrations();
  console.log("Migrations applied");
} finally {
  await closeDatabase();
}
