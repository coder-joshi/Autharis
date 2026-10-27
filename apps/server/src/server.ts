import { createApp } from "./app.js";
import { env } from "./config/env.js";
import { closeDatabase } from "./infrastructure/database/db.js";

const app = createApp();

const server = app.listen(env.PORT, () => {
  console.log(`Autharis listening on port ${env.PORT}`);
});

let shuttingDown = false;

function shutdown(signal: string) {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log(`${signal} received, shutting down`);

  const force = setTimeout(() => process.exit(1), 10_000);
  force.unref();

  server.close(async () => {
    await closeDatabase();
    process.exit(0);
  });
  server.closeIdleConnections();
}

process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));
