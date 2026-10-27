import { Router } from "express";
import { checkDatabase } from "../infrastructure/database/database-health.js";

const healthRouter = Router();

healthRouter.get("/health", (_req, res) => {
  res.status(200).json({
    status: "ok",
    service: "autharis",
  });
});

healthRouter.get("/ready", async (_req, res) => {
  const ok = await checkDatabase();
  res.status(ok ? 200 : 503).json({ status: ok ? "ready" : "unavailable" });
});

export { healthRouter };
