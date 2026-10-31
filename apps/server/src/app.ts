import { fileURLToPath } from "node:url";
import cookieParser from "cookie-parser";
import express from "express";
import helmet from "helmet";
import { env } from "./config/env.js";
import {
  createLimiters,
  type LimitConfig,
} from "./infrastructure/rate-limiting/rate-limit.middleware.js";
import { errorHandler } from "./middleware/error-handler.js";
import { notFoundHandler } from "./middleware/not-found.js";
import { createAuthenticationRouter } from "./modules/authentication/authentication.routes.js";
import { healthRouter } from "./routes/health.routes.js";
export interface AppOptions {
  limits?: Partial<LimitConfig>;
}
const publicDir = fileURLToPath(new URL("../public", import.meta.url));
export function createApp(options: AppOptions = {}) {
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", env.TRUST_PROXY);
  app.use(helmet());
  app.use("/assets", express.static(publicDir, { index: false, maxAge: "1h" }));
  app.use(express.json({ limit: "32kb" }));
  app.use(express.urlencoded({ extended: false, limit: "32kb" }));
  app.use(cookieParser());
  const limiters = createLimiters(options.limits);
  app.use(healthRouter);
  app.use(createAuthenticationRouter(limiters));
  app.use(notFoundHandler);
  app.use(errorHandler);
  return app;
}
