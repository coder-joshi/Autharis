import type { Request, Response } from "express";
import { rateLimit } from "express-rate-limit";
import { renderPage } from "../http/html.js";
import { normalizeEmail } from "../../modules/identity/user.validation.js";
export interface LimitConfig {
  loginIp: number;
  loginEmail: number;
  registerIp: number;
  resetIp: number;
  resetEmail: number;
  tokenIp: number;
}
export const defaultLimits: LimitConfig = {
  loginIp: 20, // per 15 minutes
  loginEmail: 8, // per 15 minutes
  registerIp: 5, // per hour
  resetIp: 5, // per hour
  resetEmail: 3, // per hour
  tokenIp: 120, // per minute
};
const htmlHandler = (_req: Request, res: Response) =>
  renderPage(res, {
    status: 429,
    title: "Too many attempts",
    body: "<h1>Too many attempts</h1><p>Please wait a while and try again.</p>",
  });
export const jsonHandler = (_req: Request, res: Response) => {
  res
    .status(429)
    .json({ error: "temporarily_unavailable", error_description: "rate limit exceeded" });
};
const emailKey = (req: Request): string => {
  const email = (req.body as { email?: unknown } | undefined)?.email;
  return typeof email === "string" ? normalizeEmail(email).slice(0, 254) : "";
};
const common = { standardHeaders: "draft-7", legacyHeaders: false } as const;
const MIN = 60_000;
export function createLimiters(overrides: Partial<LimitConfig> = {}) {
  const c = { ...defaultLimits, ...overrides };
  return {
    loginIp: rateLimit({ ...common, windowMs: 15 * MIN, limit: c.loginIp, handler: htmlHandler }),
    loginEmail: rateLimit({
      ...common,
      windowMs: 15 * MIN,
      limit: c.loginEmail,
      keyGenerator: emailKey,
      skip: (req) => emailKey(req) === "",
      handler: htmlHandler,
    }),
    registerIp: rateLimit({
      ...common,
      windowMs: 60 * MIN,
      limit: c.registerIp,
      handler: htmlHandler,
    }),
    resetIp: rateLimit({ ...common, windowMs: 60 * MIN, limit: c.resetIp, handler: htmlHandler }),
    resetEmail: rateLimit({
      ...common,
      windowMs: 60 * MIN,
      limit: c.resetEmail,
      keyGenerator: emailKey,
      skip: (req) => emailKey(req) === "",
      handler: htmlHandler,
    }),
    tokenIp: rateLimit({ ...common, windowMs: MIN, limit: c.tokenIp, handler: jsonHandler }),
  };
}
export type Limiters = ReturnType<typeof createLimiters>;
