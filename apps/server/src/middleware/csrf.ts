import type { NextFunction, Request, Response } from "express";
import { env } from "../config/env.js";
import { randomToken, safeEqual } from "../infrastructure/cryptography/tokens.js";

const issuerOrigin = new URL(env.AUTHARIS_ISSUER).origin;
const secure = env.NODE_ENV === "production";
export const csrfCookieName = secure ? "__Host-autharis_csrf" : "autharis_csrf";

/** Call when rendering any form. Reuses the token already in the cookie, or sets a new one. */
export function issueCsrfToken(req: Request, res: Response): string {
  if (typeof res.locals.csrfToken === "string") return res.locals.csrfToken;
  const existing: unknown = req.cookies?.[csrfCookieName];
  const token = typeof existing === "string" && existing.length >= 32 ? existing : randomToken(32);
  if (token !== existing) {
    res.cookie(csrfCookieName, token, { httpOnly: true, secure, sameSite: "lax", path: "/" });
  }
  res.locals.csrfToken = token;
  return token;
}

export function verifyCsrf(req: Request, res: Response, next: NextFunction): void {
  const origin = req.get("origin");
  const cookie: unknown = req.cookies?.[csrfCookieName];
  const submitted: unknown =
    (req.body ?? {})._csrf ?? req.get("x-csrf-token") ?? req.get("x-csrf token");
  const ok =
    (!origin || origin === issuerOrigin) &&
    typeof cookie === "string" &&
    typeof submitted === "string" &&
    safeEqual(cookie, submitted);
  if (!ok) {
    res.status(403).type("text").send("Invalid or missing CSRF token");
    return;
  }
  next();
}
