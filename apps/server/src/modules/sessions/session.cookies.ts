import type { CookieOptions, Response } from "express";
import { env } from "../../config/env.js";
const isProd = env.NODE_ENV === "production";
/** `__Host-` needs Secure, Path=/ and no Domain, so it is only used in
production. */
export const sessionCookieName = isProd ? "__Host-autharis_sid" : "autharis_sid";
export function sessionCookieOptions(prod: boolean, maxAgeSeconds?: number): CookieOptions {
  return {
    httpOnly: true,
    secure: prod,
    sameSite: "lax", // Strict would drop the cookie when a client redirects the browser to /authorize
    path: "/",
    ...(maxAgeSeconds ? { maxAge: maxAgeSeconds * 1000 } : {}),
  };
}
export function setSessionCookie(res: Response, token: string): void {
  res.cookie(
    sessionCookieName,
    token,
    sessionCookieOptions(isProd, env.SESSION_ABSOLUTE_TTL_SECONDS),
  );
}
export function clearSessionCookie(res: Response): void {
  res.clearCookie(sessionCookieName, sessionCookieOptions(isProd));
}
