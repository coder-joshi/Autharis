import type { NextFunction, Request, Response } from "express";
import { clearSessionCookie, sessionCookieName } from "./session.cookies.js";
import { sessionService } from "./session.service.js";
/** Sets req.auth when the cookie holds a live session. Never rejects the
request. */
export async function loadSession(req: Request, res: Response, next: NextFunction): Promise<void> {
  const token: unknown = req.cookies?.[sessionCookieName];
  if (typeof token === "string" && token.length >= 20 && token.length <= 200) {
    const auth = await sessionService.validate(token);
    if (auth) req.auth = auth;
    else clearSessionCookie(res);
  }
  next();
}
export function requireSession(req: Request, res: Response, next: NextFunction): void {
  if (!req.auth) {
    res.redirect(303, "/login");
    return;
  }
  next();
}
