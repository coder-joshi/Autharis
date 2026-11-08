import { Router, type Request, type Response } from "express";
import { z } from "zod";
import { csrfField, escapeHtml, renderPage } from "../../infrastructure/http/html.js";
import { audit, requestContext } from "../../infrastructure/logging/audit.service.js";
import type { Limiters } from "../../infrastructure/rate-limiting/rate-limit.middleware.js";
import { issueCsrfToken, verifyCsrf } from "../../middleware/csrf.js";
import { clearSessionCookie, setSessionCookie } from "../sessions/session.cookies.js";
import { requireSession } from "../sessions/session.middleware.js";
import { sessionService } from "../sessions/session.service.js";
import {
  authenticate,
  EmailNotVerifiedError,
  InvalidCredentialsError,
} from "./authentication.service.js";
import { loginSchema } from "./authentication.schema.js";
import { safeReturnTo, stripPromptValue } from "./return-to.js";
function loginPage(
  req: Request,
  res: Response,
  returnTo: string | null,
  error?: string,
  status = 200,
) {
  const hidden = returnTo
    ? `<input type="hidden" name="return_to"
value="${escapeHtml(returnTo)}">`
    : "";
  renderPage(res, {
    status,
    title: "Sign in",
    body:
      `<h1>Sign in</h1>${error ? `<p class="error">${escapeHtml(error)}</p>` : ""}` +
      `<form method="post" action="/login">${csrfField(issueCsrfToken(req, res))}${hidden}` +
      `<label for="email">Email</label><input id="email" name="email"
type="email" required maxlength="254" autocomplete="username">` +
      `<label for="password">Password</label><input id="password"
name="password" type="password" required maxlength="128"
autocomplete="current-password">` +
      `<button type="submit">Sign in</button></form>` +
      `<p class="muted"><a href="/forgot-password">Forgot password?</a> · <a
href="/register">Create account</a></p>`,
  });
}
export function createSessionRouter(limiters: Limiters): Router {
  const r = Router();
  r.get("/login", (req, res) => loginPage(req, res, safeReturnTo(req.query.return_to)));
  r.post("/login", limiters.loginIp, limiters.loginEmail, verifyCsrf, async (req, res) => {
    const body = (req.body ?? {}) as Record<string, unknown>;
    const returnTo = safeReturnTo(body.return_to);
    const parsed = loginSchema.safeParse(body);
    if (!parsed.success)
      return loginPage(req, res, returnTo, "Enter your email and password.", 400);
    const ctx = requestContext(req);
    try {
      const user = await authenticate(parsed.data.email, parsed.data.password, ctx);
      // New session on every login: prevents session fixation and resets auth_time.
      if (req.auth) await sessionService.revoke(req.auth.session.id);
      const { token, session } = await sessionService.create(user.id, ctx);
      setSessionCookie(res, token);
      await audit(
        "login.succeeded",
        { ...ctx, actorUserId: user.id },
        {
          subjectType: "session",
          subjectId: session.id,
        },
      );
      res.redirect(303, returnTo ? stripPromptValue(returnTo, "login") : "/account");
    } catch (err) {
      if (err instanceof EmailNotVerifiedError) {
        return loginPage(
          req,
          res,
          returnTo,
          "Confirm your email address first. Check your inbox.",
          403,
        );
      }
      if (err instanceof InvalidCredentialsError) {
        return loginPage(req, res, returnTo, "Invalid email or password.", 400);
      }
      throw err;
    }
  });
  // Local sign-out. Step 16 extends /logout with OIDC RP-Initiated Logout.
  r.post("/logout", verifyCsrf, async (req, res) => {
    if (req.auth) {
      await sessionService.revoke(req.auth.session.id);
      await audit(
        "logout",
        { ...requestContext(req), actorUserId: req.auth.user.id },
        { subjectType: "session", subjectId: req.auth.session.id },
      );
    }
    clearSessionCookie(res);
    res.redirect(303, "/login");
  });
  r.get("/account", requireSession, async (req, res) => {
    const auth = req.auth!;
    const csrf = issueCsrfToken(req, res);
    const list = await sessionService.listActiveForUser(auth.user.id);
    const rows = list
      .map((s) => {
        const current = s.id === auth.session.id;
        const action = current
          ? "<em>this device</em>"
          : `<form method="post"
action="/account/sessions/${s.id}/revoke">${csrfField(csrf)}<button
type="submit">Revoke</button></form>`;
        return `<li>${escapeHtml(s.userAgent ?? "Unknown device")}<br><span
class="muted">${escapeHtml(s.ip ?? "")} · last active
${s.lastSeenAt.toISOString()}</span> ${action}</li>`;
      })
      .join("");
    renderPage(res, {
      title: "Account",
      body:
        `<h1>Account</h1><p>Signed in as ${escapeHtml(auth.user.email)}.</p>
<h2>Active sessions</h2><ul>${rows}</ul>` +
        `<form method="post" action="/account/sessions/revoke-others">${csrfField(csrf)}<button type="submit">Sign out other
sessions</button></form>` +
        `<form method="post" action="/logout">${csrfField(csrf)}<button
type="submit">Sign out</button></form>`,
    });
  });
  r.post("/account/sessions/:id/revoke", requireSession, verifyCsrf, async (req, res) => {
    const id = z.string().uuid().safeParse(req.params.id);
    if (id.success) await sessionService.revoke(id.data, req.auth!.user.id);
    res.redirect(303, "/account");
  });
  r.post("/account/sessions/revoke-others", requireSession, verifyCsrf, async (req, res) => {
    await sessionService.revokeAllForUser(req.auth!.user.id, req.auth!.session.id);
    res.redirect(303, "/account");
  });
  return r;
}
