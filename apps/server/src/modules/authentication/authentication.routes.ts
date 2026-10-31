import { Router, type Request, type Response } from "express";
import { csrfField, escapeHtml, renderPage } from "../../infrastructure/http/html.js";
import { requestContext } from "../../infrastructure/logging/audit.service.js";
import type { Limiters } from "../../infrastructure/rate-limiting/rate-limit.middleware.js";
import { issueCsrfToken, verifyCsrf } from "../../middleware/csrf.js";
import {
  registerUser,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
} from "./authentication.service.js";
import {
  emailOnlySchema,
  registerSchema,
  resetSchema,
  tokenSchema,
} from "./authentication.schema.js";

const notice = (res: Response, title: string, message: string, status = 200) =>
  renderPage(res, {
    status,
    title,
    body: `<h1>${escapeHtml(title)}</h1><p>${escapeHtml(message)}</p>`,
  });

const errorLine = (msg?: string) => (msg ? `<p class="error">${escapeHtml(msg)}</p>` : "");

function registerForm(req: Request, res: Response, error?: string) {
  return (
    `<h1>Create account</h1>${errorLine(error)}` +
    `<form method="post" action="/register">${csrfField(issueCsrfToken(req, res))}` +
    `<label for="email">Email</label><input id="email" name="email" type="email" required maxlength="254" autocomplete="email">` +
    `<label for="displayName">Name (optional)</label><input id="displayName" name="displayName" maxlength="100" autocomplete="name">` +
    `<label for="password">Password (12 to 128 characters)</label><input id="password" name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">` +
    `<button type="submit">Create account</button></form><p class="muted"><a href="/login">Sign in</a></p>`
  );
}

function tokenForm(
  req: Request,
  res: Response,
  action: string,
  token: string,
  extra: string,
  button: string,
) {
  return (
    `<form method="post" action="${action}">${csrfField(issueCsrfToken(req, res))}` +
    `<input type="hidden" name="token" value="${escapeHtml(token)}">${extra}<button type="submit">${button}</button></form>`
  );
}

export function createAuthenticationRouter(limiters: Limiters): Router {
  const r = Router();

  r.get("/register", (req, res) =>
    renderPage(res, { title: "Create account", body: registerForm(req, res) }),
  );

  r.post("/register", limiters.registerIp, verifyCsrf, async (req, res) => {
    const parsed = registerSchema.safeParse(req.body ?? {});
    if (!parsed.success) {
      return renderPage(res, {
        status: 400,
        title: "Create account",
        body: registerForm(req, res, "Enter a valid email and a password of 12 to 128 characters."),
      });
    }
    await registerUser(parsed.data, requestContext(req));
    notice(res, "Check your email", "If the address can be used, we sent instructions to it.");
  });

  r.get("/verify-email", (req, res) => {
    const parsed = tokenSchema.safeParse(req.query);
    if (!parsed.success) return notice(res, "Invalid link", "This link is not valid.", 400);
    renderPage(res, {
      title: "Confirm your email",
      body: `<h1>Confirm your email</h1>${tokenForm(req, res, "/verify-email", parsed.data.token, "", "Confirm email")}`,
    });
  });

  r.post("/verify-email", limiters.resetIp, verifyCsrf, async (req, res) => {
    const parsed = tokenSchema.safeParse(req.body ?? {});
    const ok = parsed.success && (await verifyEmail(parsed.data.token, requestContext(req)));
    if (!ok) return notice(res, "Link expired", "This link is invalid or has expired.", 400);
    notice(res, "Email confirmed", "Your email address is confirmed. You can now sign in.");
  });

  r.get("/forgot-password", (req, res) =>
    renderPage(res, {
      title: "Reset password",
      body:
        `<h1>Reset password</h1><form method="post" action="/forgot-password">${csrfField(issueCsrfToken(req, res))}` +
        `<label for="email">Email</label><input id="email" name="email" type="email" required maxlength="254" autocomplete="email">` +
        `<button type="submit">Send reset link</button></form>`,
    }),
  );

  r.post(
    "/forgot-password",
    limiters.resetIp,
    limiters.resetEmail,
    verifyCsrf,
    async (req, res) => {
      const parsed = emailOnlySchema.safeParse(req.body ?? {});
      if (parsed.success) await requestPasswordReset(parsed.data.email, requestContext(req));
      // Identical response for valid, unknown and malformed input.
      notice(
        res,
        "Check your email",
        "If an account exists for that address, we sent a reset link.",
      );
    },
  );

  r.get("/reset-password", (req, res) => {
    const parsed = tokenSchema.safeParse(req.query);
    if (!parsed.success) return notice(res, "Invalid link", "This link is not valid.", 400);
    const field = `<label for="password">New password (12 to 128 characters)</label><input id="password" name="password" type="password" required minlength="12" maxlength="128" autocomplete="new-password">`;
    renderPage(res, {
      title: "Choose a new password",
      body: `<h1>Choose a new password</h1>${tokenForm(req, res, "/reset-password", parsed.data.token, field, "Set password")}`,
    });
  });

  r.post("/reset-password", limiters.resetIp, verifyCsrf, async (req, res) => {
    const parsed = resetSchema.safeParse(req.body ?? {});
    if (!parsed.success)
      return notice(res, "Cannot reset", "Check the password length (12 to 128).", 400);
    const ok = await resetPassword(parsed.data.token, parsed.data.password, requestContext(req));
    if (!ok) return notice(res, "Link expired", "This link is invalid or has expired.", 400);
    notice(res, "Password updated", "Your password was changed. Sign in with the new password.");
  });

  return r;
}
