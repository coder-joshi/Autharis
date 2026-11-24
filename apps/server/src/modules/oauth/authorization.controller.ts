import { Router, type Response } from "express";
import { env } from "../../config/env.js";
import {
  csrfField,
  escapeHtml,
  formActionSource,
  renderPage,
} from "../../infrastructure/http/html.js";
import { audit, requestContext } from "../../infrastructure/logging/audit.service.js";
import { issueCsrfToken, verifyCsrf } from "../../middleware/csrf.js";
import { safeReturnTo, stripPromptValue } from "../authentication/return-to.js";
import { requireSession } from "../sessions/session.middleware.js";
import { issueAuthorizationCode } from "./authorization-code.service.js";
import {
  buildClientRedirect,
  queryFromUrl,
  validateAuthorizationRequest,
  type ValidatedAuthorizationRequest,
} from "./authorization.service.js";
import { consentService } from "./consent.service.js";
import type { OAuthErrorCode } from "./oauth.errors.js";
const SCOPE_LABELS: Record<string, string> = {
  openid: "Confirm who you are",
  profile: "See your name",
  email: "See your email address and whether it is verified",
  offline_access: "Stay signed in to the app, including while you are away",
};
function noStore(res: Response) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("Pragma", "no-cache");
}
function fatalPage(res: Response, message: string) {
  renderPage(res, {
    status: 400,
    title: "Authorization error",
    body: `<h1>Authorization error</h1><p>${escapeHtml(message)}</p><p
class="muted">Return to the application and try again.</p>`,
  });
}
function clientError(r: ValidatedAuthorizationRequest, error: OAuthErrorCode, description: string) {
  return buildClientRedirect(r.redirectUri, {
    error,
    error_description: description,
    state: r.state,
    iss: env.AUTHARIS_ISSUER,
  });
}
export function createAuthorizeRouter(): Router {
  const r = Router();
  r.get("/authorize", async (req, res) => {
    noStore(res);
    const outcome = await validateAuthorizationRequest(req.query as Record<string, unknown>);
    if (outcome.kind === "fatal") return fatalPage(res, outcome.message);
    if (outcome.kind === "redirect_error") {
      return res.redirect(
        302,
        buildClientRedirect(outcome.redirectUri, {
          error: outcome.error,
          error_description: outcome.description,
          state: outcome.state,
          iss: env.AUTHARIS_ISSUER,
        }),
      );
    }
    const q = outcome.request;
    const auth = req.auth;
    // 1. Authentication: no session, forced re-login, or session older than max_age.
    const tooOld =
      auth !== undefined &&
      q.maxAge !== undefined &&
      Date.now() - auth.session.authTime.getTime() > q.maxAge * 1000;
    if (!auth || q.prompt.has("login") || tooOld) {
      if (q.prompt.has("none"))
        return res.redirect(302, clientError(q, "login_required", "authentication is required"));
      return res.redirect(303, `/login?return_to=${encodeURIComponent(req.originalUrl)}`);
    }
    // 2. Consent. offline_access is only honored when the user explicitly consented to it.
    const stored = await consentService.get(auth.user.id, q.client.id);
    const covered = stored !== null && q.scopes.every((s) => stored.scopes.includes(s));
    const needsConsent = q.client.requireConsent && (!covered || q.prompt.has("consent"));
    if (needsConsent) {
      if (q.prompt.has("none"))
        return res.redirect(302, clientError(q, "consent_required", "user consent is required"));
      const items = q.scopes.map((s) => `<li>${escapeHtml(SCOPE_LABELS[s] ?? s)}</li>`).join("");
      return renderPage(res, {
        title: "Authorize application",
        formActionOrigins: [formActionSource(q.redirectUri)],
        body:
          `<h1>${escapeHtml(q.client.name)} wants access</h1>` +
          `<p>Signed in as ${escapeHtml(auth.user.email)}. This application
will be able to:</p><ul>${items}</ul>` +
          `<p class="muted">You will be sent to ${escapeHtml(new URL(q.redirectUri).host)}.</p>` +
          `<form method="post"
action="/consent">${csrfField(issueCsrfToken(req, res))}` +
          `<input type="hidden" name="return_to"
value="${escapeHtml(req.originalUrl)}">` +
          `<button type="submit" name="decision" value="allow">Allow</button>
` +
          `<button type="submit" name="decision" value="deny">Deny</button>
</form>`,
      });
    }
    // 3. Issue the code.
    const code = await issueAuthorizationCode({
      clientRef: q.client.id,
      userId: auth.user.id,
      sessionId: auth.session.id,
      redirectUri: q.redirectUri,
      scopes: q.scopes,
      nonce: q.nonce,
      codeChallenge: q.codeChallenge,
      authTime: auth.session.authTime,
    });
    await audit(
      "authorization.code_issued",
      { ...requestContext(req), actorUserId: auth.user.id },
      {
        subjectType: "client",
        subjectId: q.client.clientId,
      },
    );
    res.redirect(
      302,
      buildClientRedirect(q.redirectUri, { code, state: q.state, iss: env.AUTHARIS_ISSUER }),
    );
  });
  r.post("/consent", requireSession, verifyCsrf, async (req, res) => {
    noStore(res);
    const body = (req.body ?? {}) as Record<string, unknown>;
    const returnTo = safeReturnTo(body.return_to);
    if (!returnTo) return fatalPage(res, "The consent request is invalid.");
    const outcome = await validateAuthorizationRequest(queryFromUrl(returnTo));
    if (outcome.kind !== "ok")
      return fatalPage(res, "The authorization request is no longer valid.");
    const q = outcome.request;
    const ctx = { ...requestContext(req), actorUserId: req.auth!.user.id };
    if (body.decision === "deny") {
      await audit("consent.denied", ctx, { subjectType: "client", subjectId: q.client.clientId });
      return res.redirect(303, clientError(q, "access_denied", "the user denied the request"));
    }
    if (body.decision !== "allow") return fatalPage(res, "The consent request is invalid.");
    await consentService.grant(req.auth!.user.id, q.client.id, q.scopes);
    await audit("consent.granted", ctx, {
      subjectType: "client",
      subjectId: q.client.clientId,
      metadata: { scopes: q.scopes },
    });
    // Back to /authorize, which re-checks everything and issues the code.
    res.redirect(303, stripPromptValue(returnTo, "consent"));
  });
  return r;
}
