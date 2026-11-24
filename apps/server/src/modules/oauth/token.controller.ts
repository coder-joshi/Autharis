import { Router } from "express";
import type { Limiters } from "../../infrastructure/rate-limiting/rate-limit.middleware.js";
import { registeredOriginCors } from "../../middleware/cors-registered-origins.js";
import { userService } from "../identity/user.service.js";
import { issueAccessToken } from "../tokens/access-token.service.js";
import { redeemAuthorizationCode } from "./authorization-code.service.js";
import { authenticateClient, formValue } from "./client-auth.js";
import { OAuthError, oauthErrorHandler } from "./oauth.errors.js";

export function createTokenRouter(limiters: Limiters): Router {
  const router = Router();
  router.use("/token", registeredOriginCors);

  router.post("/token", limiters.tokenIp, async (req, res) => {
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Pragma", "no-cache");
    if (!req.is("application/x-www-form-urlencoded")) {
      throw new OAuthError(
        "invalid_request",
        "Content-Type must be application/x-www-form-urlencoded",
      );
    }
    const body = (req.body ?? {}) as Record<string, unknown>;
    const client = await authenticateClient(req);
    const grantType = formValue(body, "grant_type");

    if (grantType === "authorization_code") {
      if (!client.grantTypes.includes("authorization_code")) {
        throw new OAuthError("unauthorized_client", "grant type not allowed for this client");
      }
      const code = formValue(body, "code");
      if (!code) throw new OAuthError("invalid_request", "code is required");
      const row = await redeemAuthorizationCode({
        code,
        client,
        redirectUri: formValue(body, "redirect_uri"),
        codeVerifier: formValue(body, "code_verifier"),
      });
      const user = await userService.findById(row.userId);
      if (!user || user.status !== "active") {
        throw new OAuthError("invalid_grant", "the grant is no longer valid");
      }
      const access = await issueAccessToken({
        clientRef: client.id,
        userId: user.id,
        scope: row.scope,
        authCodeId: row.id,
      });
      res.json({
        access_token: access.token,
        token_type: "Bearer",
        expires_in: access.expiresIn,
        scope: row.scope,
      });
      return;
    }
    if (grantType === undefined) throw new OAuthError("invalid_request", "grant_type is required");
    if (grantType === "refresh_token" && !client.grantTypes.includes("refresh_token")) {
      throw new OAuthError("unauthorized_client", "grant type not allowed for this client");
    }
    throw new OAuthError("unsupported_grant_type", "unsupported grant_type");
  });

  router.use(oauthErrorHandler);
  return router;
}
