export type OAuthErrorCode =
  | "invalid_request"
  | "invalid_client"
  | "invalid_grant"
  | "unauthorized_client"
  | "unsupported_grant_type"
  | "unsupported_response_type"
  | "invalid_scope"
  | "invalid_token"
  | "insufficient_scope"
  | "access_denied"
  | "login_required"
  | "consent_required"
  | "request_not_supported"
  | "request_uri_not_supported"
  | "server_error"
  | "temporarily_unavailable";
export class OAuthError extends Error {
  constructor(
    readonly code: OAuthErrorCode,
    readonly description: string,
    readonly status = 400,
    readonly headers: Record<string, string> = {},
  ) {
    super(description);
  }
}
import type { ErrorRequestHandler } from "express";

export const oauthErrorHandler: ErrorRequestHandler = (err, _req, res, next) => {
  if (err instanceof OAuthError) {
    for (const [key, value] of Object.entries(err.headers)) res.setHeader(key, value);
    res.setHeader("Cache-Control", "no-store");
    res.status(err.status).json({ error: err.code, error_description: err.description });
    return;
  }
  next(err);
};
