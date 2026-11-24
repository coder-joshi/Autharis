import { clientService, type ClientWithUris } from "../clients/client.service.js";
import { SUPPORTED_SCOPES } from "../clients/client.validation.js";
import type { OAuthErrorCode } from "./oauth.errors.js";
export interface ValidatedAuthorizationRequest {
  client: ClientWithUris;
  redirectUri: string;
  scopes: string[]; // granted scopes: requested AND allowed AND supported;always includes openid
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  prompt: Set<string>;
  maxAge?: number;
}
export type AuthorizeOutcome =
  | { kind: "fatal"; message: string }
  | {
      kind: "redirect_error";
      redirectUri: string;
      state?: string;
      error: OAuthErrorCode;
      description: string;
    }
  | { kind: "ok"; request: ValidatedAuthorizationRequest };
type Raw = Record<string, unknown>;
/** undefined = absent, null = present but unusable (repeated, not a string,
too long). */
function param(raw: Raw, key: string): string | undefined | null {
  const v = raw[key];
  if (v === undefined) return undefined;
  return typeof v === "string" && v.length <= 2048 ? v : null;
}
// An S256 challenge is base64url of a 32-byte hash: exactly 43 characters.
const S256_CHALLENGE = /^[A-Za-z0-9\-._~]{43}$/;
const PROMPTS = new Set(["none", "login", "consent", "select_account"]);
export async function validateAuthorizationRequest(raw: Raw): Promise<AuthorizeOutcome> {
  // ---- Phase A: nothing in this phase may redirect ----
  const clientId = param(raw, "client_id");
  const redirectUri = param(raw, "redirect_uri");
  if (!clientId) return { kind: "fatal", message: "The request is missing a valid client_id." };
  if (!redirectUri)
    return { kind: "fatal", message: "The request is missing a valid redirect_uri." };
  const client = await clientService.findActive(clientId);
  if (!client) return { kind: "fatal", message: "The application is not recognised." };
  if (!clientService.isRegisteredRedirectUri(client, redirectUri)) {
    return { kind: "fatal", message: "The redirect_uri is not registered for this application." };
  }
  // ---- Phase B: errors are returned to the client's redirect URI ----
  const rawState = param(raw, "state");
  const state = typeof rawState === "string" && rawState.length <= 512 ? rawState : undefined;
  const fail = (error: OAuthErrorCode, description: string): AuthorizeOutcome => ({
    kind: "redirect_error",
    redirectUri,
    state,
    error,
    description,
  });
  if (rawState === null || (rawState !== undefined && rawState.length > 512)) {
    return fail("invalid_request", "state is invalid or longer than 512 characters");
  }
  if (raw.request !== undefined)
    return fail("request_not_supported", "request objects are not supported");
  if (raw.request_uri !== undefined)
    return fail("request_uri_not_supported", "request_uri is not supported");
  if (param(raw, "response_type") !== "code") {
    return fail("unsupported_response_type", "only response_type=code is supported");
  }
  if (!client.grantTypes.includes("authorization_code")) {
    return fail("unauthorized_client", "this client may not use the authorization code flow");
  }
  const responseMode = param(raw, "response_mode");
  if (responseMode !== undefined && responseMode !== "query") {
    return fail("invalid_request", "only response_mode=query is supported");
  }
  const scopeRaw = param(raw, "scope");
  if (!scopeRaw) return fail("invalid_scope", "scope must include openid");
  const requested = scopeRaw.split(" ").filter(Boolean);
  if (!requested.includes("openid")) return fail("invalid_scope", "scope must include openid");
  // Unknown scopes are ignored (OIDC Core 3.1.2.1); only the intersection is granted.
  const scopes = SUPPORTED_SCOPES.filter(
    (s) => requested.includes(s) && client.allowedScopes.includes(s),
  );
  if (!scopes.includes("openid"))
    return fail("invalid_scope", "openid is not allowed for this client");
  const challenge = param(raw, "code_challenge");
  const method = param(raw, "code_challenge_method");
  if (challenge === null || method === null)
    return fail("invalid_request", "malformed PKCE parameters");
  const pkceRequired = client.type === "public" || client.requirePkce;
  if (challenge === undefined) {
    if (pkceRequired) return fail("invalid_request", "code_challenge is required");
    if (method !== undefined)
      return fail("invalid_request", "code_challenge_method needs a code_challenge");
  } else {
    if (method !== "S256") return fail("invalid_request", "code_challenge_method must be S256");
    if (!S256_CHALLENGE.test(challenge)) return fail("invalid_request", "malformed code_challenge");
  }
  const nonce = param(raw, "nonce");
  if (nonce === null || (nonce !== undefined && nonce.length > 512)) {
    return fail("invalid_request", "nonce is invalid or longer than 512 characters");
  }
  const promptRaw = param(raw, "prompt");
  if (promptRaw === null) return fail("invalid_request", "malformed prompt");
  const prompt = new Set((promptRaw ?? "").split(" ").filter(Boolean));
  for (const p of prompt)
    if (!PROMPTS.has(p)) return fail("invalid_request", "unsupported prompt value");
  if (prompt.has("none") && prompt.size > 1)
    return fail("invalid_request", "prompt=none cannot be combined");
  const maxAgeRaw = param(raw, "max_age");
  let maxAge: number | undefined;
  if (maxAgeRaw !== undefined) {
    if (maxAgeRaw === null || !/^\d{1,9}$/.test(maxAgeRaw))
      return fail("invalid_request", "max_age must be a non-negative integer");
    maxAge = Number(maxAgeRaw);
  }
  return {
    kind: "ok",
    request: {
      client,
      redirectUri,
      scopes,
      state,
      nonce: nonce ?? undefined,
      codeChallenge: challenge ?? undefined,
      prompt,
      maxAge,
    },
  };
}
/** Builds a client redirect and always carries `iss` (RFC 9207). Undefined
values are skipped. */
export function buildClientRedirect(
  redirectUri: string,
  params: Record<string, string | undefined>,
): string {
  const url = new URL(redirectUri);
  for (const [k, v] of Object.entries(params)) if (v !== undefined) url.searchParams.set(k, v);
  return url.toString();
}
/** Parses `/authorize?...` into the same shape as req.query, keeping
repeated keys as arrays. */
export function queryFromUrl(pathAndQuery: string): Record<string, string | string[]> {
  const out = Object.create(null) as Record<string, string | string[]>;
  for (const [k, v] of new URL(pathAndQuery, "http://placeholder.invalid").searchParams) {
    const prev = out[k];
    out[k] = prev === undefined ? v : Array.isArray(prev) ? [...prev, v] : [prev, v];
  }
  return out;
}
