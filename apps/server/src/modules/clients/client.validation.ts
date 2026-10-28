import { z } from "zod";
export const SUPPORTED_SCOPES = ["openid", "profile", "email", "offline_access"] as const;
export const SUPPORTED_GRANTS = ["authorization_code", "refresh_token"] as const;
const LOOPBACK_HOSTS = new Set(["localhost", "127.0.0.1", "[::1]"]);
export type UriCheck = { ok: true; origin: string } | { ok: false; reason: string };

export function validateRedirectUri(uri: string): UriCheck {
  if (uri.length === 0 || uri.length > 2000) return { ok: false, reason: "invalid length" };
  if (uri.includes("#")) return { ok: false, reason: "fragments are notallowed" };
  if (uri.includes("*")) return { ok: false, reason: "wildcards are notallowed" };
  let url: URL;
  try {
    url = new URL(uri);
  } catch {
    return { ok: false, reason: "must be an absolute URI" };
  }
  if (url.username || url.password) return { ok: false, reason: "credentialsare not allowed" };
  if (url.protocol === "https:") return { ok: true, origin: url.origin };
  if (url.protocol === "http:" && LOOPBACK_HOSTS.has(url.hostname)) {
    return { ok: true, origin: url.origin };
  }
  return { ok: false, reason: "must use https (http only for localhost,127.0.0.1 or [::1])" };
}

const uriList = (max: number) =>
  z
    .array(z.string())
    .max(max)
    .superRefine((uris, ctx) => {
      uris.forEach((u, i) => {
        const check = validateRedirectUri(u);
        if (!check.ok) ctx.addIssue({ code: "custom", path: [i], message: check.reason });
      });
    });

export const clientInputSchema = z
  .object({
    name: z.string().trim().min(1).max(100),
    type: z.enum(["public", "confidential"]),
    tokenEndpointAuthMethod: z
      .enum(["none", "client_secret_basic", "client_secret_post"])
      .optional(),
    redirectUris: uriList(10).refine((a) => a.length >= 1, "at least oneredirect URI"),
    postLogoutRedirectUris: uriList(10).default([]),
    grantTypes: z.array(z.enum(SUPPORTED_GRANTS)).min(1).default(["authorization_code"]),
    allowedScopes: z.array(z.enum(SUPPORTED_SCOPES)).min(1).default(["openid", "profile", "email"]),
    requirePkce: z.boolean().default(true),
    requireConsent: z.boolean().default(true),
  })
  .superRefine((v, ctx) => {
    const fail = (path: string, message: string) =>
      ctx.addIssue({ code: "custom", path: [path], message });
    if (!v.grantTypes.includes("authorization_code"))
      fail("grantTypes", "must include authorization_code");
    if (!v.allowedScopes.includes("openid")) fail("allowedScopes", "mustinclude openid");
    if (v.allowedScopes.includes("offline_access") && !v.grantTypes.includes("refresh_token")) {
      fail("allowedScopes", "offline_access requires the refresh_tokengrant");
    }
    if (v.type === "public") {
      if (v.tokenEndpointAuthMethod && v.tokenEndpointAuthMethod !== "none") {
        fail("tokenEndpointAuthMethod", "public clients must use none");
      }
      if (!v.requirePkce) fail("requirePkce", "public clients must requirePKCE");
    } else if (v.tokenEndpointAuthMethod === "none") {
      fail("tokenEndpointAuthMethod", "confidential clients need a secretmethod");
    }
  });

export type ClientInput = z.infer<typeof clientInputSchema>;
