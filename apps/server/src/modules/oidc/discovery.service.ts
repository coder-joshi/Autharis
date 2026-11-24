import { env } from "../../config/env.js";
import { features } from "./features.js";

export function buildDiscoveryDocument() {
  const issuer = env.AUTHARIS_ISSUER;
  const authMethods = ["client_secret_basic", "client_secret_post", "none"];
  return {
    issuer,
    authorization_endpoint: `${issuer}/authorize`,
    token_endpoint: `${issuer}/token`,
    jwks_uri: `${issuer}/jwks`,
    ...(features.userinfo ? { userinfo_endpoint: `${issuer}/userinfo` } : {}),
    ...(features.revocation
      ? {
          revocation_endpoint: `${issuer}/revoke`,
          revocation_endpoint_auth_methods_supported: authMethods,
        }
      : {}),
    ...(features.endSession ? { end_session_endpoint: `${issuer}/logout` } : {}),
    response_types_supported: ["code"],
    response_modes_supported: ["query"],
    grant_types_supported: features.refreshTokens
      ? ["authorization_code", "refresh_token"]
      : ["authorization_code"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    scopes_supported: features.refreshTokens
      ? ["openid", "profile", "email", "offline_access"]
      : ["openid", "profile", "email"],
    token_endpoint_auth_methods_supported: authMethods,
    code_challenge_methods_supported: ["S256"],
    claims_supported: [
      "sub",
      "iss",
      "aud",
      "exp",
      "iat",
      "auth_time",
      "nonce",
      "at_hash",
      "name",
      "updated_at",
      "email",
      "email_verified",
    ],
    claim_types_supported: ["normal"],
    request_parameter_supported: false,
    request_uri_parameter_supported: false,
    claims_parameter_supported: false,
    authorization_response_iss_parameter_supported: true,
  };
}
