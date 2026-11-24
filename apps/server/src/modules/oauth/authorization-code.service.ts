import { sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { randomToken, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import { db } from "../../infrastructure/database/db.js";
import { authorizationCodes } from "../../infrastructure/database/schema.js";
import { and, eq, gt, isNull } from "drizzle-orm";
import type { ClientWithUris } from "../clients/client.service.js";
import { OAuthError } from "./oauth.errors.js";
import { verifyPkceS256 } from "./pkce.js";
import { revokeTokensForAuthCode } from "../tokens/revocation.service.js";
export interface IssueCodeInput {
  clientRef: string;
  userId: string;
  sessionId: string;
  redirectUri: string;
  scopes: string[];
  nonce?: string;
  codeChallenge?: string;
  authTime: Date;
}
export async function issueAuthorizationCode(input: IssueCodeInput): Promise<string> {
  const code = randomToken(32);
  await db.insert(authorizationCodes).values({
    codeHash: sha256Hex(code),
    clientRef: input.clientRef,
    userId: input.userId,
    sessionId: input.sessionId,
    redirectUri: input.redirectUri,
    scope: input.scopes.join(" "),
    nonce: input.nonce,
    codeChallenge: input.codeChallenge,
    codeChallengeMethod: input.codeChallenge ? "S256" : null,
    authTime: input.authTime,
    expiresAt: sql`now() + make_interval(secs =>
${env.AUTH_CODE_TTL_SECONDS})`,
  });
  return code;
}

export async function redeemAuthorizationCode(input: {
  code: string;
  client: ClientWithUris;
  redirectUri?: string;
  codeVerifier?: string;
}) {
  const invalid = () =>
    new OAuthError("invalid_grant", "the authorization code is invalid, expired or already used");
  const hash = sha256Hex(input.code);
  const [row] = await db
    .update(authorizationCodes)
    .set({ consumedAt: sql`now()` })
    .where(
      and(
        eq(authorizationCodes.codeHash, hash),
        isNull(authorizationCodes.consumedAt),
        gt(authorizationCodes.expiresAt, sql`now()`),
      ),
    )
    .returning();

  if (!row) {
    const [used] = await db
      .select({ id: authorizationCodes.id, consumedAt: authorizationCodes.consumedAt })
      .from(authorizationCodes)
      .where(eq(authorizationCodes.codeHash, hash))
      .limit(1);
    if (used?.consumedAt) await revokeTokensForAuthCode(used.id);
    throw invalid();
  }

  // Burn the code before checking bindings to prevent retries and mix-ups.
  if (row.clientRef !== input.client.id) throw invalid();
  if (input.redirectUri === undefined || input.redirectUri !== row.redirectUri) throw invalid();
  if (row.codeChallenge) {
    if (!input.codeVerifier || !verifyPkceS256(input.codeVerifier, row.codeChallenge))
      throw invalid();
  } else if (input.codeVerifier !== undefined) {
    throw invalid();
  }
  return row;
}
