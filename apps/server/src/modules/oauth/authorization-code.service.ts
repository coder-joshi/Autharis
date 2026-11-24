import { sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { randomToken, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import { db } from "../../infrastructure/database/db.js";
import { authorizationCodes } from "../../infrastructure/database/schema.js";
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
