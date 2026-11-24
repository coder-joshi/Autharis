import { sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { randomToken, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import { db } from "../../infrastructure/database/db.js";
import { accessTokens } from "../../infrastructure/database/schema.js";

export async function issueAccessToken(input: {
  clientRef: string;
  userId: string;
  scope: string;
  authCodeId?: string;
}): Promise<{ token: string; expiresIn: number }> {
  const token = randomToken(32);
  await db.insert(accessTokens).values({
    tokenHash: sha256Hex(token),
    clientRef: input.clientRef,
    userId: input.userId,
    scope: input.scope,
    authCodeId: input.authCodeId,
    expiresAt: sql`now() + make_interval(secs => ${env.ACCESS_TOKEN_TTL_SECONDS})`,
  });
  return { token, expiresIn: env.ACCESS_TOKEN_TTL_SECONDS };
}
