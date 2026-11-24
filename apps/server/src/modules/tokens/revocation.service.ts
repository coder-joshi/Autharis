import { and, eq, isNull, sql } from "drizzle-orm";
import { db } from "../../infrastructure/database/db.js";
import { accessTokens } from "../../infrastructure/database/schema.js";

/** Revoke access tokens minted from a replayed authorization code. */
export async function revokeTokensForAuthCode(authCodeId: string): Promise<void> {
  await db
    .update(accessTokens)
    .set({ revokedAt: sql`now()` })
    .where(and(eq(accessTokens.authCodeId, authCodeId), isNull(accessTokens.revokedAt)));
}
