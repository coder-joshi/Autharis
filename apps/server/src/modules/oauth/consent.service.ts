import { and, eq, sql } from "drizzle-orm";
import { db } from "../../infrastructure/database/db.js";
import { userConsents } from "../../infrastructure/database/schema.js";
export const consentService = {
  async get(userId: string, clientRef: string) {
    const [row] = await db
      .select()
      .from(userConsents)
      .where(and(eq(userConsents.userId, userId), eq(userConsents.clientRef, clientRef)))
      .limit(1);
    return row ?? null;
  },
  async grant(userId: string, clientRef: string, scopes: string[]) {
    const existing = await this.get(userId, clientRef);
    const merged = [...new Set([...(existing?.scopes ?? []), ...scopes])];
    await db
      .insert(userConsents)
      .values({ userId, clientRef, scopes: merged })
      .onConflictDoUpdate({
        target: [userConsents.userId, userConsents.clientRef],
        set: { scopes: merged, updatedAt: sql`now()` },
      });
  },
  async revoke(userId: string, clientRef: string) {
    await db
      .delete(userConsents)
      .where(and(eq(userConsents.userId, userId), eq(userConsents.clientRef, clientRef)));
  },
};
