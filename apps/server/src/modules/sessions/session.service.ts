import { and, desc, eq, gt, isNull, ne, sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { randomToken, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import { db } from "../../infrastructure/database/db.js";
import { sessions, users } from "../../infrastructure/database/schema.js";
import type { AuditContext } from "../../infrastructure/logging/audit.service.js";
export type SessionRow = typeof sessions.$inferSelect;
export type SessionUser = typeof users.$inferSelect;
export interface AuthState {
  session: SessionRow;
  user: SessionUser;
}
export const sessionService = {
  /** Returns the raw token once. Only its SHA-256 is stored. */
  async create(userId: string, ctx: AuditContext): Promise<{ token: string; session: SessionRow }> {
    const token = randomToken(32);
    const [session] = await db
      .insert(sessions)
      .values({
        userId,
        tokenHash: sha256Hex(token),
        authTime: sql`now()`,
        lastSeenAt: sql`now()`,
        expiresAt: sql`now() + make_interval(secs =>
${env.SESSION_ABSOLUTE_TTL_SECONDS})`,
        ip: ctx.ip,
        userAgent: ctx.userAgent,
      })
      .returning();
    return { token, session: session! };
  },
  /** Null for unknown, revoked, expired (absolute or idle) sessions and for
disabled users. */
  async validate(token: string): Promise<AuthState | null> {
    const [row] = await db
      .select({ session: sessions, user: users })
      .from(sessions)
      .innerJoin(users, eq(users.id, sessions.userId))
      .where(
        and(
          eq(sessions.tokenHash, sha256Hex(token)),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, sql`now()`),
          gt(
            sessions.lastSeenAt,
            sql`now() - make_interval(secs =>
${env.SESSION_IDLE_TTL_SECONDS})`,
          ),
          eq(users.status, "active"),
        ),
      )
      .limit(1);
    if (!row) return null;
    // Touch at most once a minute to avoid a write on every request.
    await db
      .update(sessions)
      .set({ lastSeenAt: sql`now()` })
      .where(
        and(
          eq(sessions.id, row.session.id),
          sql`${sessions.lastSeenAt}
< now() - interval '60 seconds'`,
        ),
      );
    return row;
  },
  /** Pass userId to make sure a user can only revoke their own sessions. */
  async revoke(sessionId: string, userId?: string): Promise<void> {
    await db
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(
        and(
          eq(sessions.id, sessionId),
          isNull(sessions.revokedAt),
          userId ? eq(sessions.userId, userId) : undefined,
        ),
      );
  },
  async revokeAllForUser(userId: string, exceptSessionId?: string): Promise<void> {
    await db
      .update(sessions)
      .set({ revokedAt: sql`now()` })
      .where(
        and(
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt),
          exceptSessionId ? ne(sessions.id, exceptSessionId) : undefined,
        ),
      );
  },
  async listActiveForUser(userId: string): Promise<SessionRow[]> {
    return db
      .select()
      .from(sessions)
      .where(
        and(
          eq(sessions.userId, userId),
          isNull(sessions.revokedAt),
          gt(sessions.expiresAt, sql`now()`),
          gt(
            sessions.lastSeenAt,
            sql`now() - make_interval(secs =>
${env.SESSION_IDLE_TTL_SECONDS})`,
          ),
        ),
      )
      .orderBy(desc(sessions.lastSeenAt));
  },
};
