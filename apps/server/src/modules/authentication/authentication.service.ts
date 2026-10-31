import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { env } from "../../config/env.js";
import { randomToken, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import {
  dummyHash,
  hashPassword,
  verifyPassword,
} from "../../infrastructure/cryptography/password.js";
import { db } from "../../infrastructure/database/db.js";
import { emailTokens } from "../../infrastructure/database/schema.js";
import { audit, type AuditContext } from "../../infrastructure/logging/audit.service.js";
import { getMailer } from "../../infrastructure/mail/mailer.js";
import { revokeAllUserAccess } from "../identity/revoke-user-access.js";
import { EmailAlreadyRegisteredError, userService } from "../identity/user.service.js";
import type { UserRow } from "../identity/user.repository.js";
export class InvalidCredentialsError extends Error {}
export class EmailNotVerifiedError extends Error {}
type Purpose = "verify_email" | "reset_password";
const TTL_SECONDS: Record<Purpose, number> = { verify_email: 24 * 3600, reset_password: 30 * 60 };
async function createEmailToken(userId: string, purpose: Purpose): Promise<string> {
  const token = randomToken(32);
  await db.transaction(async (tx) => {
    // Only the newest link works.
    await tx
      .update(emailTokens)
      .set({ usedAt: sql`now()` })
      .where(
        and(
          eq(emailTokens.userId, userId),
          eq(emailTokens.purpose, purpose),
          isNull(emailTokens.usedAt),
        ),
      );
    await tx.insert(emailTokens).values({
      userId,
      purpose,
      tokenHash: sha256Hex(token),
      expiresAt: sql`now() + make_interval(secs => ${TTL_SECONDS[purpose]})`,
    });
  });
  return token;
}
/** Atomic single use: returns the user id, or null if unknown, expired, used
or wrong purpose. */
async function consumeEmailToken(token: string, purpose: Purpose): Promise<string | null> {
  const rows = await db
    .update(emailTokens)
    .set({ usedAt: sql`now()` })
    .where(
      and(
        eq(emailTokens.tokenHash, sha256Hex(token)),
        eq(emailTokens.purpose, purpose),
        isNull(emailTokens.usedAt),
        gt(emailTokens.expiresAt, sql`now()`),
      ),
    )
    .returning({ userId: emailTokens.userId });
  return rows[0]?.userId ?? null;
}
const link = (path: string, token: string) =>
  `${env.AUTHARIS_ISSUER}${path}?token=${encodeURIComponent(token)}`;
/** Same observable outcome whether or not the email already exists. */
export async function registerUser(
  input: { email: string; password: string; displayName?: string },
  ctx: AuditContext,
): Promise<void> {
  const passwordHash = await hashPassword(input.password); // hash first so timing matches
  try {
    const user = await userService.create({
      email: input.email,
      displayName: input.displayName,
      passwordHash,
    });
    const token = await createEmailToken(user.id, "verify_email");
    await getMailer().sendVerification(user.email, link("/verify-email", token));
    await audit("user.registered", ctx, { subjectType: "user", subjectId: user.id });
  } catch (err) {
    if (!(err instanceof EmailAlreadyRegisteredError)) throw err;
    await getMailer().sendAlreadyRegistered(input.email);
    await audit("user.register_duplicate", ctx);
  }
}
export async function verifyEmail(token: string, ctx: AuditContext): Promise<boolean> {
  const userId = await consumeEmailToken(token, "verify_email");
  if (!userId) return false;
  await userService.markEmailVerified(userId);
  await audit("user.email_verified", ctx, { subjectType: "user", subjectId: userId });
  return true;
}
/** Always resolves the same way; only existing active users receive mail. */
export async function requestPasswordReset(email: string, ctx: AuditContext): Promise<void> {
  const user = await userService.findByEmail(email);
  await audit("password.reset_requested", ctx, { metadata: { known: Boolean(user) } });
  if (!user || user.status !== "active") return;
  const token = await createEmailToken(user.id, "reset_password");
  await getMailer().sendPasswordReset(user.email, link("/reset-password", token));
}
export async function resetPassword(
  token: string,
  newPassword: string,
  ctx: AuditContext,
): Promise<boolean> {
  const userId = await consumeEmailToken(token, "reset_password");
  if (!userId) return false;
  await userService.setPasswordHash(userId, await hashPassword(newPassword));
  await userService.markEmailVerified(userId); // the reset link proved control of the mailbox
  await revokeAllUserAccess(userId);
  await audit("password.reset_completed", ctx, { subjectType: "user", subjectId: userId });
  return true;
}
/** Verifies credentials. Throws InvalidCredentialsError for every failure
that could leak existence. */
export async function authenticate(
  email: string,
  password: string,
  ctx: AuditContext,
): Promise<UserRow> {
  const user = await userService.findByEmail(email);
  const valid = await verifyPassword(password, user?.passwordHash ?? (await dummyHash()));
  if (!user || !user.passwordHash || !valid || user.status !== "active") {
    await audit("login.failed", ctx, { metadata: { known: Boolean(user) } });
    throw new InvalidCredentialsError();
  }
  // Revealing "unverified" is safe only now, after the password was correct.
  if (env.REQUIRE_EMAIL_VERIFICATION && !user.emailVerifiedAt) {
    await audit("login.unverified", ctx, { subjectType: "user", subjectId: user.id });
    throw new EmailNotVerifiedError();
  }
  return user;
}
