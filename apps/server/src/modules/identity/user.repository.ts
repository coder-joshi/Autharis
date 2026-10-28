import { and, eq, isNull } from "drizzle-orm";
import { db, type DbOrTx } from "../../infrastructure/database/db.js";
import { users } from "../../infrastructure/database/schema.js";
export type UserRow = typeof users.$inferSelect;
export type NewUser = Pick<
  typeof users.$inferInsert,
  "email" | "emailNormalized" | "displayName" | "passwordHash" | "role" | "emailVerifiedAt"
>;
export const userRepository = {
  async findById(id: string, tx: DbOrTx = db): Promise<UserRow | null> {
    const [row] = await tx.select().from(users).where(eq(users.id, id)).limit(1);
    return row ?? null;
  },
  async findByEmailNormalized(emailNormalized: string, tx: DbOrTx = db): Promise<UserRow | null> {
    const [row] = await tx
      .select()
      .from(users)
      .where(eq(users.emailNormalized, emailNormalized))
      .limit(1);
    return row ?? null;
  },
  async insert(values: NewUser, tx: DbOrTx = db): Promise<UserRow> {
    const [row] = await tx.insert(users).values(values).returning();
    return row!;
  },
  async markEmailVerified(id: string, tx: DbOrTx = db): Promise<void> {
    await tx
      .update(users)
      .set({ emailVerifiedAt: new Date() })
      .where(and(eq(users.id, id), isNull(users.emailVerifiedAt)));
  },
  async setPasswordHash(id: string, passwordHash: string, tx: DbOrTx = db): Promise<void> {
    await tx.update(users).set({ passwordHash }).where(eq(users.id, id));
  },
  async setStatus(id: string, status: "active" | "disabled", tx: DbOrTx = db): Promise<void> {
    await tx.update(users).set({ status }).where(eq(users.id, id));
  },
};
