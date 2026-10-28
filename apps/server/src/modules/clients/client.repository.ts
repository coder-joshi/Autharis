import { and, eq, gt, isNull, or, sql } from "drizzle-orm";
import { db, type DbOrTx } from "../../infrastructure/database/db.js";
import {
  oauthClients,
  oauthClientSecrets,
  oauthClientUris,
} from "../../infrastructure/database/schema.js";
export type ClientRow = typeof oauthClients.$inferSelect;
export const clientRepository = {
  async insertClient(values: typeof oauthClients.$inferInsert, tx: DbOrTx = db) {
    const [row] = await tx.insert(oauthClients).values(values).returning();
    return row!;
  },
  async insertUris(rows: (typeof oauthClientUris.$inferInsert)[], tx: DbOrTx = db) {
    if (rows.length > 0) await tx.insert(oauthClientUris).values(rows);
  },
  async findByClientId(clientId: string, tx: DbOrTx = db): Promise<ClientRow | null> {
    const [row] = await tx
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, clientId))
      .limit(1);
    return row ?? null;
  },
  async listUris(clientRef: string, kind: "redirect" | "post_logout", tx: DbOrTx = db) {
    const rows = await tx
      .select({ uri: oauthClientUris.uri })
      .from(oauthClientUris)
      .where(and(eq(oauthClientUris.clientRef, clientRef), eq(oauthClientUris.kind, kind)));
    return rows.map((r) => r.uri);
  },
  async setStatus(clientRef: string, status: "active" | "disabled", tx: DbOrTx = db) {
    await tx.update(oauthClients).set({ status }).where(eq(oauthClients.id, clientRef));
  },
  async insertSecret(clientRef: string, secretHash: string, tx: DbOrTx = db) {
    await tx.insert(oauthClientSecrets).values({ clientRef, secretHash });
  },
  /**
* Ends the life of every live secret `overlapSeconds` from now (0 =
immediately).
* Uses the database clock so it agrees with liveSecretHashes below.
*/
  async expireSecrets(clientRef: string, overlapSeconds: number, tx: DbOrTx = db) {
    const at = sql`now() + make_interval(secs => ${overlapSeconds})`;
    await tx
      .update(oauthClientSecrets)
      .set({ expiresAt: at })
      .where(
        and(
          eq(oauthClientSecrets.clientRef, clientRef),
          isNull(oauthClientSecrets.revokedAt),
          or(isNull(oauthClientSecrets.expiresAt), gt(oauthClientSecrets.expiresAt, at)),
        ),
      );
  },
  async liveSecretHashes(clientRef: string, tx: DbOrTx = db): Promise<string[]> {
    const rows = await tx
      .select({ h: oauthClientSecrets.secretHash })
      .from(oauthClientSecrets)
      .where(
        and(
          eq(oauthClientSecrets.clientRef, clientRef),
          isNull(oauthClientSecrets.revokedAt),
          or(isNull(oauthClientSecrets.expiresAt), gt(oauthClientSecrets.expiresAt, sql`now()`)),
        ),
      );
    return rows.map((r) => r.h);
  },
};
