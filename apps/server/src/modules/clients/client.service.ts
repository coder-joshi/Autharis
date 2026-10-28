import { db } from "../../infrastructure/database/db.js";
import { randomToken, safeEqual, sha256Hex } from "../../infrastructure/cryptography/tokens.js";
import { clientRepository, type ClientRow } from "./client.repository.js";
import { clientInputSchema } from "./client.validation.js";
export interface ClientWithUris extends ClientRow {
  redirectUris: string[];
  postLogoutRedirectUris: string[];
}
export const clientService = {
  /** Returns the plaintext secret exactly once for confidential clients. */
  async register(raw: unknown): Promise<{ client: ClientRow; clientSecret?: string }> {
    const input = clientInputSchema.parse(raw);
    const authMethod =
      input.type === "public" ? "none" : (input.tokenEndpointAuthMethod ?? "client_secret_basic");
    const clientSecret = input.type === "confidential" ? randomToken(32) : undefined;
    const client = await db.transaction(async (tx) => {
      const row = await clientRepository.insertClient(
        {
          clientId: `cl_${randomToken(16)}`,
          name: input.name,
          type: input.type,
          tokenEndpointAuthMethod: authMethod,
          grantTypes: input.grantTypes,
          allowedScopes: input.allowedScopes,
          requirePkce: input.type === "public" ? true : input.requirePkce,
          requireConsent: input.requireConsent,
        },
        tx,
      );
      const uris = [
        ...[...new Set(input.redirectUris)].map((uri) => ({ kind: "redirect" as const, uri })),
        ...[...new Set(input.postLogoutRedirectUris)].map((uri) => ({
          kind: "post_logout" as const,
          uri,
        })),
      ].map((u) => ({
        clientRef: row.id,
        kind: u.kind,
        uri: u.uri,
        origin: new URL(u.uri).origin,
      }));
      await clientRepository.insertUris(uris, tx);
      if (clientSecret) await clientRepository.insertSecret(row.id, sha256Hex(clientSecret), tx);
      return row;
    });
    return { client, clientSecret };
  },
  /** Active clients only. Disabled or unknown clients return null. */
  async findActive(clientId: string): Promise<ClientWithUris | null> {
    const client = await clientRepository.findByClientId(clientId);
    if (!client || client.status !== "active") return null;
    const [redirectUris, postLogoutRedirectUris] = await Promise.all([
      clientRepository.listUris(client.id, "redirect"),
      clientRepository.listUris(client.id, "post_logout"),
    ]);
    return { ...client, redirectUris, postLogoutRedirectUris };
  },
  /** Exact string comparison. No normalization, no prefix match, no
wildcard. */
  isRegisteredRedirectUri(client: ClientWithUris, uri: string): boolean {
    return client.redirectUris.includes(uri);
  },
  /** Checks every live secret so timing does not reveal which one matched.
   */
  async verifySecret(clientRef: string, presented: string): Promise<boolean> {
    const hashes = await clientRepository.liveSecretHashes(clientRef);
    const candidate = sha256Hex(presented);
    let ok = false;
    for (const h of hashes) if (safeEqual(h, candidate)) ok = true;
    return ok;
  },
  /** Issues a new secret. Old secrets keep working for `overlapSeconds` (0 =
revoke now). */
  async rotateSecret(clientRef: string, overlapSeconds = 0): Promise<string> {
    const secret = randomToken(32);
    await db.transaction(async (tx) => {
      await clientRepository.expireSecrets(clientRef, overlapSeconds, tx);
      await clientRepository.insertSecret(clientRef, sha256Hex(secret), tx);
    });
    return secret;
  },
  disable: (clientRef: string) => clientRepository.setStatus(clientRef, "disabled"),
  enable: (clientRef: string) => clientRepository.setStatus(clientRef, "active"),
};
