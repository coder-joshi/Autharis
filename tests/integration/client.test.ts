import { sql } from "drizzle-orm";
import { beforeEach, describe, expect, it } from "vitest";
import { ZodError } from "zod";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import { validateRedirectUri } from "../../apps/server/src/modules/clients/client.validation.js";
import { clientService } from "../../apps/server/src/modules/clients/client.service.js";
import { resetDatabase } from "../helpers/db.js";
beforeEach(resetDatabase);
const base = {
  name: "Demo",
  type: "confidential" as const,
  redirectUris: ["https://app.example.com/callback"],
};
describe("redirect URI validation", () => {
  it.each([
    "https://app.example.com/cb",
    "http://localhost:5173/cb",
    "http://127.0.0.1:8080/cb",
    "http://[::1]:3000/cb",
  ])("accepts %s", (uri) => expect(validateRedirectUri(uri).ok).toBe(true));
  it.each([
    "",
    "/relative",
    "http://app.example.com/cb",
    "https://app.example.com/cb#frag",
    "https://*.example.com/cb",
    "javascript:alert(1)",
    "https://user:pw@app.example.com/cb",
    "ftp://app.example.com/cb",
  ])("rejects %j", (uri) => expect(validateRedirectUri(uri).ok).toBe(false));
});
describe("client registration", () => {
  it("returns the secret once and stores only a hash", async () => {
    const { client, clientSecret } = await clientService.register(base);
    expect(clientSecret).toHaveLength(43);
    const rows = await db.execute(sql`select secret_hash from
oauth_client_secrets`);
    expect(rows.rows[0]?.secret_hash).not.toBe(clientSecret);
    expect(await clientService.verifySecret(client.id, clientSecret!)).toBe(true);
    expect(await clientService.verifySecret(client.id, "wrong")).toBe(false);
  });
  it("issues no secret to public clients", async () => {
    const { clientSecret } = await clientService.register({ ...base, type: "public" });
    expect(clientSecret).toBeUndefined();
  });
  it("rejects invalid configurations", async () => {
    const bad = [
      { ...base, type: "public", tokenEndpointAuthMethod: "client_secret_basic" },
      { ...base, type: "public", requirePkce: false },
      { ...base, tokenEndpointAuthMethod: "none" },
      { ...base, grantTypes: ["refresh_token"] },
      { ...base, allowedScopes: ["profile"] },
      { ...base, allowedScopes: ["openid", "offline_access"] },
      { ...base, redirectUris: [] },
      { ...base, redirectUris: ["http://evil.example.com/cb"] },
    ];
    for (const input of bad) {
      await expect(clientService.register(input)).rejects.toBeInstanceOf(ZodError);
    }
  });
  it("does not return disabled clients", async () => {
    const { client } = await clientService.register(base);
    expect(await clientService.findActive(client.clientId)).not.toBeNull();
    await clientService.disable(client.id);
    expect(await clientService.findActive(client.clientId)).toBeNull();
  });
  it("matches redirect URIs by exact string only", async () => {
    const { client } = await clientService.register(base);
    const active = (await clientService.findActive(client.clientId))!;
    expect(clientService.isRegisteredRedirectUri(active, "https://app.example.com/callback")).toBe(
      true,
    );
    for (const uri of [
      "https://app.example.com/callback/",
      "https://app.example.com/callback?x=1",
      "https://app.example.com/callbac",
      "https://APP.example.com/callback",
      "https://app.example.com.evil.com/callback",
    ]) {
      expect(clientService.isRegisteredRedirectUri(active, uri)).toBe(false);
    }
  });
  it("rotates secrets, optionally with overlap", async () => {
    const { client, clientSecret } = await clientService.register(base);
    const fresh = await clientService.rotateSecret(client.id, 0);
    expect(await clientService.verifySecret(client.id, clientSecret!)).toBe(false);
    expect(await clientService.verifySecret(client.id, fresh)).toBe(true);
    const overlap = await clientService.rotateSecret(client.id, 3600);
    expect(await clientService.verifySecret(client.id, fresh)).toBe(true);
    expect(await clientService.verifySecret(client.id, overlap)).toBe(true);
  });
  it("enforces the database CHECK constraints even if the service isbypassed", async () => {
    await expect(
      db.execute(sql`insert into oauth_clients (client_id, name, type,
token_endpoint_auth_method, grant_types, allowed_scopes)
values ('x', 'x', 'public', 'client_secret_basic',
'{authorization_code}', '{openid}')`),
    ).rejects.toThrow();
  });
  it("enforces unique client ids at the database", async () => {
    const insert = sql`insert into oauth_clients (client_id, name, type,
token_endpoint_auth_method, grant_types, allowed_scopes)
values ('dup', 'x', 'public', 'none', '{authorization_code}',
'{openid}')`;
    await db.execute(insert);
    await expect(db.execute(insert)).rejects.toThrow();
  });
});
