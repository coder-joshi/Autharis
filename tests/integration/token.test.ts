import { createHash } from "node:crypto";
import request, { type Agent } from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../apps/server/src/app.js";
import { sha256Hex } from "../../apps/server/src/infrastructure/cryptography/tokens.js";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import {
  accessTokens,
  authorizationCodes,
  oauthClientSecrets,
} from "../../apps/server/src/infrastructure/database/schema.js";
import { clientService } from "../../apps/server/src/modules/clients/client.service.js";
import { userService } from "../../apps/server/src/modules/identity/user.service.js";
import { resetDatabase } from "../helpers/db.js";
import { csrfFrom } from "../helpers/http.js";
import { hashPassword } from "../../apps/server/src/infrastructure/cryptography/password.js";

const callback = "https://app.example.com/callback";
const verifier = "v".repeat(43);
const challenge = createHash("sha256").update(verifier).digest("base64url");
const password = "ValidPassword123!";

type ClientOptions = {
  type?: "public" | "confidential";
  tokenEndpointAuthMethod?: "client_secret_basic" | "client_secret_post";
  requirePkce?: boolean;
  grantTypes?: string[];
};

async function makeClient(options: ClientOptions = {}) {
  return clientService.register({
    name: "Token test client",
    type: options.type ?? "public",
    tokenEndpointAuthMethod: options.tokenEndpointAuthMethod,
    requirePkce: options.requirePkce ?? true,
    redirectUris: [callback],
    grantTypes: options.grantTypes ?? ["authorization_code", "refresh_token"],
  });
}

async function signedInAgent(): Promise<{
  agent: Agent;
  user: Awaited<ReturnType<typeof userService.create>>;
}> {
  const email = "token-user@example.com";
  const user = await userService.create({
    email,
    passwordHash: await hashPassword(password),
    emailVerified: true,
  });
  const agent = request.agent(createApp());
  const csrf = await csrfFrom(agent, "/login");
  const login = await agent.post("/login").type("form").send({ _csrf: csrf, email, password });
  expect(login.status).toBe(303);
  return { agent, user };
}

async function obtainCode(
  clientId: string,
  options: { verifier?: string; includeChallenge?: boolean } = {},
) {
  const { agent, user } = await signedInAgent();
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: callback,
    response_type: "code",
    scope: "openid profile",
    state: "token-state",
  });
  if (options.includeChallenge !== false) {
    params.set("code_challenge", challenge);
    params.set("code_challenge_method", "S256");
  }
  const authorizePath = `/authorize?${params}`;
  const consent = await agent.get(authorizePath);
  expect(consent.status).toBe(200);
  const csrf = /name="_csrf" value="([^"]+)"/.exec(consent.text)![1]!;
  const approved = await agent
    .post("/consent")
    .type("form")
    .send({ _csrf: csrf, return_to: authorizePath, decision: "allow" });
  expect(approved.status).toBe(303);
  const redirected = await agent.get(approved.headers.location!);
  expect(redirected.status).toBe(302);
  const returned = new URL(redirected.headers.location!);
  return {
    code: returned.searchParams.get("code")!,
    user,
    agent,
  };
}

function tokenRequest(
  fields: Record<string, string>,
  auth?: { clientId: string; secret: string; method: "basic" | "post" | "none" },
  app = createApp(),
) {
  let req = request(app).post("/token").type("form");
  const body = { ...fields };
  if (auth?.method === "basic") {
    const credentials = `${encodeURIComponent(auth.clientId)}:${encodeURIComponent(auth.secret)}`;
    req = req.set("Authorization", `Basic ${Buffer.from(credentials).toString("base64")}`);
  }
  if (auth?.method === "post") {
    body.client_id = auth.clientId;
    body.client_secret = auth.secret;
  } else if (auth?.method === "none") {
    body.client_id = auth.clientId;
  }
  return req.send(body);
}

function codeFields(code: string, extra: Record<string, string> = {}) {
  return {
    grant_type: "authorization_code",
    code,
    redirect_uri: callback,
    code_verifier: verifier,
    ...extra,
  };
}

beforeEach(resetDatabase);

describe("OAuth token endpoint", () => {
  it("issues a public-client access token and stores only its SHA-256 hash", async () => {
    const { client } = await makeClient();
    const { code, user } = await obtainCode(client.clientId);
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: "",
      method: "none",
    });
    expect(res.status).toBe(200);
    expect(res.body.token_type).toBe("Bearer");
    expect(res.body.expires_in).toBe(600);
    expect(res.body.scope).toBe("openid profile");
    expect(res.headers["cache-control"]).toBe("no-store");
    expect(res.headers.pragma).toBe("no-cache");
    const [token] = await db.select().from(accessTokens);
    expect(token!.tokenHash).toBe(sha256Hex(res.body.access_token));
    expect(token!.tokenHash).not.toBe(res.body.access_token);
    expect(token!.clientRef).toBe(client.id);
    expect(token!.userId).toBe(user.id);
  });

  it.each([
    ["Basic", "client_secret_basic", "basic"],
    ["POST", "client_secret_post", "post"],
  ] as const)("authenticates a confidential client with %s", async (_label, method, transport) => {
    const { client, clientSecret } = await makeClient({
      type: "confidential",
      tokenEndpointAuthMethod: method,
    });
    const { code } = await obtainCode(client.clientId);
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: clientSecret!,
      method: transport,
    });
    expect(res.status).toBe(200);
  });

  it("revokes tokens from a code when that code is replayed", async () => {
    const { client } = await makeClient();
    const { code } = await obtainCode(client.clientId);
    const auth = { clientId: client.clientId, secret: "", method: "none" as const };
    expect((await tokenRequest(codeFields(code), auth)).status).toBe(200);
    expect((await tokenRequest(codeFields(code), auth)).body.error).toBe("invalid_grant");
    const [token] = await db.select().from(accessTokens);
    expect(token!.revokedAt).toBeInstanceOf(Date);
  });

  it("allows exactly one of two concurrent exchanges", async () => {
    const { client } = await makeClient();
    const { code } = await obtainCode(client.clientId);
    const auth = { clientId: client.clientId, secret: "", method: "none" as const };
    const results = await Promise.all([
      tokenRequest(codeFields(code), auth),
      tokenRequest(codeFields(code), auth),
    ]);
    expect(results.map((r) => r.status).sort()).toEqual([200, 400]);
  });

  it("rejects expired codes", async () => {
    const { client } = await makeClient();
    const { code } = await obtainCode(client.clientId);
    await db.update(authorizationCodes).set({ expiresAt: new Date(Date.now() - 1000) });
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: "",
      method: "none",
    });
    expect(res.status).toBe(400);
    expect(res.body.error).toBe("invalid_grant");
  });

  it.each([
    ["wrong verifier", "x".repeat(43)],
    ["missing verifier", undefined],
    ["short verifier", "x".repeat(42)],
  ])("rejects %s", async (_label, submittedVerifier) => {
    const { client } = await makeClient();
    const { code } = await obtainCode(client.clientId);
    const fields = codeFields(code);
    if (submittedVerifier === undefined) delete (fields as Partial<typeof fields>).code_verifier;
    else fields.code_verifier = submittedVerifier;
    const res = await tokenRequest(fields, {
      clientId: client.clientId,
      secret: "",
      method: "none",
    });
    expect(res.body.error).toBe("invalid_grant");
  });

  it("rejects a verifier when the code has no stored challenge", async () => {
    const { client, clientSecret } = await makeClient({
      type: "confidential",
      tokenEndpointAuthMethod: "client_secret_post",
      requirePkce: false,
    });
    const { code } = await obtainCode(client.clientId, { includeChallenge: false });
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: clientSecret!,
      method: "post",
    });
    expect(res.body.error).toBe("invalid_grant");
  });

  it.each([
    ["missing redirect_uri", undefined],
    ["different redirect_uri", "https://other.example/callback"],
  ])("rejects %s", async (_label, redirectUri) => {
    const { client } = await makeClient();
    const { code } = await obtainCode(client.clientId);
    const fields = codeFields(code);
    if (redirectUri === undefined) delete (fields as Partial<typeof fields>).redirect_uri;
    else fields.redirect_uri = redirectUri;
    const res = await tokenRequest(fields, {
      clientId: client.clientId,
      secret: "",
      method: "none",
    });
    expect(res.body.error).toBe("invalid_grant");
  });

  it("burns a code presented by a different client", async () => {
    const real = await makeClient();
    const other = await makeClient();
    const { code } = await obtainCode(real.client.clientId);
    const rejected = await tokenRequest(codeFields(code), {
      clientId: other.client.clientId,
      secret: "",
      method: "none",
    });
    expect(rejected.body.error).toBe("invalid_grant");
    const retry = await tokenRequest(codeFields(code), {
      clientId: real.client.clientId,
      secret: "",
      method: "none",
    });
    expect(retry.body.error).toBe("invalid_grant");
  });

  it("rejects a code after its user is disabled", async () => {
    const { client } = await makeClient();
    const { code, user } = await obtainCode(client.clientId);
    await userService.disable(user.id);
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: "",
      method: "none",
    });
    expect(res.body.error).toBe("invalid_grant");
  });

  it("validates client authentication method and credentials", async () => {
    const basic = await makeClient({
      type: "confidential",
      tokenEndpointAuthMethod: "client_secret_basic",
    });
    const post = await makeClient({
      type: "confidential",
      tokenEndpointAuthMethod: "client_secret_post",
    });
    const publicClient = await makeClient();
    const noCode = { grant_type: "authorization_code", code: "missing", redirect_uri: callback };
    const badBasic = await tokenRequest(noCode, {
      clientId: basic.client.clientId,
      secret: "wrong",
      method: "basic",
    });
    expect(badBasic.status).toBe(401);
    expect(badBasic.body.error).toBe("invalid_client");
    expect(badBasic.headers["www-authenticate"]).toContain("Basic");
    const badPost = await tokenRequest(noCode, {
      clientId: post.client.clientId,
      secret: "wrong",
      method: "post",
    });
    expect(badPost.status).toBe(401);
    expect(badPost.headers["www-authenticate"]).toBeUndefined();
    const mixed = await tokenRequest(noCode, {
      clientId: basic.client.clientId,
      secret: basic.clientSecret!,
      method: "post",
    }).set(
      "Authorization",
      `Basic ${Buffer.from(`${basic.client.clientId}:${basic.clientSecret}`).toString("base64")}`,
    );
    expect(mixed.status).toBe(400);
    expect(mixed.body.error).toBe("invalid_request");
    const mismatch = await request(createApp())
      .post("/token")
      .type("form")
      .set(
        "Authorization",
        `Basic ${Buffer.from(`${basic.client.clientId}:${basic.clientSecret}`).toString("base64")}`,
      )
      .send({ ...noCode, client_id: "another-client" });
    expect(mismatch.body.error).toBe("invalid_request");
    const wrongMethod = await tokenRequest(noCode, {
      clientId: basic.client.clientId,
      secret: basic.clientSecret!,
      method: "post",
    });
    expect(wrongMethod.status).toBe(401);
    const publicSecret = await tokenRequest(noCode, {
      clientId: publicClient.client.clientId,
      secret: "secret",
      method: "post",
    });
    expect(publicSecret.status).toBe(401);
    const missingSecret = await request(createApp())
      .post("/token")
      .type("form")
      .send({ ...noCode, client_id: basic.client.clientId });
    expect(missingSecret.status).toBe(401);
    await clientService.disable(basic.client.id);
    const disabled = await tokenRequest(noCode, {
      clientId: basic.client.clientId,
      secret: basic.clientSecret!,
      method: "basic",
    });
    expect(disabled.status).toBe(401);
  });

  it("decodes URL-encoded Basic credentials containing reserved characters", async () => {
    const { client } = await makeClient({
      type: "confidential",
      tokenEndpointAuthMethod: "client_secret_basic",
    });
    const secret = "a:b+c%d/e";
    await db
      .insert(oauthClientSecrets)
      .values({ clientRef: client.id, secretHash: sha256Hex(secret) });
    const { code } = await obtainCode(client.clientId);
    const res = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret,
      method: "basic",
    });
    expect(res.status).toBe(200);
  });

  it("rejects malformed request shapes and unsupported grants safely", async () => {
    const { client } = await makeClient();
    const json = await request(createApp())
      .post("/token")
      .send({ grant_type: "authorization_code" });
    expect(json.status).toBe(400);
    expect(json.body.error).toBe("invalid_request");
    const missing = await tokenRequest(
      {},
      { clientId: client.clientId, secret: "", method: "none" },
    );
    expect(missing.body.error).toBe("invalid_request");
    const repeated = await request(createApp())
      .post("/token")
      .type("form")
      .send("client_id=x&client_id=y&grant_type=authorization_code");
    expect(repeated.status).toBe(400);
    expect(repeated.body.error).toBe("invalid_request");
    const repeatedGrant = await request(createApp())
      .post("/token")
      .type("form")
      .send(`client_id=${client.clientId}&grant_type=authorization_code&grant_type=password`);
    expect(repeatedGrant.status).toBe(400);
    expect(repeatedGrant.body.error).toBe("invalid_request");
    const repeatedCode = await request(createApp())
      .post("/token")
      .type("form")
      .send(`client_id=${client.clientId}&grant_type=authorization_code&code=a&code=b`);
    expect(repeatedCode.status).toBe(400);
    expect(repeatedCode.body.error).toBe("invalid_request");
    for (const grant of ["password", "client_credentials"]) {
      const res = await tokenRequest(
        { grant_type: grant },
        { clientId: client.clientId, secret: "", method: "none" },
      );
      expect(res.body.error).toBe("unsupported_grant_type");
    }
    const noRefresh = await makeClient({ grantTypes: ["authorization_code"] });
    const refresh = await tokenRequest(
      { grant_type: "refresh_token" },
      { clientId: noRefresh.client.clientId, secret: "", method: "none" },
    );
    expect(refresh.body.error).toBe("unauthorized_client");
    const oversized = await request(createApp())
      .post("/token")
      .set("Content-Type", "application/x-www-form-urlencoded")
      .send(`x=${"a".repeat(33_000)}`);
    expect(oversized.status).toBe(413);
    expect(oversized.body.error).toBe("invalid_request");
    const malformed = await request(createApp())
      .post("/token")
      .set("Content-Type", "application/json")
      .send('{"grant_type":');
    expect(malformed.status).toBe(400);
    expect(malformed.body.error).toBe("invalid_request");
    const [codeRow] = await db.select().from(authorizationCodes).limit(1);
    expect(codeRow).toBeUndefined();
  });

  it("returns generic OAuth errors with no internal details", async () => {
    const { client } = await makeClient();
    const res = await tokenRequest(
      { grant_type: "authorization_code", code: "bad", redirect_uri: callback },
      { clientId: client.clientId, secret: "", method: "none" },
    );
    expect(Object.keys(res.body).sort()).toEqual(["error", "error_description"]);
    expect(JSON.stringify(res.body)).not.toMatch(/stack|sql|\/home\/|node_modules/i);
  });

  it("rate limits token requests with OAuth JSON", async () => {
    const app = createApp({ limits: { tokenIp: 2 } });
    const fields = { grant_type: "unknown" };
    await request(app).post("/token").type("form").send(fields);
    await request(app).post("/token").type("form").send(fields);
    const limited = await request(app).post("/token").type("form").send(fields);
    expect(limited.status).toBe(429);
    expect(limited.body.error).toBe("temporarily_unavailable");
  });

  it("adds CORS only for active registered redirect origins and supports preflight", async () => {
    const app = createApp();
    const { client } = await makeClient();
    const allowed = await request(app).options("/token").set("Origin", "https://app.example.com");
    expect(allowed.status).toBe(204);
    expect(allowed.headers["access-control-allow-origin"]).toBe("https://app.example.com");
    const denied = await request(app).options("/token").set("Origin", "https://evil.example");
    expect(denied.status).toBe(204);
    expect(denied.headers["access-control-allow-origin"]).toBeUndefined();
    const { code } = await obtainCode(client.clientId);
    const cors = await tokenRequest(codeFields(code), {
      clientId: client.clientId,
      secret: "",
      method: "none",
    }).set("Origin", "https://app.example.com");
    expect(cors.headers["access-control-allow-origin"]).toBe("https://app.example.com");
  });
});
