import { eq } from "drizzle-orm";
import request from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../apps/server/src/app.js";
import { hashPassword } from "../../apps/server/src/infrastructure/cryptography/password.js";
import { sha256Hex } from "../../apps/server/src/infrastructure/cryptography/tokens.js";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import { authorizationCodes } from "../../apps/server/src/infrastructure/database/schema.js";
import { clientService } from "../../apps/server/src/modules/clients/client.service.js";
import { userService } from "../../apps/server/src/modules/identity/user.service.js";
import { resetDatabase } from "../helpers/db.js";
import { csrfFrom } from "../helpers/http.js";

const redirectUri = "https://app.example.com/callback";
const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";
const issuer = process.env.AUTHARIS_ISSUER ?? "http://localhost:3000";

async function makeClient(
  options: { requireConsent?: boolean; type?: "public" | "confidential" } = {},
) {
  const { client } = await clientService.register({
    name: "Demo application",
    type: options.type ?? "public",
    redirectUris: [redirectUri],
    requireConsent: options.requireConsent ?? true,
    grantTypes: ["authorization_code", "refresh_token"],
    allowedScopes: ["openid", "profile", "email", "offline_access"],
  });
  return client;
}

function authorizeUrl(clientId: string, overrides: Record<string, string> = {}) {
  const params = new URLSearchParams({
    client_id: clientId,
    redirect_uri: redirectUri,
    response_type: "code",
    scope: "openid profile",
    state: "test-state",
    code_challenge: challenge,
    code_challenge_method: "S256",
    ...overrides,
  });
  return `/authorize?${params}`;
}

async function signedInAgent() {
  const email = "authorization-user@example.com";
  const password = "ValidPassword123!";
  const user = await userService.create({
    email,
    passwordHash: await hashPassword(password),
    emailVerified: true,
    displayName: "Authorization User",
  });
  const agent = request.agent(createApp());
  const csrf = await csrfFrom(agent, "/login");
  const login = await agent.post("/login").type("form").send({ _csrf: csrf, email, password });
  expect(login.status).toBe(303);
  return { agent, user };
}

function clientResponse(location: string) {
  return new URL(location, issuer);
}

beforeEach(resetDatabase);

describe("authorization request validation", () => {
  it("returns fatal 400 HTML without a Location for missing, unknown, or disabled clients", async () => {
    const client = await makeClient();
    await clientService.disable(client.id);
    const app = createApp();
    const missing = await request(app).get(
      `/authorize?redirect_uri=${encodeURIComponent(redirectUri)}`,
    );
    const unknown = await request(app).get(authorizeUrl("missing-client"));
    const disabled = await request(app).get(authorizeUrl(client.clientId));
    for (const res of [missing, unknown, disabled]) {
      expect(res.status).toBe(400);
      expect(res.headers.location!).toBeUndefined();
      expect(res.type).toBe("text/html");
    }
  });

  it.each([
    ["missing redirect_uri", (id: string) => `/authorize?client_id=${id}`],
    [
      "unregistered URI",
      (id: string) => authorizeUrl(id, { redirect_uri: "https://evil.example/cb" }),
    ],
    ["trailing slash", (id: string) => authorizeUrl(id, { redirect_uri: `${redirectUri}/` })],
    [
      "different case",
      (id: string) => authorizeUrl(id, { redirect_uri: "https://APP.example.com/callback" }),
    ],
    ["extra query", (id: string) => authorizeUrl(id, { redirect_uri: `${redirectUri}?x=1` })],
    ["prefix", (id: string) => authorizeUrl(id, { redirect_uri: `${redirectUri}/extra` })],
    [
      "look-alike host",
      (id: string) =>
        authorizeUrl(id, { redirect_uri: "https://app.example.com.evil.test/callback" }),
    ],
  ])("rejects fatal redirect URI: %s", async (_label, build) => {
    const client = await makeClient();
    const res = await request(createApp()).get(build(client.clientId));
    expect(res.status).toBe(400);
    expect(res.headers.location!).toBeUndefined();
  });

  it("rejects repeated client_id as fatal", async () => {
    const client = await makeClient();
    const res = await request(createApp()).get(
      `${authorizeUrl(client.clientId)}&client_id=${client.clientId}`,
    );
    expect(res.status).toBe(400);
    expect(res.headers.location!).toBeUndefined();
  });

  it.each([
    ["token response", { response_type: "token" }, "unsupported_response_type"],
    ["id_token response", { response_type: "id_token" }, "unsupported_response_type"],
    ["missing scope", { scope: "" }, "invalid_scope"],
    ["scope without openid", { scope: "profile" }, "invalid_scope"],
    ["request object", { request: "signed" }, "request_not_supported"],
    ["request URI", { request_uri: "https://client.example/request" }, "request_uri_not_supported"],
    ["prompt none with login", { prompt: "none login" }, "invalid_request"],
    ["unknown prompt", { prompt: "bogus" }, "invalid_request"],
    ["negative max_age", { max_age: "-1" }, "invalid_request"],
    ["invalid max_age", { max_age: "abc" }, "invalid_request"],
    [
      "missing PKCE challenge",
      { code_challenge: "", code_challenge_method: "" },
      "invalid_request",
    ],
    ["plain PKCE", { code_challenge_method: "plain" }, "invalid_request"],
    ["PKCE challenge without method", { code_challenge_method: "" }, "invalid_request"],
    ["short PKCE challenge", { code_challenge: "A".repeat(42) }, "invalid_request"],
  ])("redirects validation error for %s", async (_label, overrides, error) => {
    const client = await makeClient();
    const res = await request(createApp()).get(authorizeUrl(client.clientId, overrides));
    expect(res.status).toBe(302);
    const target = clientResponse(res.headers.location!);
    expect(target.origin + target.pathname).toBe(redirectUri);
    expect(target.searchParams.get("error")).toBe(error);
    expect(target.searchParams.get("state")).toBe("test-state");
    expect(target.searchParams.get("iss")).toBe(issuer);
  });

  it("does not echo oversized state and includes issuer on every redirect error", async () => {
    const client = await makeClient();
    const res = await request(createApp()).get(
      authorizeUrl(client.clientId, { state: "x".repeat(513) }),
    );
    const target = clientResponse(res.headers.location!);
    expect(target.searchParams.get("error")).toBe("invalid_request");
    expect(target.searchParams.has("state")).toBe(false);
    expect(target.searchParams.get("iss")).toBe(issuer);
  });
});

describe("authorization interactions", () => {
  it("redirects signed-out users to login, or returns login_required for prompt=none", async () => {
    const client = await makeClient();
    const app = createApp();
    const res = await request(app).get(authorizeUrl(client.clientId));
    expect(res.status).toBe(303);
    expect(res.headers.location!).toMatch(/^\/login\?return_to=\/authorize%3F/);
    const none = await request(app).get(authorizeUrl(client.clientId, { prompt: "none" }));
    const target = clientResponse(none.headers.location!);
    expect(none.status).toBe(302);
    expect(target.searchParams.get("error")).toBe("login_required");
    expect(target.searchParams.get("iss")).toBe(issuer);
  });

  it("validates the login return_to before displaying the client or widening form-action", async () => {
    const client = await makeClient();
    const valid = await request(createApp()).get(
      `/login?return_to=${encodeURIComponent(authorizeUrl(client.clientId))}`,
    );
    expect(valid.text).toContain("Sign in to continue to Demo application");
    expect(valid.headers["content-security-policy"]).toContain(
      "form-action 'self' https://app.example.com",
    );
    const invalid = await request(createApp()).get(
      `/login?return_to=${encodeURIComponent(`/authorize?client_id=${client.clientId}&redirect_uri=https://evil.test/cb`)}`,
    );
    expect(invalid.text).not.toContain("Sign in to continue to");
    expect(invalid.headers["content-security-policy"]).toContain("form-action 'self'");
    expect(invalid.headers["content-security-policy"]).not.toContain("evil.test");
  });

  it("shows consent and CSP origin for a signed-in user, then Allow issues a code and persists only its hash", async () => {
    const client = await makeClient();
    const { agent, user } = await signedInAgent();
    const page = await agent.get(authorizeUrl(client.clientId));
    expect(page.status).toBe(200);
    expect(page.text).toContain("Demo application wants access");
    expect(page.headers["content-security-policy"]).toContain(
      "form-action 'self' https://app.example.com",
    );
    const csrf = /name="_csrf" value="([^"]+)"/.exec(page.text)![1]!;
    const allowed = await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: csrf, return_to: authorizeUrl(client.clientId), decision: "allow" });
    expect(allowed.status).toBe(303);
    expect(allowed.headers.location!).toContain("/authorize?");
    const issued = await agent.get(allowed.headers.location!);
    expect(issued.status).toBe(302);
    const target = clientResponse(issued.headers.location!);
    const rawCode = target.searchParams.get("code")!;
    expect(target.searchParams.get("state")).toBe("test-state");
    expect(target.searchParams.get("iss")).toBe(issuer);
    const rows = await db.select().from(authorizationCodes);
    expect(rows).toHaveLength(1);
    expect(rows[0]!.codeHash).toBe(sha256Hex(rawCode));
    expect(rows[0]!.codeHash).not.toBe(rawCode);
    expect(rows[0]!.clientRef).toBe(client.id);
    expect(rows[0]!.userId).toBe(user.id);
    expect(rows[0]!.redirectUri).toBe(redirectUri);
    expect(rows[0]!.scope).toBe("openid profile");
    expect(rows[0]!.expiresAt.getTime()).toBeGreaterThan(Date.now() + 45_000);
    expect(rows[0]!.expiresAt.getTime()).toBeLessThan(Date.now() + 75_000);
  });

  it("denies consent and reuses consent until a new scope is requested", async () => {
    const client = await makeClient();
    const { agent } = await signedInAgent();
    const page = await agent.get(authorizeUrl(client.clientId));
    const csrf = /name="_csrf" value="([^"]+)"/.exec(page.text)![1]!;
    const denied = await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: csrf, return_to: authorizeUrl(client.clientId), decision: "deny" });
    expect(clientResponse(denied.headers.location!).searchParams.get("error")).toBe(
      "access_denied",
    );
    expect(clientResponse(denied.headers.location!).searchParams.get("state")).toBe("test-state");

    const consentPage = await agent.get(authorizeUrl(client.clientId));
    const token = /name="_csrf" value="([^"]+)"/.exec(consentPage.text)![1]!;
    await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: token, return_to: authorizeUrl(client.clientId), decision: "allow" });
    const followup = await agent.get(authorizeUrl(client.clientId));
    expect(followup.status).toBe(302);
    expect(clientResponse(followup.headers.location!).searchParams.has("code")).toBe(true);
    expect((await agent.get(authorizeUrl(client.clientId, { prompt: "consent" }))).status).toBe(
      200,
    );
    const promptedUrl = authorizeUrl(client.clientId, { prompt: "consent" });
    const promptedPage = await agent.get(promptedUrl);
    const promptedCsrf = /name="_csrf" value="([^"]+)"/.exec(promptedPage.text)![1]!;
    const promptedAllow = await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: promptedCsrf, return_to: promptedUrl, decision: "allow" });
    const afterPromptedAllow = await agent.get(promptedAllow.headers.location!);
    expect(afterPromptedAllow.status).toBe(302);
    expect(clientResponse(afterPromptedAllow.headers.location!).searchParams.has("code")).toBe(
      true,
    );
  });

  it("asks for consent when offline_access was not previously granted", async () => {
    const client = await makeClient();
    const { agent } = await signedInAgent();
    const initialUrl = authorizeUrl(client.clientId, { scope: "openid profile email" });
    const initialPage = await agent.get(initialUrl);
    const initialCsrf = /name="_csrf" value="([^"]+)"/.exec(initialPage.text)![1]!;
    await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: initialCsrf, return_to: initialUrl, decision: "allow" });

    const offlineUrl = authorizeUrl(client.clientId, {
      scope: "openid profile email offline_access",
    });
    const offlinePage = await agent.get(offlineUrl);
    expect(offlinePage.status).toBe(200);
    expect(offlinePage.text).toContain("Stay signed in to the app");
  });

  it("enforces prompt=none, prompt=login, max_age, and no-consent client behavior", async () => {
    const client = await makeClient();
    const { agent } = await signedInAgent();
    const noConsent = await agent.get(authorizeUrl(client.clientId, { prompt: "none" }));
    expect(clientResponse(noConsent.headers.location!).searchParams.get("error")).toBe(
      "consent_required",
    );
    const login = await agent.get(authorizeUrl(client.clientId, { prompt: "login" }));
    expect(login.status).toBe(303);
    expect(login.headers.location!).toContain("/login?");
    const relogCsrf = await csrfFrom(agent, login.headers.location!);
    const relog = await agent
      .post("/login")
      .type("form")
      .send({
        _csrf: relogCsrf,
        email: "authorization-user@example.com",
        password: "ValidPassword123!",
        return_to: authorizeUrl(client.clientId, { prompt: "login" }),
      });
    expect(relog.status).toBe(303);
    expect(relog.headers.location).not.toContain("prompt=login");
    expect((await agent.get(authorizeUrl(client.clientId, { max_age: "0" }))).status).toBe(303);
    const noConsentClient = await makeClient({ requireConsent: false });
    const direct = await agent.get(authorizeUrl(noConsentClient.clientId));
    expect(direct.status).toBe(302);
    expect(clientResponse(direct.headers.location!).searchParams.has("code")).toBe(true);
  });

  it("rejects unsafe consent submissions and returns 400 without redirecting", async () => {
    const client = await makeClient();
    const { agent } = await signedInAgent();
    const noCsrf = await agent
      .post("/consent")
      .type("form")
      .send({ return_to: authorizeUrl(client.clientId), decision: "allow" });
    expect(noCsrf.status).toBe(403);
    const csrf = await csrfFrom(agent, "/login");
    for (const returnTo of [
      "https://evil.test/",
      "/account",
      authorizeUrl(client.clientId, { redirect_uri: "https://evil.test/cb" }),
    ]) {
      const res = await agent
        .post("/consent")
        .type("form")
        .send({ _csrf: csrf, return_to: returnTo, decision: "allow" });
      expect(res.status).toBe(400);
      expect(res.headers.location!).toBeUndefined();
    }
  });

  it("grants only supported scopes when an unknown scope is requested", async () => {
    const client = await makeClient();
    const { agent } = await signedInAgent();
    const url = authorizeUrl(client.clientId, { scope: "openid profile bogus" });
    const page = await agent.get(url);
    const csrf = /name="_csrf" value="([^"]+)"/.exec(page.text)![1]!;
    await agent
      .post("/consent")
      .type("form")
      .send({ _csrf: csrf, return_to: url, decision: "allow" });
    const issued = await agent.get(url);
    const code = clientResponse(issued.headers.location!).searchParams.get("code")!;
    const [row] = await db
      .select()
      .from(authorizationCodes)
      .where(eq(authorizationCodes.codeHash, sha256Hex(code)));
    expect(row!.scope).toBe("openid profile");
  });
});
