import { eq } from "drizzle-orm";
import request, { type Agent } from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../apps/server/src/app.js";
import { hashPassword } from "../../apps/server/src/infrastructure/cryptography/password.js";
import {
  randomToken,
  sha256Hex,
} from "../../apps/server/src/infrastructure/cryptography/tokens.js";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import { sessions } from "../../apps/server/src/infrastructure/database/schema.js";
import { setMailer } from "../../apps/server/src/infrastructure/mail/mailer.js";
import {
  requestPasswordReset,
  resetPassword,
} from "../../apps/server/src/modules/authentication/authentication.service.js";
import { userService } from "../../apps/server/src/modules/identity/user.service.js";
import type { UserRow } from "../../apps/server/src/modules/identity/user.repository.js";
import {
  sessionCookieName,
  sessionCookieOptions,
} from "../../apps/server/src/modules/sessions/session.cookies.js";
import { sessionService } from "../../apps/server/src/modules/sessions/session.service.js";
import { resetDatabase } from "../helpers/db.js";
import { csrfFrom } from "../helpers/http.js";
import { InMemoryMailer } from "../helpers/mailer.js";

interface LoginResult {
  agent: Agent;
  user: UserRow;
  rawCookie: string;
  token: string;
  response: request.Response;
}

async function loginHelper(
  email = "session-user@example.com",
  password = "ValidPassword123!",
): Promise<LoginResult> {
  const passwordHash = await hashPassword(password);
  const user = await userService.create({
    email,
    passwordHash,
    emailVerified: true,
  });

  const agent = request.agent(createApp());
  const csrf = await csrfFrom(agent, "/login");
  const response = await agent.post("/login").type("form").send({ _csrf: csrf, email, password });

  const setCookie = response.headers["set-cookie"] ?? [];
  const rawCookie =
    (Array.isArray(setCookie) ? setCookie : [setCookie]).find((c: string) =>
      c.startsWith(`${sessionCookieName}=`),
    ) ?? "";

  const match = new RegExp(`^${sessionCookieName}=([^;]+)`).exec(rawCookie);
  const token = match ? match[1]! : "";

  return { agent, user, rawCookie, token, response };
}

function stripCsrfToken(html: string): string {
  return html.replace(/name="_csrf" value="[^"]*"/g, 'name="_csrf" value="REDACTED"');
}

describe("Session integration tests", () => {
  beforeEach(async () => {
    await resetDatabase();
  });

  it("Successful login: 303 to /account; Set-Cookie has HttpOnly, SameSite=Lax, Path=/; one sessions row; the raw cookie value is not found anywhere in the table", async () => {
    const { user, rawCookie, token, response } = await loginHelper();

    expect(response.status).toBe(303);
    expect(response.headers.location).toBe("/account");

    expect(rawCookie).toMatch(/httponly/i);
    expect(rawCookie).toMatch(/samesite=lax/i);
    expect(rawCookie).toMatch(/path=\//i);

    const allSessions = await db.select().from(sessions);
    expect(allSessions).toHaveLength(1);
    expect(allSessions[0]!.userId).toBe(user.id);
    expect(allSessions[0]!.tokenHash).toBe(sha256Hex(token));

    const stringifiedTable = JSON.stringify(allSessions);
    expect(stringifiedTable).not.toContain(token);
    expect(stringifiedTable).not.toContain(rawCookie);
  });

  it("Cookie options: sessionCookieOptions(true) has secure: true; sessionCookieOptions(false) has secure: false; both httpOnly and sameSite: 'lax'", () => {
    const prodOptions = sessionCookieOptions(true);
    expect(prodOptions.secure).toBe(true);
    expect(prodOptions.httpOnly).toBe(true);
    expect(prodOptions.sameSite).toBe("lax");

    const devOptions = sessionCookieOptions(false);
    expect(devOptions.secure).toBe(false);
    expect(devOptions.httpOnly).toBe(true);
    expect(devOptions.sameSite).toBe("lax");
  });

  it("Wrong password vs unknown email: Both return 400 with the identical body and set no cookie", async () => {
    const email = "registered@example.com";
    await userService.create({
      email,
      passwordHash: await hashPassword("CorrectPassword123!"),
      emailVerified: true,
    });

    const agent1 = request.agent(createApp());
    const csrf1 = await csrfFrom(agent1, "/login");
    const resWrongPw = await agent1
      .post("/login")
      .type("form")
      .send({ _csrf: csrf1, email, password: "WrongPassword999!" });

    const agent2 = request.agent(createApp());
    const csrf2 = await csrfFrom(agent2, "/login");
    const resUnknown = await agent2
      .post("/login")
      .type("form")
      .send({ _csrf: csrf2, email: "unknown@example.com", password: "AnyPassword123!" });

    expect(resWrongPw.status).toBe(400);
    expect(resUnknown.status).toBe(400);
    expect(stripCsrfToken(resWrongPw.text)).toBe(stripCsrfToken(resUnknown.text));

    const cookiesWrongPw = resWrongPw.headers["set-cookie"] ?? [];
    const hasSessionCookieWrong = (
      Array.isArray(cookiesWrongPw) ? cookiesWrongPw : [cookiesWrongPw]
    ).some((c: string) => c.startsWith(`${sessionCookieName}=`));
    expect(hasSessionCookieWrong).toBe(false);

    const cookiesUnknown = resUnknown.headers["set-cookie"] ?? [];
    const hasSessionCookieUnknown = (
      Array.isArray(cookiesUnknown) ? cookiesUnknown : [cookiesUnknown]
    ).some((c: string) => c.startsWith(`${sessionCookieName}=`));
    expect(hasSessionCookieUnknown).toBe(false);
  });

  it("Unverified user, correct password: 403 with the 'confirm your email' message", async () => {
    const email = "unverified@example.com";
    const password = "ValidPassword123!";
    await userService.create({
      email,
      passwordHash: await hashPassword(password),
      emailVerified: false,
    });

    const agent = request.agent(createApp());
    const csrf = await csrfFrom(agent, "/login");
    const res = await agent.post("/login").type("form").send({ _csrf: csrf, email, password });

    expect(res.status).toBe(403);
    expect(res.text.toLowerCase()).toContain("confirm your email");
  });

  it("Disabled user: Same generic 400 as a wrong password", async () => {
    const email = "disabled@example.com";
    const password = "ValidPassword123!";
    const user = await userService.create({
      email,
      passwordHash: await hashPassword(password),
      emailVerified: true,
    });
    await userService.disable(user.id);

    // Baseline wrong password response to compare body against
    const baselineAgent = request.agent(createApp());
    const baselineCsrf = await csrfFrom(baselineAgent, "/login");
    const resWrongPw = await baselineAgent
      .post("/login")
      .type("form")
      .send({ _csrf: baselineCsrf, email: "unknown@example.com", password });

    const agent = request.agent(createApp());
    const csrf = await csrfFrom(agent, "/login");
    const resDisabled = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrf, email, password });

    expect(resDisabled.status).toBe(400);
    expect(stripCsrfToken(resDisabled.text)).toBe(stripCsrfToken(resWrongPw.text));

    const setCookie = resDisabled.headers["set-cookie"] ?? [];
    const hasSessionCookie = (Array.isArray(setCookie) ? setCookie : [setCookie]).some(
      (c: string) => c.startsWith(`${sessionCookieName}=`),
    );
    expect(hasSessionCookie).toBe(false);
  });

  it("Expired absolute session (set expires_at in the past): GET /account redirects to /login", async () => {
    const { agent } = await loginHelper();

    // Verify session initially works
    const okRes = await agent.get("/account");
    expect(okRes.status).toBe(200);

    // Expire absolute session in DB
    await db.update(sessions).set({ expiresAt: new Date(Date.now() - 1000) });

    const res = await agent.get("/account");
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/login");
  });

  it("Expired idle session (set last_seen_at 3 hours ago): Redirects to /login", async () => {
    const { agent } = await loginHelper();

    // Set last_seen_at 3 hours in the past
    await db.update(sessions).set({ lastSeenAt: new Date(Date.now() - 3 * 60 * 60 * 1000) });

    const res = await agent.get("/account");
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/login");
  });

  it("Revoked session: Redirects to /login", async () => {
    const { agent } = await loginHelper();

    // Revoke session in DB
    await db.update(sessions).set({ revokedAt: new Date() });

    const res = await agent.get("/account");
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/login");
  });

  it("Malformed cookies ( x , 300 characters, random 43 characters): Treated as signed out, no 500", async () => {
    const app = createApp();
    const malformed = ["x", "a".repeat(300), randomToken(43)];

    for (const val of malformed) {
      const res = await request(app).get("/account").set("Cookie", `${sessionCookieName}=${val}`);

      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/login");
    }
  });

  it("Logout: revoked_at is set; replaying the old cookie value in a new request fails", async () => {
    const { agent, token } = await loginHelper();

    const csrf = await csrfFrom(agent, "/account");
    const logoutRes = await agent.post("/logout").type("form").send({ _csrf: csrf });
    expect(logoutRes.status).toBe(303);
    expect(logoutRes.headers.location).toBe("/login");

    const [dbSession] = await db.select().from(sessions);
    expect(dbSession!.revokedAt).not.toBeNull();

    // Replay old cookie in a new agent
    const replayAgent = request.agent(createApp());
    const replayRes = await replayAgent
      .get("/account")
      .set("Cookie", `${sessionCookieName}=${token}`);

    expect(replayRes.status).toBe(303);
    expect(replayRes.headers.location).toBe("/login");
  });

  it("Fixation: Logging in while holding a session revokes it and issues a different token", async () => {
    const { agent, token: token1 } = await loginHelper("first@example.com", "Password123!");

    const [firstDbSession] = await db.select().from(sessions);
    expect(firstDbSession!.revokedAt).toBeNull();

    // Create second user
    await userService.create({
      email: "second@example.com",
      passwordHash: await hashPassword("Password123!"),
      emailVerified: true,
    });

    // Log in as second user holding the active agent/cookie
    const csrf2 = await csrfFrom(agent, "/login");
    const res2 = await agent
      .post("/login")
      .type("form")
      .send({ _csrf: csrf2, email: "second@example.com", password: "Password123!" });

    expect(res2.status).toBe(303);

    const setCookie2 = res2.headers["set-cookie"] ?? [];
    const rawCookie2 =
      (Array.isArray(setCookie2) ? setCookie2 : [setCookie2]).find((c: string) =>
        c.startsWith(`${sessionCookieName}=`),
      ) ?? "";
    const match2 = new RegExp(`^${sessionCookieName}=([^;]+)`).exec(rawCookie2);
    const token2 = match2 ? match2[1]! : "";

    expect(token2).toBeTruthy();
    expect(token2).not.toBe(token1);

    // Old session must be revoked
    const [oldDbSession] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, firstDbSession!.id));
    expect(oldDbSession!.revokedAt).not.toBeNull();

    // New session must be active
    const [newDbSession] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.tokenHash, sha256Hex(token2)));
    expect(newDbSession!.revokedAt).toBeNull();
  });

  it("revokeAllForUser(userId, keep): Other sessions die, keep survives", async () => {
    const user = await userService.create({
      email: "multi-session@example.com",
      emailVerified: true,
    });
    const ctx = { ip: "127.0.0.1", userAgent: "test-agent" };

    const s1 = await sessionService.create(user.id, ctx);
    const s2 = await sessionService.create(user.id, ctx);
    const s3 = await sessionService.create(user.id, ctx);

    await sessionService.revokeAllForUser(user.id, s2.session.id);

    expect(await sessionService.validate(s1.token)).toBeNull();
    expect(await sessionService.validate(s2.token)).not.toBeNull();
    expect(await sessionService.validate(s3.token)).toBeNull();
  });

  it("Disabling a user: Their live session stops validating immediately", async () => {
    const { agent, user } = await loginHelper();

    const okRes = await agent.get("/account");
    expect(okRes.status).toBe(200);

    await userService.disable(user.id);

    const res = await agent.get("/account");
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/login");
  });

  it("Password reset: After resetPassword, previously valid sessions stop validating", async () => {
    const { agent, user } = await loginHelper("reset-flow@example.com", "OldPassword123!");

    const okRes = await agent.get("/account");
    expect(okRes.status).toBe(200);

    const mailer = new InMemoryMailer();
    setMailer(mailer);
    const ctx = { ip: "127.0.0.1", userAgent: "test-agent" };

    await requestPasswordReset(user.email, ctx);
    const resetToken = mailer.tokenOf("reset");
    const ok = await resetPassword(resetToken, "NewPassword123!", ctx);
    expect(ok).toBe(true);

    const res = await agent.get("/account");
    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/login");
  });

  it("CSRF: POST /login and POST /logout without the token return 403", async () => {
    const agent = request.agent(createApp());

    const loginRes = await agent
      .post("/login")
      .type("form")
      .send({ email: "csrf@example.com", password: "Password123!" });
    expect(loginRes.status).toBe(403);

    const logoutRes = await agent.post("/logout").type("form").send({});
    expect(logoutRes.status).toBe(403);
  });

  it("return_to: //evil.com, https://evil.com, /other and a value containing a backslash are ignored and land on /account; /authorize?client_id=x is honored; prompt=login consent becomes prompt=consent after login", async () => {
    const email = "return-to@example.com";
    const password = "ValidPassword123!";
    await userService.create({
      email,
      passwordHash: await hashPassword(password),
      emailVerified: true,
    });

    async function loginWithReturnTo(returnTo: string) {
      const agent = request.agent(createApp());
      const csrf = await csrfFrom(agent, `/login?return_to=${encodeURIComponent(returnTo)}`);
      return agent
        .post("/login")
        .type("form")
        .send({ _csrf: csrf, email, password, return_to: returnTo });
    }

    // Invalid return_to paths ignored, defaulting to /account
    const invalidReturnTos = ["//evil.com", "https://evil.com", "/other", "/authorize?\\bad"];
    for (const invalid of invalidReturnTos) {
      const res = await loginWithReturnTo(invalid);
      expect(res.status).toBe(303);
      expect(res.headers.location).toBe("/account");
    }

    // /authorize?client_id=x is honored
    const resHonored = await loginWithReturnTo("/authorize?client_id=x");
    expect(resHonored.status).toBe(303);
    expect(resHonored.headers.location).toBe("/authorize?client_id=x");

    // prompt=login consent becomes prompt=consent after login
    const resPrompt = await loginWithReturnTo("/authorize?prompt=login consent");
    expect(resPrompt.status).toBe(303);
    expect(resPrompt.headers.location).toBe("/authorize?prompt=consent");
  });

  it("Another user's session id: POST /account/sessions/<id>/revoke for a session you do not own changes nothing", async () => {
    const { agent: agent1 } = await loginHelper("victim@example.com", "Password123!");
    const { user: user2 } = await loginHelper("attacker@example.com", "Password123!");

    const [user2Session] = await db.select().from(sessions).where(eq(sessions.userId, user2.id));
    expect(user2Session).toBeDefined();
    expect(user2Session!.revokedAt).toBeNull();

    // User 1 tries to revoke User 2's session
    const csrf1 = await csrfFrom(agent1, "/account");
    const res = await agent1
      .post(`/account/sessions/${user2Session!.id}/revoke`)
      .type("form")
      .send({ _csrf: csrf1 });

    expect(res.status).toBe(303);
    expect(res.headers.location).toBe("/account");

    // Session 2 should remain unrevoked
    const [user2SessionAfter] = await db
      .select()
      .from(sessions)
      .where(eq(sessions.id, user2Session!.id));
    expect(user2SessionAfter!.revokedAt).toBeNull();
  });
});
