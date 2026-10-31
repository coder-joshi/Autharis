import { sql, eq } from "drizzle-orm";
import request, { type Agent } from "supertest";
import { beforeEach, describe, expect, it } from "vitest";
import { createApp } from "../../apps/server/src/app.js";
import {
  hashPassword,
  verifyPassword,
} from "../../apps/server/src/infrastructure/cryptography/password.js";
import { sha256Hex } from "../../apps/server/src/infrastructure/cryptography/tokens.js";
import { db } from "../../apps/server/src/infrastructure/database/db.js";
import { auditEvents, users } from "../../apps/server/src/infrastructure/database/schema.js";
import { setMailer } from "../../apps/server/src/infrastructure/mail/mailer.js";
import {
  authenticate,
  EmailNotVerifiedError,
  InvalidCredentialsError,
  requestPasswordReset,
  resetPassword,
  verifyEmail,
} from "../../apps/server/src/modules/authentication/authentication.service.js";
import { userService } from "../../apps/server/src/modules/identity/user.service.js";
import { resetDatabase } from "../helpers/db.js";
import { csrfFrom } from "../helpers/http.js";
import { InMemoryMailer } from "../helpers/mailer.js";

describe("Authentication integration tests", () => {
  let agent: Agent;
  let mailer: InMemoryMailer;

  beforeEach(async () => {
    await resetDatabase();
    mailer = new InMemoryMailer();
    setMailer(mailer);
    agent = request.agent(createApp());
  });

  it("Password hashing: hash differs from input, correct verifies, wrong fails, malformed returns false, NFKC-equivalent verify", async () => {
    const password = "CorrectHorseBatteryStaple!";
    const hash = await hashPassword(password);

    // Hash differs from input
    expect(hash).not.toBe(password);

    // Correct password verifies
    expect(await verifyPassword(password, hash)).toBe(true);

    // Wrong password fails
    expect(await verifyPassword("WrongPassword123!", hash)).toBe(false);

    // Malformed hash returns false
    expect(await verifyPassword(password, "malformed-hash-string")).toBe(false);
    expect(await verifyPassword(password, "$argon2id$v=19$m=65536,t=3,p=4$badhash")).toBe(false);

    // NFKC-equivalent passwords verify
    // Combining character sequence vs precomposed character
    const composed = "caf\u00E9Password123!";
    const decomposed = "cafe\u0301Password123!";
    expect(composed).not.toBe(decomposed);

    const hashComposed = await hashPassword(composed);
    expect(await verifyPassword(decomposed, hashComposed)).toBe(true);
  });

  it("Register new email: one user row, stored hash starts with $argon2id$, one verification mail", async () => {
    const email = "alice@example.com";
    const password = "validPassword123!";
    const csrf = await csrfFrom(agent, "/register");

    const res = await agent.post("/register").send({
      email,
      password,
      _csrf: csrf,
    });
    expect(res.status).toBe(200);

    const userRows = await db
      .select()
      .from(users)
      .where(eq(users.emailNormalized, "alice@example.com"));
    expect(userRows).toHaveLength(1);
    expect(userRows[0]!.passwordHash).toMatch(/^\$argon2id\$/);

    expect(mailer.sent).toHaveLength(1);
    expect(mailer.sent[0]!.kind).toBe("verify");
    expect(mailer.sent[0]!.to).toBe(email);
  });

  it("Register existing email: still one user row, 'duplicate' mail sent, HTTP body identical to new-email response", async () => {
    const email = "bob@example.com";
    const password = "validPassword123!";

    const csrf1 = await csrfFrom(agent, "/register");
    const res1 = await agent.post("/register").send({
      email,
      password,
      _csrf: csrf1,
    });
    expect(res1.status).toBe(200);

    const csrf2 = await csrfFrom(agent, "/register");
    const res2 = await agent.post("/register").send({
      email,
      password,
      _csrf: csrf2,
    });
    expect(res2.status).toBe(200);

    // HTTP body identical to the new-email response
    expect(res2.text).toBe(res1.text);

    // Still one user row
    const userRows = await db
      .select()
      .from(users)
      .where(eq(users.emailNormalized, "bob@example.com"));
    expect(userRows).toHaveLength(1);

    // "duplicate" mail sent
    expect(mailer.sent).toHaveLength(2);
    expect(mailer.sent[1]!.kind).toBe("duplicate");
    expect(mailer.sent[1]!.to).toBe(email);
  });

  it("Register without CSRF field: returns 403", async () => {
    const res = await agent.post("/register").send({
      email: "nocsrf@example.com",
      password: "validPassword123!",
    });
    expect(res.status).toBe(403);
  });

  it("Register with weak password (11 chars): 400, no user created", async () => {
    const email = "weakpw@example.com";
    const csrf = await csrfFrom(agent, "/register");

    const res = await agent.post("/register").send({
      email,
      password: "shortpass11", // 11 characters
      _csrf: csrf,
    });
    expect(res.status).toBe(400);

    const userRows = await db
      .select()
      .from(users)
      .where(eq(users.emailNormalized, "weakpw@example.com"));
    expect(userRows).toHaveLength(0);
  });

  it("authenticate: wrong password, unknown email, disabled user all throw InvalidCredentialsError", async () => {
    const email = "authtest@example.com";
    const password = "validPassword123!";
    const ctx = { ip: "127.0.0.1" };

    const csrf = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email, password, _csrf: csrf });

    // Wrong password
    await expect(authenticate(email, "incorrectPassword123!", ctx)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );

    // Unknown email
    await expect(authenticate("unknown@example.com", password, ctx)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );

    // Disabled user
    const user = await userService.findByEmail(email);
    expect(user).not.toBeNull();
    await userService.disable(user!.id);

    await expect(authenticate(email, password, ctx)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
  });

  it("authenticate: correct password, unverified throws EmailNotVerifiedError; after verifyEmail returns the user", async () => {
    const email = "unverified@example.com";
    const password = "validPassword123!";
    const ctx = { ip: "127.0.0.1" };

    const csrf = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email, password, _csrf: csrf });

    // Throws EmailNotVerifiedError
    await expect(authenticate(email, password, ctx)).rejects.toBeInstanceOf(EmailNotVerifiedError);

    // After verifyEmail returns the user
    const token = mailer.tokenOf("verify");
    const verified = await verifyEmail(token, ctx);
    expect(verified).toBe(true);

    const authenticatedUser = await authenticate(email, password, ctx);
    expect(authenticatedUser).toBeDefined();
    expect(authenticatedUser.email).toBe(email);
    expect(authenticatedUser.emailVerifiedAt).not.toBeNull();
  });

  it("verifyEmail: token works once; second use returns false; expired token returns false; reset token is rejected for verification", async () => {
    const email = "tokenverify@example.com";
    const password = "validPassword123!";
    const ctx = { ip: "127.0.0.1" };

    const csrf = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email, password, _csrf: csrf });
    const token = mailer.tokenOf("verify");

    // Token works once
    expect(await verifyEmail(token, ctx)).toBe(true);

    // Second use returns false
    expect(await verifyEmail(token, ctx)).toBe(false);

    // Expired token (set expires_at to the past in SQL) returns false
    const email2 = "tokenexpired@example.com";
    const csrf2 = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email: email2, password, _csrf: csrf2 });
    const token2 = mailer.tokenOf("verify");

    await db.execute(
      sql`UPDATE email_tokens SET expires_at = now() - interval '1 hour' WHERE token_hash = ${sha256Hex(token2)}`,
    );
    expect(await verifyEmail(token2, ctx)).toBe(false);

    // A reset token is rejected for verification
    const user = await userService.findByEmail(email);
    await requestPasswordReset(user!.email, ctx);
    const resetToken = mailer.tokenOf("reset");

    expect(await verifyEmail(resetToken, ctx)).toBe(false);
  });

  it("Reset flow: unknown email sends no mail but returns same page; valid token changes password; old fails, new works; token second use fails; newer request invalidates older link", async () => {
    const email = "resetflow@example.com";
    const oldPassword = "initialPassword123!";
    const ctx = { ip: "127.0.0.1" };

    // Register and verify user
    const csrfReg = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email, password: oldPassword, _csrf: csrfReg });
    await verifyEmail(mailer.tokenOf("verify"), ctx);

    // Unknown email sends no mail but returns the same page
    const mailCountBefore = mailer.sent.length;
    const csrfForgot1 = await csrfFrom(agent, "/forgot-password");
    const resUnknown = await agent
      .post("/forgot-password")
      .send({ email: "unknown@example.com", _csrf: csrfForgot1 });

    expect(mailer.sent.length).toBe(mailCountBefore);

    const csrfForgot2 = await csrfFrom(agent, "/forgot-password");
    const resKnown = await agent.post("/forgot-password").send({ email, _csrf: csrfForgot2 });

    expect(resUnknown.text).toBe(resKnown.text);

    // A newer request invalidates the older link
    const firstResetToken = mailer.tokenOf("reset");
    const csrfForgot3 = await csrfFrom(agent, "/forgot-password");
    await agent.post("/forgot-password").send({ email, _csrf: csrfForgot3 });
    const secondResetToken = mailer.tokenOf("reset");
    expect(secondResetToken).not.toBe(firstResetToken);

    // Using older link fails (invalidated by newer request)
    expect(await resetPassword(firstResetToken, "newPassword12345!", ctx)).toBe(false);

    // Valid token changes the password
    const newPassword = "newPassword12345!";
    const csrfResetValid = await csrfFrom(
      agent,
      `/reset-password?token=${encodeURIComponent(secondResetToken)}`,
    );
    const resValid = await agent.post("/reset-password").send({
      token: secondResetToken,
      password: newPassword,
      _csrf: csrfResetValid,
    });
    expect(resValid.status).toBe(200);

    // Old password fails, new works
    await expect(authenticate(email, oldPassword, ctx)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );
    const authenticated = await authenticate(email, newPassword, ctx);
    expect(authenticated).toBeDefined();
    expect(authenticated.email).toBe(email);

    // Token second use fails
    const csrfResetAgain = await csrfFrom(
      agent,
      `/reset-password?token=${encodeURIComponent(secondResetToken)}`,
    );
    const resSecondUse = await agent.post("/reset-password").send({
      token: secondResetToken,
      password: "anotherPassword123!",
      _csrf: csrfResetAgain,
    });
    expect(resSecondUse.status).toBe(400);
    expect(await resetPassword(secondResetToken, "anotherPassword123!", ctx)).toBe(false);
  });

  it("GET /verify-email?token=...: does not consume the token (a later POST still succeeds)", async () => {
    const email = "getverify@example.com";
    const password = "validPassword123!";

    const csrf = await csrfFrom(agent, "/register");
    await agent.post("/register").send({ email, password, _csrf: csrf });
    const token = mailer.tokenOf("verify");

    // GET /verify-email?token=... does not consume token
    const getRes = await agent.get(`/verify-email?token=${encodeURIComponent(token)}`);
    expect(getRes.status).toBe(200);
    expect(getRes.text).toContain("Confirm email");

    // A later POST still succeeds
    const csrfPost = await csrfFrom(agent, `/verify-email?token=${encodeURIComponent(token)}`);
    const postRes = await agent.post("/verify-email").send({
      token,
      _csrf: csrfPost,
    });
    expect(postRes.status).toBe(200);
    expect(postRes.text).toContain("Email confirmed");
  });

  it("Rate limit: createApp({ limits: { registerIp: 2 } }): third POST returns 429", async () => {
    const limitedApp = createApp({ limits: { registerIp: 2 } });
    const limitedAgent = request.agent(limitedApp);

    const csrf1 = await csrfFrom(limitedAgent, "/register");
    const res1 = await limitedAgent.post("/register").send({
      email: "rl1@example.com",
      password: "validPassword123!",
      _csrf: csrf1,
    });
    expect(res1.status).toBe(200);

    const csrf2 = await csrfFrom(limitedAgent, "/register");
    const res2 = await limitedAgent.post("/register").send({
      email: "rl2@example.com",
      password: "validPassword123!",
      _csrf: csrf2,
    });
    expect(res2.status).toBe(200);

    const csrf3 = await csrfFrom(limitedAgent, "/register");
    const res3 = await limitedAgent.post("/register").send({
      email: "rl3@example.com",
      password: "validPassword123!",
      _csrf: csrf3,
    });
    expect(res3.status).toBe(429);
  });

  it("Audit: login.failed row exists after a failed login and its metadata contains no password", async () => {
    const email = "auditfailure@example.com";
    const attemptedSecret = "superSecretPasswordThatMustNotLeak123!";
    const ctx = { ip: "192.168.1.100", userAgent: "test-client" };

    await expect(authenticate(email, attemptedSecret, ctx)).rejects.toBeInstanceOf(
      InvalidCredentialsError,
    );

    const rows = await db
      .select()
      .from(auditEvents)
      .where(eq(auditEvents.eventType, "login.failed"));

    expect(rows.length).toBeGreaterThan(0);
    const lastEvent = rows[rows.length - 1]!;
    expect(lastEvent.ip).toBe("192.168.1.100");

    const metadataStr = JSON.stringify(lastEvent.metadata);
    expect(metadataStr).not.toContain(attemptedSecret);
    expect(metadataStr).not.toContain("password");
  });
});
