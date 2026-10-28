import { beforeEach, describe, expect, it } from "vitest";
import {
  EmailAlreadyRegisteredError,
  toSafeUser,
  userService,
} from "../../apps/server/src/modules/identity/user.service.js";
import { resetDatabase } from "../helpers/db.js";
beforeEach(resetDatabase);
describe("user service", () => {
  it("creates a user with a UUID id and normalized email", async () => {
    const user = await userService.create({ email: " Ada@Example.COM " });
    expect(user.id).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(user.email).toBe("Ada@Example.COM");
    expect(user.emailNormalized).toBe("ada@example.com");
  });
  it("rejects duplicates regardless of case or whitespace", async () => {
    await userService.create({ email: "ada@example.com" });
    await expect(userService.create({ email: " ADA@example.com " })).rejects.toBeInstanceOf(
      EmailAlreadyRegisteredError,
    );
  });
  it("treats plus-addressing as a different account", async () => {
    await userService.create({ email: "ada@example.com" });
    await expect(userService.create({ email: "ada+x@example.com" })).resolves.toBeDefined();
  });
  it("finds users case-insensitively", async () => {
    const user = await userService.create({ email: "ada@example.com" });
    expect((await userService.findByEmail("ADA@Example.com"))?.id).toBe(user.id);
    expect(await userService.findByEmail("nobody@example.com")).toBeNull();
  });
  it("disables and re-enables a user", async () => {
    const user = await userService.create({ email: "ada@example.com" });
    await userService.disable(user.id);
    expect((await userService.findById(user.id))?.status).toBe("disabled");
    await userService.enable(user.id);
    expect((await userService.findById(user.id))?.status).toBe("active");
  });
  it("never exposes the password hash through toSafeUser", async () => {
    const user = await userService.create({ email: "ada@example.com", passwordHash: "x" });
    expect(JSON.stringify(toSafeUser(user))).not.toContain("passwordHash");
  });
});
