import request from "supertest";
import { describe, expect, it } from "vitest";
import { createApp } from "../../apps/server/src/app.js";

const issuer = process.env.AUTHARIS_ISSUER!;

describe("OpenID Connect discovery", () => {
  it("publishes required metadata that matches implemented endpoints", async () => {
    const app = createApp();
    const response = await request(app).get("/.well-known/openid-configuration");
    expect(response.status).toBe(200);
    expect(response.type).toBe("application/json");
    expect(response.headers["access-control-allow-origin"]).toBe("*");
    expect(response.headers["cache-control"]).toContain("max-age=3600");

    const document = response.body;
    for (const field of [
      "issuer",
      "authorization_endpoint",
      "token_endpoint",
      "jwks_uri",
      "response_types_supported",
      "subject_types_supported",
      "id_token_signing_alg_values_supported",
    ]) {
      expect(document).toHaveProperty(field);
    }
    expect(document.issuer).toBe(issuer);
    expect(document.issuer).not.toMatch(/\/$/);
    for (const key of Object.keys(document).filter((name) => name.endsWith("_endpoint"))) {
      expect(document[key].startsWith(issuer)).toBe(true);
    }
    expect(document.jwks_uri.startsWith(issuer)).toBe(true);
    expect(document.id_token_signing_alg_values_supported).toEqual(["RS256"]);
    expect(document.request_uri_parameter_supported).toBe(false);
    expect(document.code_challenge_methods_supported).toEqual(["S256"]);
    expect(document.grant_types_supported).toEqual(["authorization_code"]);
    expect(document.scopes_supported).toEqual(["openid", "profile", "email"]);

    for (const key of Object.keys(document).filter((name) => name.endsWith("_endpoint"))) {
      const url = new URL(document[key]);
      const result =
        key === "token_endpoint"
          ? await request(app).post(url.pathname).type("form").send({})
          : await request(app).get(url.pathname);
      expect(result.status).not.toBe(404);
    }
    const jwks = await request(app).get(new URL(document.jwks_uri).pathname);
    expect(jwks.status).toBe(200);
    expect(jwks.body).toEqual({ keys: [] });
  });
});
