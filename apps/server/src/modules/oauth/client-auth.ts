import type { Request } from "express";
import { clientService, type ClientWithUris } from "../clients/client.service.js";
import { OAuthError } from "./oauth.errors.js";

type Method = "none" | "client_secret_basic" | "client_secret_post";

/** Return one form parameter and reject repeated or non-string values. */
export function formValue(body: Record<string, unknown>, key: string): string | undefined {
  const value = body[key];
  if (value === undefined) return undefined;
  if (typeof value !== "string") {
    throw new OAuthError("invalid_request", `parameter ${key} must appear once`);
  }
  return value;
}

export async function authenticateClient(req: Request): Promise<ClientWithUris> {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const header = req.get("authorization");
  const usesBasic = header !== undefined && /^basic\s/i.test(header);
  const bodyId = formValue(body, "client_id");
  const bodySecret = formValue(body, "client_secret");
  const challenge: Record<string, string> = usesBasic
    ? { "WWW-Authenticate": 'Basic realm="autharis", charset="UTF-8"' }
    : {};
  const invalidClient = () =>
    new OAuthError("invalid_client", "client authentication failed", 401, challenge);

  let id: string | undefined;
  let secret: string | undefined;
  let method: Method;
  if (usesBasic) {
    if (bodySecret !== undefined) {
      throw new OAuthError("invalid_request", "use only one client authentication method");
    }
    let decoded: string;
    try {
      decoded = Buffer.from(header!.slice(6).trim(), "base64").toString("utf8");
    } catch {
      throw invalidClient();
    }
    const separator = decoded.indexOf(":");
    if (separator < 0) throw invalidClient();
    try {
      id = decodeURIComponent(decoded.slice(0, separator).replace(/\+/g, " "));
      secret = decodeURIComponent(decoded.slice(separator + 1).replace(/\+/g, " "));
    } catch {
      throw invalidClient();
    }
    if (bodyId !== undefined && bodyId !== id) {
      throw new OAuthError("invalid_request", "client_id does not match the Authorization header");
    }
    method = "client_secret_basic";
  } else if (bodySecret !== undefined) {
    id = bodyId;
    secret = bodySecret;
    method = "client_secret_post";
  } else {
    id = bodyId;
    method = "none";
  }

  if (!id) throw invalidClient();
  const client = await clientService.findActive(id);
  if (!client || client.tokenEndpointAuthMethod !== method) throw invalidClient();
  if (method !== "none" && !(await clientService.verifySecret(client.id, secret ?? ""))) {
    throw invalidClient();
  }
  return client;
}
