import type { Request } from "express";
import { env } from "../../config/env.js";
import { db } from "../database/db.js";
import { auditEvents } from "../database/schema.js";
export interface AuditContext {
  ip?: string;
  userAgent?: string;
  actorUserId?: string;
}
export function requestContext(req: Request): AuditContext {
  return { ip: req.ip, userAgent: req.get("user-agent")?.slice(0, 255) };
}
const FORBIDDEN_KEY = /pass|secret|token|code|cookie|authorization|verifier/i;
export async function audit(
  eventType: string,
  ctx: AuditContext,
  data: { subjectType?: string; subjectId?: string; metadata?: Record<string, unknown> } = {},
): Promise<void> {
  const metadata = data.metadata ?? {};
  if (env.NODE_ENV !== "production") {
    for (const key of Object.keys(metadata)) {
      if (FORBIDDEN_KEY.test(key))
        throw new Error(`audit metadata key
"${key}" looks like a secret`);
    }
  }
  try {
    await db.insert(auditEvents).values({
      eventType,
      actorUserId: ctx.actorUserId,
      subjectType: data.subjectType,
      subjectId: data.subjectId,
      ip: ctx.ip,
      userAgent: ctx.userAgent,
      metadata,
    });
  } catch (err) {
    // Auditing is best effort: a logging failure must not take down sign-in.
    console.error("audit write failed", eventType, (err as Error).message);
  }
}
