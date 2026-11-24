import { and, eq } from "drizzle-orm";
import type { RequestHandler } from "express";
import { db } from "../infrastructure/database/db.js";
import { oauthClientUris, oauthClients } from "../infrastructure/database/schema.js";

export const registeredOriginCors: RequestHandler = async (req, res, next) => {
  res.vary("Origin");
  const origin = req.get("origin");
  if (origin) {
    const [hit] = await db
      .select({ id: oauthClientUris.id })
      .from(oauthClientUris)
      .innerJoin(oauthClients, eq(oauthClients.id, oauthClientUris.clientRef))
      .where(
        and(
          eq(oauthClientUris.origin, origin),
          eq(oauthClientUris.kind, "redirect"),
          eq(oauthClients.status, "active"),
        ),
      )
      .limit(1);
    if (hit) res.setHeader("Access-Control-Allow-Origin", origin);
  }
  if (req.method === "OPTIONS") {
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "authorization, content-type");
    res.setHeader("Access-Control-Max-Age", "600");
    res.sendStatus(204);
    return;
  }
  next();
};
