import { Router } from "express";
import { buildDiscoveryDocument } from "./discovery.service.js";

export function createOidcRouter(): Router {
  const router = Router();
  router.get("/.well-known/openid-configuration", (_req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json(buildDiscoveryDocument());
  });
  // Discovery requires jwks_uri. Step 14 replaces this empty set with the active key set.
  router.get("/jwks", (_req, res) => {
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Cache-Control", "public, max-age=3600");
    res.json({ keys: [] });
  });
  return router;
}
