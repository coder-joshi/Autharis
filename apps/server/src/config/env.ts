import "dotenv/config";
import { z } from "zod";

const envBool = (fallback: boolean) =>
  z
    .enum(["true", "false"])
    .default(fallback ? "true" : "false")
    .transform((v) => v === "true");

const envSchema = z.object({
  NODE_ENV: z.enum(["development", "test", "production"]).default("development"),

  PORT: z.coerce.number().int().min(1).max(65535).default(3000),

  DATABASE_URL: z.string().url(),
  DB_POOL_MAX: z.coerce.number().int().min(1).max(100).default(10),

  AUTHARIS_ISSUER: z
    .string()
    .url()
    .refine((v) => new URL(v).origin === v, "must be an origin with no path or trailing slash")
    .refine(
      (v) => process.env.NODE_ENV !== "production" || v.startsWith("https://"),
      "must use https in production",
    ),

  REQUIRE_EMAIL_VERIFICATION: envBool(true),
  TRUST_PROXY: z
    .string()
    .default("false")
    .refine((v) => v !== "true", "TRUST_PROXY=true trusts every client; use a hop count such as 1")
    .transform((v) => (v === "false" ? false : /^\d+$/.test(v) ? Number(v) : v)),
});

export const env = envSchema.parse(process.env);
