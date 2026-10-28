import {
  pgEnum,
  pgTable,
  text,
  timestamp,
  uuid,
  boolean,
  check,
  index,
  uniqueIndex,
} from "drizzle-orm/pg-core";
import { sql } from "drizzle-orm";

export const userStatus = pgEnum("user_status", ["active", "disabled"]);
export const userRole = pgEnum("user_role", ["user", "admin"]);

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  emailNormalized: text("email_normalized").notNull().unique(),
  emailVerifiedAt: timestamp("email_verified_at", {
    withTimezone: true,
  }),
  passwordHash: text("password_hash"),
  displayName: text("display_name"),
  status: userStatus("status").notNull().default("active"),
  role: userRole("role").notNull().default("user"),
  createdAt: timestamp("created_at", {
    withTimezone: true,
  })
    .notNull()
    .defaultNow(),
  updatedAt: timestamp("updated_at", {
    withTimezone: true,
  })
    .notNull()
    .defaultNow()
    .$onUpdate(() => new Date()),
});

export const clientType = pgEnum("oauth_client_type", ["public", "confidential"]);
export const clientStatus = pgEnum("oauth_client_status", ["active", "disabled"]);
export const clientAuthMethod = pgEnum("oauth_client_auth_method", [
  "none",
  "client_secret_basic",
  "client_secret_post",
]);
export const clientUriKind = pgEnum("oauth_client_uri_kind", ["redirect", "post_logout"]);
export const oauthClients = pgTable(
  "oauth_clients",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    clientId: text("client_id").notNull().unique(),
    name: text("name").notNull(),
    type: clientType("type").notNull(),
    status: clientStatus("status").notNull().default("active"),
    tokenEndpointAuthMethod: clientAuthMethod("token_endpoint_auth_method").notNull(),
    grantTypes: text("grant_types").array().notNull(),
    allowedScopes: text("allowed_scopes").array().notNull(),
    requirePkce: boolean("require_pkce").notNull().default(true),
    requireConsent: boolean("require_consent").notNull().default(true),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    updatedAt: timestamp("updated_at", { withTimezone: true })
      .notNull()
      .defaultNow()
      .$onUpdate(() => new Date()),
  },
  (t) => [
    check(
      "oauth_clients_auth_method_matches_type",
      sql`(${t.type} = 'public' AND ${t.tokenEndpointAuthMethod} = 'none')
OR (${t.type} = 'confidential' AND ${t.tokenEndpointAuthMethod} <>
'none')`,
    ),
    check(
      "oauth_clients_public_requires_pkce",
      sql`${t.type} <> 'public' OR
${t.requirePkce}`,
    ),
  ],
);

export const oauthClientUris = pgTable(
  "oauth_client_uris",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    clientRef: uuid("client_ref")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    kind: clientUriKind("kind").notNull(),
    uri: text("uri").notNull(),
    origin: text("origin").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
  },
  (t) => [
    uniqueIndex("oauth_client_uris_unique").on(t.clientRef, t.kind, t.uri),
    index("oauth_client_uris_origin_idx").on(t.origin),
  ],
);
export const oauthClientSecrets = pgTable(
  "oauth_client_secrets",
  {
    id: uuid("id").primaryKey().defaultRandom(),
    clientRef: uuid("client_ref")
      .notNull()
      .references(() => oauthClients.id, { onDelete: "cascade" }),
    secretHash: text("secret_hash").notNull(),
    createdAt: timestamp("created_at", { withTimezone: true }).notNull().defaultNow(),
    expiresAt: timestamp("expires_at", { withTimezone: true }),
    revokedAt: timestamp("revoked_at", { withTimezone: true }),
  },
  (t) => [index("oauth_client_secrets_client_idx").on(t.clientRef)],
);
