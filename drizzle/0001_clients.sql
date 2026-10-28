CREATE TYPE "public"."oauth_client_auth_method" AS ENUM('none', 'client_secret_basic', 'client_secret_post');--> statement-breakpoint
CREATE TYPE "public"."oauth_client_status" AS ENUM('active', 'disabled');--> statement-breakpoint
CREATE TYPE "public"."oauth_client_type" AS ENUM('public', 'confidential');--> statement-breakpoint
CREATE TYPE "public"."oauth_client_uri_kind" AS ENUM('redirect', 'post_logout');--> statement-breakpoint
CREATE TABLE "oauth_client_secrets" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_ref" uuid NOT NULL,
	"secret_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "oauth_client_uris" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_ref" uuid NOT NULL,
	"kind" "oauth_client_uri_kind" NOT NULL,
	"uri" text NOT NULL,
	"origin" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "oauth_clients" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"client_id" text NOT NULL,
	"name" text NOT NULL,
	"type" "oauth_client_type" NOT NULL,
	"status" "oauth_client_status" DEFAULT 'active' NOT NULL,
	"token_endpoint_auth_method" "oauth_client_auth_method" NOT NULL,
	"grant_types" text[] NOT NULL,
	"allowed_scopes" text[] NOT NULL,
	"require_pkce" boolean DEFAULT true NOT NULL,
	"require_consent" boolean DEFAULT true NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "oauth_clients_client_id_unique" UNIQUE("client_id"),
	CONSTRAINT "oauth_clients_auth_method_matches_type" CHECK (("oauth_clients"."type" = 'public' AND "oauth_clients"."token_endpoint_auth_method" = 'none')
OR ("oauth_clients"."type" = 'confidential' AND "oauth_clients"."token_endpoint_auth_method" <>
'none')),
	CONSTRAINT "oauth_clients_public_requires_pkce" CHECK ("oauth_clients"."type" <> 'public' OR
"oauth_clients"."require_pkce")
);
--> statement-breakpoint
ALTER TABLE "oauth_client_secrets" ADD CONSTRAINT "oauth_client_secrets_client_ref_oauth_clients_id_fk" FOREIGN KEY ("client_ref") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oauth_client_uris" ADD CONSTRAINT "oauth_client_uris_client_ref_oauth_clients_id_fk" FOREIGN KEY ("client_ref") REFERENCES "public"."oauth_clients"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "oauth_client_secrets_client_idx" ON "oauth_client_secrets" USING btree ("client_ref");--> statement-breakpoint
CREATE UNIQUE INDEX "oauth_client_uris_unique" ON "oauth_client_uris" USING btree ("client_ref","kind","uri");--> statement-breakpoint
CREATE INDEX "oauth_client_uris_origin_idx" ON "oauth_client_uris" USING btree ("origin");