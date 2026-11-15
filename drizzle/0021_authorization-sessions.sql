CREATE TABLE "authorization_sessions" (
	"id" uuid PRIMARY KEY NOT NULL,
	"client_id" text NOT NULL,
	"user_id" uuid NOT NULL,
	"scopes" jsonb NOT NULL,
	"resource" text NOT NULL,
	"authenticated_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"refresh_expires_at" timestamp with time zone,
	"revoked_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "refresh_tokens" RENAME COLUMN "family_id" TO "session_id";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP CONSTRAINT "refresh_tokens_client_id_oidc_clients_client_id_fk";
--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP CONSTRAINT "refresh_tokens_user_id_users_id_fk";
--> statement-breakpoint
DROP INDEX "refresh_tokens_family_id_idx";--> statement-breakpoint
DROP INDEX "refresh_tokens_expires_at_idx";--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_client_id_oidc_clients_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oidc_clients"("client_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD CONSTRAINT "authorization_sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "authorization_sessions_user_id_idx" ON "authorization_sessions" USING btree ("user_id");--> statement-breakpoint
CREATE INDEX "authorization_sessions_client_id_idx" ON "authorization_sessions" USING btree ("client_id");--> statement-breakpoint
INSERT INTO "authorization_sessions" ("id", "client_id", "user_id", "scopes", "resource", "created_at", "refresh_expires_at", "revoked_at")
SELECT DISTINCT ON ("session_id")
  "session_id", "client_id", "user_id", "scopes", "resource", "created_at", "expires_at",
  min("revoked_at") OVER (PARTITION BY "session_id")
FROM "refresh_tokens"
ORDER BY "session_id", "created_at", "token_hash";
--> statement-breakpoint
ALTER TABLE "refresh_tokens" ADD CONSTRAINT "refresh_tokens_session_id_authorization_sessions_id_fk" FOREIGN KEY ("session_id") REFERENCES "public"."authorization_sessions"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "refresh_tokens_session_id_idx" ON "refresh_tokens" USING btree ("session_id");--> statement-breakpoint
CREATE UNIQUE INDEX "refresh_tokens_current_session_idx" ON "refresh_tokens" USING btree ("session_id") WHERE "refresh_tokens"."consumed_at" is null;--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "client_id";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "user_id";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "scopes";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "resource";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "expires_at";--> statement-breakpoint
ALTER TABLE "refresh_tokens" DROP COLUMN "revoked_at";
