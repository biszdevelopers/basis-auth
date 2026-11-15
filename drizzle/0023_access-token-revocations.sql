CREATE TABLE "access_token_revocations" (
	"jti" text PRIMARY KEY NOT NULL,
	"audience" text NOT NULL,
	"valid_after" timestamp with time zone NOT NULL,
	"expires_at" timestamp with time zone,
	"next_attempt_at" timestamp with time zone DEFAULT now() NOT NULL,
	"delivered_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "authorization_sessions" ADD COLUMN "access_token_expires_at" timestamp with time zone;--> statement-breakpoint
CREATE INDEX "access_token_revocations_pending_idx" ON "access_token_revocations" USING btree ("next_attempt_at") WHERE "access_token_revocations"."delivered_at" is null;--> statement-breakpoint
CREATE INDEX "access_token_revocations_expires_at_idx" ON "access_token_revocations" USING btree ("expires_at");