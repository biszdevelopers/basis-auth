ALTER TABLE "access_token_revocations" ADD COLUMN "delivered_uris" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "resource_servers" ADD COLUMN "backchannel_logout_uris" jsonb DEFAULT '[]'::jsonb NOT NULL;--> statement-breakpoint
UPDATE "resource_servers"
SET "backchannel_logout_uris" = jsonb_build_array("backchannel_logout_uri")
WHERE "backchannel_logout_uri" IS NOT NULL;