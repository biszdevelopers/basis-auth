ALTER TABLE "resource_servers" ADD COLUMN IF NOT EXISTS "name" text;--> statement-breakpoint
UPDATE "resource_servers" SET "name" = "audience" WHERE "name" IS NULL;--> statement-breakpoint
ALTER TABLE "resource_servers" ALTER COLUMN "name" SET NOT NULL;
