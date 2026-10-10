ALTER TABLE "resource_servers" ADD COLUMN "name" text;
UPDATE "resource_servers" SET "name" = "audience" WHERE "name" IS NULL;
ALTER TABLE "resource_servers" ALTER COLUMN "name" SET NOT NULL;
