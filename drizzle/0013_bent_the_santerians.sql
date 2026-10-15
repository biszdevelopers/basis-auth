CREATE TABLE IF NOT EXISTS "default_permissions" (
	"permission" text PRIMARY KEY NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
INSERT INTO "default_permissions" ("permission") VALUES ('participant') ON CONFLICT ("permission") DO NOTHING;
--> statement-breakpoint
DELETE FROM "user_permissions" WHERE "permission" = 'participant';
