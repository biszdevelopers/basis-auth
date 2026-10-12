CREATE TABLE "default_permissions" (
	"permission" text PRIMARY KEY NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
INSERT INTO "default_permissions" ("permission") VALUES ('participant');
--> statement-breakpoint
DELETE FROM "user_permissions" WHERE "permission" = 'participant';
