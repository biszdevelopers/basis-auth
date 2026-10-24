CREATE TABLE "oidc_permissions" (
	"client_id" text NOT NULL,
	"permission" text NOT NULL,
	"description" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "oidc_permissions_client_id_permission_pk" PRIMARY KEY("client_id","permission")
);
--> statement-breakpoint
INSERT INTO "oidc_permissions" ("client_id", "permission", "description")
SELECT client."client_id", definition.key, definition.value
FROM "oidc_clients" AS client
CROSS JOIN LATERAL jsonb_each_text(
	CASE WHEN jsonb_typeof(client."metadata"->'permissions') = 'object'
		THEN client."metadata"->'permissions' ELSE '{}'::jsonb END
) AS definition
ON CONFLICT ("client_id", "permission") DO NOTHING;
--> statement-breakpoint
UPDATE "oidc_clients"
SET "metadata" = "metadata" - 'permissions'
WHERE "metadata" ? 'permissions';
--> statement-breakpoint
DELETE FROM "user_permissions";
--> statement-breakpoint
DELETE FROM "default_permissions";
--> statement-breakpoint
ALTER TABLE "user_permissions" DROP CONSTRAINT IF EXISTS "user_permissions_user_id_permission_pk";
--> statement-breakpoint
ALTER TABLE "default_permissions" DROP CONSTRAINT IF EXISTS "default_permissions_pkey";
--> statement-breakpoint
ALTER TABLE "default_permissions" DROP CONSTRAINT IF EXISTS "default_permissions_permission_pk";
--> statement-breakpoint
ALTER TABLE "user_permissions" ADD COLUMN "application_id" text NOT NULL;
--> statement-breakpoint
ALTER TABLE "default_permissions" ADD COLUMN "application_id" text NOT NULL;
--> statement-breakpoint
ALTER TABLE "oidc_clients" ADD COLUMN "permission_catalog_version" integer DEFAULT 1 NOT NULL;
--> statement-breakpoint
ALTER TABLE "user_permissions" ADD CONSTRAINT "user_permissions_user_id_application_id_permission_pk" PRIMARY KEY("user_id","application_id","permission");
--> statement-breakpoint
ALTER TABLE "default_permissions" ADD CONSTRAINT "default_permissions_application_id_permission_pk" PRIMARY KEY("application_id","permission");
--> statement-breakpoint
ALTER TABLE "oidc_permissions" ADD CONSTRAINT "oidc_permissions_client_id_oidc_clients_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oidc_clients"("client_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "user_permissions" ADD CONSTRAINT "user_permissions_application_id_oidc_clients_client_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."oidc_clients"("client_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "default_permissions" ADD CONSTRAINT "default_permissions_catalog_fk" FOREIGN KEY ("application_id","permission") REFERENCES "public"."oidc_permissions"("client_id","permission") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE TABLE "user_applications" (
	"user_id" uuid NOT NULL,
	"application_id" text NOT NULL,
	"first_login_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "user_applications_user_id_application_id_pk" PRIMARY KEY("user_id","application_id")
);
--> statement-breakpoint
ALTER TABLE "user_applications" ADD CONSTRAINT "user_applications_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
ALTER TABLE "user_applications" ADD CONSTRAINT "user_applications_application_id_oidc_clients_client_id_fk" FOREIGN KEY ("application_id") REFERENCES "public"."oidc_clients"("client_id") ON DELETE cascade ON UPDATE no action;
--> statement-breakpoint
CREATE INDEX "user_applications_application_idx" ON "user_applications" USING btree ("application_id","user_id");
--> statement-breakpoint
CREATE INDEX "user_permissions_application_idx" ON "user_permissions" USING btree ("application_id","user_id");
