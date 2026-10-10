CREATE TABLE "oidc_client_organizations" (
	"client_id" text NOT NULL,
	"organization_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "oidc_client_organizations_client_id_organization_id_pk" PRIMARY KEY("client_id","organization_id")
);
--> statement-breakpoint
ALTER TABLE "accepted_email_domains" RENAME TO "organizations";--> statement-breakpoint
ALTER TABLE "email_domain_suffixes" RENAME COLUMN "accepted_email_domain_id" TO "organization_id";--> statement-breakpoint
INSERT INTO "oidc_client_organizations" ("client_id", "organization_id")
SELECT "oidc_clients"."client_id", "organizations"."id"
FROM "oidc_clients"
CROSS JOIN "organizations"
WHERE "oidc_clients"."login_types" ? 'COMMON'
   OR ("organizations"."first_party" = true AND "oidc_clients"."login_types" ? 'FIRST_PARTY')
   OR ("organizations"."first_party" = false AND "oidc_clients"."login_types" ? 'THIRD_PARTY')
ON CONFLICT DO NOTHING;--> statement-breakpoint
ALTER TABLE "organizations" DROP CONSTRAINT "accepted_email_domains_organization_id_unique";--> statement-breakpoint
ALTER TABLE "oidc_clients" DROP CONSTRAINT "oidc_clients_login_types_check";--> statement-breakpoint
ALTER TABLE "email_domain_suffixes" DROP CONSTRAINT "email_domain_suffixes_accepted_email_domain_id_accepted_email_domains_id_fk";
--> statement-breakpoint
DROP INDEX "accepted_email_domains_one_first_party";--> statement-breakpoint
ALTER TABLE "oidc_client_organizations" ADD CONSTRAINT "oidc_client_organizations_client_id_oidc_clients_client_id_fk" FOREIGN KEY ("client_id") REFERENCES "public"."oidc_clients"("client_id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "oidc_client_organizations" ADD CONSTRAINT "oidc_client_organizations_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "email_domain_suffixes" ADD CONSTRAINT "email_domain_suffixes_organization_id_organizations_id_fk" FOREIGN KEY ("organization_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "organizations_one_first_party" ON "organizations" USING btree ("first_party") WHERE "organizations"."first_party" = true;--> statement-breakpoint
ALTER TABLE "oidc_clients" DROP COLUMN "login_types";--> statement-breakpoint
ALTER TABLE "organizations" ADD CONSTRAINT "organizations_organization_id_unique" UNIQUE("organization_id");
