CREATE TABLE "accepted_email_domains" (
	"id" uuid PRIMARY KEY NOT NULL,
	"organization_id" uuid NOT NULL,
	"first_party" boolean DEFAULT false NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "accepted_email_domains_organization_id_unique" UNIQUE("organization_id")
);
--> statement-breakpoint
CREATE TABLE "email_domain_suffixes" (
	"id" uuid PRIMARY KEY NOT NULL,
	"suffix" text NOT NULL,
	"accepted_email_domain_id" uuid NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "email_domain_suffixes_suffix_unique" UNIQUE("suffix")
);
--> statement-breakpoint
ALTER TABLE "oidc_clients" ADD COLUMN "login_types" jsonb DEFAULT '["FIRST_PARTY"]'::jsonb NOT NULL;--> statement-breakpoint
ALTER TABLE "upstream_auth_requests" ADD COLUMN "microsoft_authority" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "email_suffix_id" uuid;--> statement-breakpoint
ALTER TABLE "email_domain_suffixes" ADD CONSTRAINT "email_domain_suffixes_accepted_email_domain_id_accepted_email_domains_id_fk" FOREIGN KEY ("accepted_email_domain_id") REFERENCES "public"."accepted_email_domains"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE UNIQUE INDEX "accepted_email_domains_one_first_party" ON "accepted_email_domains" USING btree ("first_party") WHERE "accepted_email_domains"."first_party" = true;--> statement-breakpoint
ALTER TABLE "users" ADD CONSTRAINT "users_email_suffix_id_email_domain_suffixes_id_fk" FOREIGN KEY ("email_suffix_id") REFERENCES "public"."email_domain_suffixes"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
INSERT INTO "accepted_email_domains" ("id", "organization_id", "first_party")
VALUES ('ca6a1bd8-7015-42ee-84ba-7ba67f2b0f73', 'cbc6e1e2-a6bb-4002-bbdc-6da892a051a7', true);--> statement-breakpoint
INSERT INTO "email_domain_suffixes" ("id", "suffix", "accepted_email_domain_id") VALUES
  ('f2a2ebb7-8bd0-4fb8-a874-fcac6d96fe7b', 'basis-global.com', 'ca6a1bd8-7015-42ee-84ba-7ba67f2b0f73'),
  ('99b01e42-6237-425f-8dfd-a33ec3471924', 'basischina.com', 'ca6a1bd8-7015-42ee-84ba-7ba67f2b0f73');--> statement-breakpoint
UPDATE "users"
SET "email_suffix_id" = CASE lower(split_part("email", '@', 2))
  WHEN 'basis-global.com' THEN 'f2a2ebb7-8bd0-4fb8-a874-fcac6d96fe7b'::uuid
  WHEN 'basischina.com' THEN '99b01e42-6237-425f-8dfd-a33ec3471924'::uuid
END
WHERE lower(split_part("email", '@', 2)) IN ('basis-global.com', 'basischina.com');--> statement-breakpoint
ALTER TABLE "users" DROP COLUMN "email_verified";--> statement-breakpoint
ALTER TABLE "oidc_clients" ADD CONSTRAINT "oidc_clients_login_types_check" CHECK (jsonb_typeof("oidc_clients"."login_types") = 'array'
        and jsonb_array_length("oidc_clients"."login_types") between 1 and 3
        and "oidc_clients"."login_types" <@ '["FIRST_PARTY", "THIRD_PARTY", "COMMON"]'::jsonb
        and (
          jsonb_array_length("oidc_clients"."login_types") = 1
          or (jsonb_array_length("oidc_clients"."login_types") = 2 and jsonb_path_match("oidc_clients"."login_types", '$[0] != $[1]'))
          or (jsonb_array_length("oidc_clients"."login_types") = 3 and jsonb_path_match("oidc_clients"."login_types", '$[0] != $[1] && $[0] != $[2] && $[1] != $[2]'))
        ));
