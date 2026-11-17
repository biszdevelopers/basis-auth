CREATE TABLE "resource_server_scopes" (
	"audience" text NOT NULL,
	"scope" text NOT NULL,
	"upstream_scope" text,
	CONSTRAINT "resource_server_scopes_audience_scope_pk" PRIMARY KEY("audience","scope")
);
--> statement-breakpoint
ALTER TABLE "resource_server_scopes" ADD CONSTRAINT "resource_server_scopes_audience_resource_servers_audience_fk" FOREIGN KEY ("audience") REFERENCES "public"."resource_servers"("audience") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
INSERT INTO "resource_server_scopes" ("audience", "scope")
SELECT DISTINCT resource."audience", legacy."scope"
FROM "resource_servers" AS resource
CROSS JOIN LATERAL jsonb_array_elements_text(resource."scopes") AS legacy("scope");
--> statement-breakpoint
ALTER TABLE "resource_servers" DROP COLUMN "scopes";
