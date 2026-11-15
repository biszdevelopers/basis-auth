CREATE TABLE "backchannel_verifications" (
	"nonce" text PRIMARY KEY NOT NULL,
	"audience" text NOT NULL,
	"challenge" text NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"validated_at" timestamp with time zone
);
--> statement-breakpoint
ALTER TABLE "backchannel_verifications" ADD CONSTRAINT "backchannel_verifications_audience_resource_servers_audience_fk" FOREIGN KEY ("audience") REFERENCES "public"."resource_servers"("audience") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "backchannel_verifications_expires_at_idx" ON "backchannel_verifications" USING btree ("expires_at");