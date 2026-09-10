ALTER TABLE "users" ADD COLUMN "student_id" text;--> statement-breakpoint
ALTER TABLE "users" ADD COLUMN "school_district" text;--> statement-breakpoint
UPDATE "users"
SET "email_verified" = lower(split_part("email", '@', 2)) IN ('basischina.com', 'basis-global.com');
