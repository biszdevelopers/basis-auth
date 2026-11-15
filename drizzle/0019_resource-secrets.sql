ALTER TABLE "resource_servers" ADD COLUMN "secret_hash" text;--> statement-breakpoint
-- Scrypt hash of the deployment bootstrap secret sk-1. New rows get independent secrets.
UPDATE "resource_servers"
SET "secret_hash" = 'scrypt:QVKYqX9NmjkoFbUQPnvCFQ:n1YzbC-n4aSwmrru5PNimc4UcGexLBVVGssdT3ivK7BljJs3dZUBQq6BMEPDT74ycM_7W_QCF6_bPFuN9YMvxg';--> statement-breakpoint
ALTER TABLE "resource_servers" ALTER COLUMN "secret_hash" SET NOT NULL;
