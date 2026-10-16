INSERT INTO "default_permissions" ("permission")
VALUES ('Assets.Assets.create')
ON CONFLICT ("permission") DO NOTHING;
