import "dotenv/config";
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDatabase } from "./database/client.js";
import { migrateDatabase } from "./database/migrate.js";
import { seedConfiguration } from "./database/seed.js";
import { createIdentityService } from "./identity.js";
import { createMicrosoftService } from "./microsoft.js";
import { createKeyService } from "./oauth/keys.js";
import { createOAuthService } from "./oauth/service.js";
import { createSessionService } from "./oauth/sessions.js";
import { createInternalUserService } from "./internal/users.js";
import { createInternalApp } from "./internal/app.js";

const config = await loadConfig();
await migrateDatabase(config.databaseUrl);
const { db, pool } = createDatabase(config.databaseUrl);
await seedConfiguration(db, config.clients, config.resources);
const identity = createIdentityService(
  db,
  config.defaultPermission,
  config.bootstrapPermissionGrants,
);
const keys = await createKeyService(config, identity);
const sessions = createSessionService(db);
const oauth = createOAuthService(config, db, keys, identity);
const microsoft = createMicrosoftService(config, db, identity);
const internalUsers = createInternalUserService(db);
const app = createApp(config, oauth, keys, sessions, identity, microsoft);
const internalApp = createInternalApp(config.internalApiToken, internalUsers);

const server = serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`basis-auth listening on ${config.issuer}`);
  if (config.environment === "development") {
    console.log(`OIDC demo: ${config.issuer}/dev/demo`);
  }
});
const internalServer = serve(
  { fetch: internalApp.fetch, hostname: config.internalApiHost, port: config.internalApiPort },
  () => console.log(`basis-auth internal API listening on http://${config.internalApiHost}:${config.internalApiPort}`),
);

async function shutdown(signal: string) {
  console.log(`Received ${signal}; shutting down`);
  await Promise.all([
    new Promise<void>((resolve) => server.close(() => resolve())),
    new Promise<void>((resolve) => internalServer.close(() => resolve())),
  ]);
  await pool.end();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
