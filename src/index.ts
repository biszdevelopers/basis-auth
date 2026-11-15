import "dotenv/config";
import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { loadConfig } from "./config.js";
import { createDatabase } from "./database/client.js";
import { createEmailDomainService } from "./database/emailDomains.js";
import { migrateDatabase } from "./database/migrate.js";
import { seedConfiguration } from "./database/seed.js";
import { createIdentityService } from "./identity.js";
import { createMicrosoftService } from "./microsoft.js";
import { createKeyService } from "./oauth/keys.js";
import { createLogoutService } from "./oauth/logout.js";
import { createOAuthService } from "./oauth/service.js";
import { createSessionService } from "./oauth/sessions.js";
import { createInternalUserService } from "./internal/users.js";
import { createInternalApp } from "./internal/app.js";
import { createResourceVerifier } from "./internal/resource-auth.js";
import { createInternalApplicationService, InternalApplicationError } from "./internal/applications.js";
import { serverIdentity } from "./serverIdentity.js";

const config = await loadConfig();
const startupIdentity = serverIdentity(config.environment, config.databaseUrl);
const database = startupIdentity.database
  ? `${startupIdentity.database.host}:${startupIdentity.database.port}/${startupIdentity.database.database ?? "unknown"}`
  : "unknown";
console.log(
  `basis-auth ${startupIdentity.version} (${startupIdentity.commit ?? "commit unknown"}) database ${database} pid ${startupIdentity.pid} started ${startupIdentity.startedAt}`,
);
await migrateDatabase(config.databaseUrl);
const { db, pool } = createDatabase(config.databaseUrl);
await seedConfiguration(db, config.clients, config.resources, {
  clientId: config.managementPortalClientId,
  resourceRootUserId: process.env.BASIS_RESOURCE_ROOT_USER_ID || undefined,
});
const emailDomains = createEmailDomainService(db);
const identity = createIdentityService(
  db,
  emailDomains,
  config.bootstrapPermissionGrants,
);
const keys = await createKeyService(config, identity, db);
const sessions = createSessionService(db);
const oauth = createOAuthService(config, db, keys, identity);
const microsoft = createMicrosoftService(config, db, identity);
const internalUsers = createInternalUserService(db, emailDomains);
const internalApplications = createInternalApplicationService(db, config.issuer, oauth.invalidateClient);
const app = createApp(config, oauth, keys, sessions, identity, microsoft);
const internalApp = createInternalApp({
  verifyResource: createResourceVerifier(db),
  userWriteResources: config.internalUserWriteResources,
}, internalUsers, {
  applications: internalApplications,
  keys,
  clientId: config.managementPortalClientId,
  audience: config.managementPortalAudience,
  scope: config.managementPortalScope,
  sessions: oauth,
}, createLogoutService(db, keys));

const server = serve({ fetch: app.fetch, port: config.port }, () => {
  console.log(`basis-auth listening on port ${config.port} for ${config.issuer} (pid ${process.pid})`);
  if (config.environment === "development") {
    console.log(`OIDC demo: ${config.issuer}/dev/demo`);
  }
});
const internalServer = serve(
  { fetch: internalApp.fetch, hostname: config.internalApiHost, port: config.internalApiPort },
  () => {
    console.log(`basis-auth internal API listening on http://${config.internalApiHost}:${config.internalApiPort} (pid ${process.pid})`);
    void reconcileConfiguredLogoutUris();
  },
);

let revocationFlush: Promise<void> | undefined;
function flushRevocations() {
  revocationFlush ??= oauth.flushAccessTokenRevocations()
    .catch(() => console.warn("Could not process pending access token revocations"))
    .finally(() => { revocationFlush = undefined; });
}
const revocationTimer = setInterval(flushRevocations, 5000).unref();
flushRevocations();

async function reconcileConfiguredLogoutUris() {
  for (const resource of config.resources) {
    if (!resource.backchannelLogoutUri) continue;
    try {
      await internalApplications.reconcileConfiguredLogoutUri(resource.audience, resource.backchannelLogoutUri);
    } catch (error) {
      const reason = error instanceof InternalApplicationError ? error.message : "Verification could not be completed";
      console.warn("Configured logout webhook was not saved", resource.audience, reason);
    }
  }
}

async function shutdown(signal: string) {
  console.log(`Received ${signal}; shutting down`);
  clearInterval(revocationTimer);
  await Promise.all([
    new Promise<void>((resolve) => server.close(() => resolve())),
    new Promise<void>((resolve) => internalServer.close(() => resolve())),
  ]);
  await revocationFlush;
  await pool.end();
  process.exit(0);
}

process.on("SIGINT", () => void shutdown("SIGINT"));
process.on("SIGTERM", () => void shutdown("SIGTERM"));
