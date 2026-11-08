import "dotenv/config";
import { eq } from "drizzle-orm";
import { createDatabase } from "../src/database/client.js";
import { oidcClients } from "../src/database/schema.js";
import { databaseIdentity, type DatabaseIdentity } from "../src/serverIdentity.js";

function databaseLabel(identity: DatabaseIdentity | null | undefined): string {
  return identity
    ? `${identity.host}:${identity.port}/${identity.database ?? "unknown"}`
    : "unknown";
}

async function main() {
  const clientId = process.argv[2]?.trim();
  if (!clientId) {
    console.error("Usage: bun run clients:doctor <clientId> [serverUrl...]");
    process.exitCode = 2;
    return;
  }

  const serverUrls = (process.argv.slice(3).filter(Boolean).length
    ? process.argv.slice(3)
    : [process.env.OIDC_ISSUER ?? "http://localhost:3000"])
    .map((url) => url.replace(/\/+$/, ""));
  const localDatabase = databaseIdentity(process.env.DATABASE_URL);
  process.stdout.write(`Local database: ${databaseLabel(localDatabase)}\n`);

  let localClient: { updatedAt: Date } | undefined;
  if (process.env.DATABASE_URL) {
    const { db, pool } = createDatabase(process.env.DATABASE_URL);
    try {
      [localClient] = await db
        .select({ updatedAt: oidcClients.updatedAt })
        .from(oidcClients)
        .where(eq(oidcClients.clientId, clientId))
        .limit(1);
    } finally {
      await pool.end();
    }
  }
  process.stdout.write(
    `Local client: ${localClient ? `present since ${localClient.updatedAt.toISOString()}` : "missing"}\n`,
  );

  for (const serverUrl of serverUrls) {
    let serverStartedAt: string | undefined;
    try {
      const healthResponse = await fetch(`${serverUrl}/health`, {
        headers: { accept: "application/json" },
        signal: AbortSignal.timeout(10_000),
      });
      const health = await healthResponse.json() as {
        version?: string;
        commit?: string | null;
        startedAt?: string;
        environment?: string;
        pid?: number;
        database?: DatabaseIdentity | null;
      };
      if (health.version === undefined) {
        process.stderr.write(
          `WARNING: ${serverUrl} does not expose build identity; it is running an older build.\n`,
        );
      }
      process.stdout.write(
        `Server ${serverUrl}: ${healthResponse.status} ` +
        `version=${health.version ?? "unknown"} commit=${health.commit ?? "unknown"} ` +
        `startedAt=${health.startedAt ?? "unknown"} environment=${health.environment ?? "unknown"} ` +
        `pid=${health.pid ?? "unknown"}\n`,
      );
      process.stdout.write(`Server database: ${databaseLabel(health.database)}\n`);
      serverStartedAt = health.startedAt;
      if (
        localDatabase && health.database &&
        databaseLabel(localDatabase) !== databaseLabel(health.database)
      ) {
        process.stderr.write(
          "WARNING: the local database does not match the running server database.\n",
        );
      }
    } catch (error) {
      process.stderr.write(
        `Server ${serverUrl} did not answer /health: ${error instanceof Error ? error.message : "unknown error"}\n`,
      );
      process.exitCode = 1;
    }

    try {
      const clientResponse = await fetch(
        `${serverUrl}/oauth/clients/${encodeURIComponent(clientId)}`,
        {
          headers: { accept: "application/json" },
          signal: AbortSignal.timeout(10_000),
        },
      );
      process.stdout.write(`Client ${clientId} on ${serverUrl}: ${clientResponse.status}\n`);
      process.stdout.write(`${await clientResponse.text()}\n`);
      if (!clientResponse.ok) {
        process.exitCode = 1;
        if (
          localClient &&
          serverStartedAt &&
          localClient.updatedAt.toISOString() > serverStartedAt
        ) {
          process.stderr.write(
            "WARNING: the local client was written after the server started; the server may be stale.\n",
          );
        }
      }
    } catch (error) {
      process.stderr.write(
        `Could not check client ${clientId} on ${serverUrl}: ${error instanceof Error ? error.message : "unknown error"}\n`,
      );
      process.exitCode = 1;
    }
  }
}

await main();
