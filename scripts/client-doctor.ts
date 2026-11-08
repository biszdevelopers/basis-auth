import "dotenv/config";
import { databaseIdentity, type DatabaseIdentity } from "../src/serverIdentity.js";

function databaseLabel(identity: DatabaseIdentity | null | undefined): string {
  return identity
    ? `${identity.host}:${identity.port}/${identity.database ?? "unknown"}`
    : "unknown";
}

async function main() {
  const clientId = process.argv[2]?.trim();
  if (!clientId) {
    console.error("Usage: bun run clients:doctor <clientId> [serverUrl]");
    process.exitCode = 2;
    return;
  }

  const serverUrl = (process.argv[3] ?? process.env.OIDC_ISSUER ?? "http://localhost:3000")
    .replace(/\/+$/, "");
  const localDatabase = databaseIdentity(process.env.DATABASE_URL);
  process.stdout.write(`Local database: ${databaseLabel(localDatabase)}\n`);

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
      database?: DatabaseIdentity | null;
    };
    process.stdout.write(
      `Server ${serverUrl}: ${healthResponse.status} ` +
      `version=${health.version ?? "unknown"} commit=${health.commit ?? "unknown"} ` +
      `startedAt=${health.startedAt ?? "unknown"} environment=${health.environment ?? "unknown"}\n`,
    );
    process.stdout.write(`Server database: ${databaseLabel(health.database)}\n`);
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
    process.stdout.write(`Client ${clientId}: ${clientResponse.status}\n`);
    process.stdout.write(`${await clientResponse.text()}\n`);
    if (!clientResponse.ok) process.exitCode = 1;
  } catch (error) {
    process.stderr.write(
      `Could not check client ${clientId}: ${error instanceof Error ? error.message : "unknown error"}\n`,
    );
    process.exitCode = 1;
  }
}

await main();
