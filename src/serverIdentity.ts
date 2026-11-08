import { readFileSync } from "node:fs";

const startedAt = new Date().toISOString();

function packageVersion(): string {
  try {
    const packageJson = JSON.parse(
      readFileSync(new URL("../package.json", import.meta.url), "utf8"),
    ) as { version?: unknown };
    return typeof packageJson.version === "string" ? packageJson.version : "unknown";
  } catch {
    return "unknown";
  }
}

const version = packageVersion();
const commit =
  process.env.BUILD_COMMIT ??
  process.env.GIT_COMMIT ??
  process.env.GITHUB_SHA ??
  process.env.VERCEL_GIT_COMMIT_SHA ??
  null;

export interface DatabaseIdentity {
  host: string;
  port: number;
  database: string | null;
}

export interface ServerIdentity {
  version: string;
  commit: string | null;
  startedAt: string;
  environment: string;
  database: DatabaseIdentity | null;
}

/** Strips credentials and query parameters from a PostgreSQL connection string. */
export function databaseIdentity(databaseUrl: string | undefined): DatabaseIdentity | null {
  if (!databaseUrl) return null;
  try {
    const url = new URL(databaseUrl);
    const database = url.pathname.replace(/^\//, "");
    return {
      host: url.hostname || "localhost",
      port: url.port ? Number(url.port) : 5432,
      database: database ? decodeURIComponent(database) : null,
    };
  } catch {
    return null;
  }
}

export function serverIdentity(environment: string, databaseUrl?: string): ServerIdentity {
  return {
    version,
    commit,
    startedAt,
    environment,
    database: databaseIdentity(databaseUrl),
  };
}
