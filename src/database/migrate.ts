import "dotenv/config";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate } from "drizzle-orm/node-postgres/migrator";
import { createDatabase } from "./client.js";

export async function migrateDatabase(databaseUrl: string) {
  const { pool } = createDatabase(databaseUrl);
  try {
    const client = await pool.connect();
    try {
      await client.query("select set_config('basis.management_portal_client_id', $1, false), set_config('basis.resource_root_user_id', $2, false)", [
        process.env.MANAGEMENT_PORTAL_CLIENT_ID ?? "",
        process.env.BASIS_RESOURCE_ROOT_USER_ID ?? "",
      ]);
      await migrate(drizzle({ client }), { migrationsFolder: "drizzle" });
    } finally {
      client.release();
    }
  } finally {
    await pool.end();
  }
}

import { pathToFileURL } from "node:url";

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const databaseUrl = process.env.DATABASE_URL;
  if (!databaseUrl) throw new Error("DATABASE_URL is required");
  await migrateDatabase(databaseUrl);
}
