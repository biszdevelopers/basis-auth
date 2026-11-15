import "dotenv/config";
import { eq } from "drizzle-orm";
import { createDatabase } from "../src/database/client.js";
import { resourceServers } from "../src/database/schema.js";
import { generateSecret, hashClientSecret } from "../src/database/seed.js";

const [audience, ...extra] = process.argv.slice(2);
if (!audience || extra.length) throw new Error("Usage: bun run resources:rotate-secret <audience>");
const databaseUrl = process.env.DATABASE_URL;
if (!databaseUrl) throw new Error("DATABASE_URL is required");

const { db, pool } = createDatabase(databaseUrl);
try {
  const secret = generateSecret();
  const [resource] = await db.update(resourceServers)
    .set({ secretHash: await hashClientSecret(secret), updatedAt: new Date() })
    .where(eq(resourceServers.audience, audience))
    .returning({ audience: resourceServers.audience });
  if (!resource) throw new Error("Resource not found");
  process.stdout.write(`${secret}\n`);
} finally {
  await pool.end();
}
