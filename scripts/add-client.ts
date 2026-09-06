import "dotenv/config";
import { clientInputSchema, type ClientSeed } from "../src/config.js";
import { seedConfiguration } from "../src/database/seed.js";
import { generateClientSecret, requireDatabase, runAddFlow } from "./clients.js";

const { db, pool } = requireDatabase();

try {
  const rawClient = process.argv[2];
  if (!rawClient) {
    await runAddFlow(db);
  } else {
    const parsed = JSON.parse(rawClient) as Record<string, unknown>;
    let generatedSecret: string | null = null;
    if (!parsed.public && !parsed.clientSecret) {
      generatedSecret = generateClientSecret();
      parsed.clientSecret = generatedSecret;
    }
    const input = clientInputSchema.parse(parsed);
    const client: ClientSeed = { ...input, clientId: crypto.randomUUID() };
    await seedConfiguration(db, [client], []);
    process.stdout.write(`${client.clientId}\n`);
    if (generatedSecret) {
      process.stdout.write(`Client secret (copy now, only a hash is stored): ${generatedSecret}\n`);
    }
  }
} finally {
  await pool.end();
}
