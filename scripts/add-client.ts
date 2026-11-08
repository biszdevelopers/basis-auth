import "dotenv/config";
import { clientInputSchema } from "../src/config.js";
import { generateClientSecret, requireDatabase, runAddFlow, saveClient } from "./clients.js";

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
    const resourceScopes = new Map(
      input.resources.map((resource) => [
        resource,
        input.resourceScopes?.[resource] ?? input.scopes,
      ]),
    );
    const client = await saveClient(db, input, resourceScopes);
    process.stdout.write(`${client.clientId}\n`);
    if (generatedSecret) {
      process.stdout.write(`Client secret (copy now, only a hash is stored): ${generatedSecret}\n`);
    }
  }
} finally {
  await pool.end();
}
