import "dotenv/config";
import { deleteClientById, requireDatabase, runRemoveFlow } from "./clients.js";

const { db, pool } = requireDatabase();

try {
  const rawClientId = process.argv[2];
  if (!rawClientId) {
    await runRemoveFlow(db);
  } else {
    const clientId = rawClientId.trim();
    if (!clientId) throw new Error("Client ID must not be empty");
    process.stdout.write(`${await deleteClientById(db, clientId)}\n`);
  }
} finally {
  await pool.end();
}
