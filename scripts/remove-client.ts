import "dotenv/config";
import { z } from "zod";
import { deleteClientById, requireDatabase, runRemoveFlow } from "./clients.js";

const { db, pool } = requireDatabase();

try {
  const rawClientId = process.argv[2];
  if (!rawClientId) {
    await runRemoveFlow(db);
  } else {
    const clientId = z.uuid().parse(rawClientId);
    process.stdout.write(`${await deleteClientById(db, clientId)}\n`);
  }
} finally {
  await pool.end();
}
