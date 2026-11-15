import { eq } from "drizzle-orm";
import type { Database } from "../database/client.js";
import { resourceServers } from "../database/schema.js";
import { secretMatches } from "../database/seed.js";

export function createResourceVerifier(db: Database) {
  return async (audience: string, secret: string) => {
    const [resource] = await db.select({ secretHash: resourceServers.secretHash })
      .from(resourceServers).where(eq(resourceServers.audience, audience)).limit(1);
    return resource ? secretMatches(secret, resource.secretHash) : false;
  };
}
