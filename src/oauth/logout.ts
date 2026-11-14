import { eq } from "drizzle-orm";
import { backchannelLogoutUriSchema } from "../config.js";
import type { Database } from "../database/client.js";
import { resourceServers } from "../database/schema.js";
import type { KeyService } from "./keys.js";

export function createLogoutService(db: Database, keys: Pick<KeyService, "issueLogoutToken">) {
  return async function executeLogout(userId: string, audience: string) {
    const [resource] = await db.select({ uri: resourceServers.backchannelLogoutUri })
      .from(resourceServers)
      .where(eq(resourceServers.audience, audience))
      .limit(1);
    if (!resource) return "unknown_resource";
    if (resource.uri === null) return "logout_not_configured";
    const uri = backchannelLogoutUriSchema.safeParse(resource.uri);
    if (!uri.success) return "logout_delivery_failed";

    const logoutToken = await keys.issueLogoutToken(userId, audience);
    try {
      const response = await fetch(uri.data, {
        method: "POST",
        body: new URLSearchParams({ logout_token: logoutToken }),
        redirect: "error",
        signal: AbortSignal.timeout(5000),
      });
      await response.body?.cancel();
      if (response.status === 200 || response.status === 204) return "delivered";
    } catch {
      return "logout_delivery_failed";
    }
    return "logout_delivery_failed";
  };
}
