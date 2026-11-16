import { eq } from "drizzle-orm";
import { backchannelLogoutUriSchema } from "../config.js";
import type { Database } from "../database/client.js";
import { resourceServers } from "../database/schema.js";
import type { KeyService } from "./keys.js";

export async function postBackchannel(uri: string, body: URLSearchParams) {
  try {
    const response = await fetch(uri, {
      method: "POST",
      body,
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    await response.body?.cancel();
    return response.status === 200 || response.status === 204;
  } catch {
    return false;
  }
}

export function createLogoutService(db: Database, keys: Pick<KeyService, "issueLogoutToken">) {
  return async function executeLogout(userId: string, audience: string) {
    const [resource] = await db.select({ uris: resourceServers.backchannelLogoutUris })
      .from(resourceServers)
      .where(eq(resourceServers.audience, audience))
      .limit(1);
    if (!resource) return "unknown_resource";
    const uris = resource.uris.filter((uri) => backchannelLogoutUriSchema.safeParse(uri).success);
    if (!uris.length) return "logout_not_configured";

    const logoutToken = await keys.issueLogoutToken(userId, audience);
    const body = new URLSearchParams({ logout_token: logoutToken });
    const results = await Promise.all(uris.map((uri) => postBackchannel(uri, body)));
    return results.some(Boolean) ? "delivered" : "logout_delivery_failed";
  };
}
