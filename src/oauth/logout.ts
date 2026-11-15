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
    const [resource] = await db.select({ uri: resourceServers.backchannelLogoutUri })
      .from(resourceServers)
      .where(eq(resourceServers.audience, audience))
      .limit(1);
    if (!resource) return "unknown_resource";
    if (resource.uri === null) return "logout_not_configured";
    const uri = backchannelLogoutUriSchema.safeParse(resource.uri);
    if (!uri.success) return "logout_delivery_failed";

    const logoutToken = await keys.issueLogoutToken(userId, audience);
    return await postBackchannel(uri.data, new URLSearchParams({ logout_token: logoutToken }))
      ? "delivered"
      : "logout_delivery_failed";
  };
}
