import { and, eq, isNull, lte, sql } from "drizzle-orm";
import { backchannelLogoutUriSchema } from "../config.js";
import type { Database } from "../database/client.js";
import { accessTokenRevocations, resourceServers } from "../database/schema.js";
import type { KeyService } from "./keys.js";
import { postBackchannel } from "./logout.js";

const DELIVERY_RETRY_MS = 15_000;
const EXPIRATION_RETENTION_MS = 5 * 60 * 1000;

export async function recordAccessTokenRevocation(
  db: Pick<Database, "insert">,
  input: { jti: string; audience: string; expiresAt: Date | null },
  graceSeconds: number,
) {
  const nowSeconds = Math.floor(Date.now() / 1000);
  await db.insert(accessTokenRevocations).values({
    ...input,
    validAfter: new Date((nowSeconds + graceSeconds) * 1000),
    nextAttemptAt: new Date(nowSeconds * 1000),
  }).onConflictDoUpdate({
    target: accessTokenRevocations.jti,
    set: {
      validAfter: sql`excluded.valid_after`,
      nextAttemptAt: sql`excluded.next_attempt_at`,
      deliveredAt: null,
    },
    where: sql`excluded.valid_after < ${accessTokenRevocations.validAfter}`,
  });
}

export async function isAccessTokenRevoked(db: Pick<Database, "select">, jti: string) {
  const [entry] = await db.select({ jti: accessTokenRevocations.jti }).from(accessTokenRevocations)
    .where(and(eq(accessTokenRevocations.jti, jti), lte(accessTokenRevocations.validAfter, new Date())));
  return Boolean(entry);
}

export function createAccessTokenRevocationDelivery(db: Database, keys: Pick<KeyService, "issueAccessTokenRevocation">) {
  async function deliver(jti: string) {
    try {
      const now = new Date();
      const [event] = await db.update(accessTokenRevocations)
        .set({ nextAttemptAt: new Date(now.getTime() + DELIVERY_RETRY_MS) })
        .where(and(
          eq(accessTokenRevocations.jti, jti),
          isNull(accessTokenRevocations.deliveredAt),
          lte(accessTokenRevocations.nextAttemptAt, now),
        )).returning();
      if (!event) return;

      const [resource] = await db.select({ uris: resourceServers.backchannelLogoutUris }).from(resourceServers)
        .where(eq(resourceServers.audience, event.audience));
      const uris = (resource?.uris ?? []).filter((uri) => backchannelLogoutUriSchema.safeParse(uri).success);
      if (!uris.length) return;
      const pending = uris.filter((uri) => !event.deliveredUris.includes(uri));
      if (!pending.length) {
        await db.update(accessTokenRevocations).set({ deliveredAt: new Date() })
          .where(and(eq(accessTokenRevocations.jti, jti), eq(accessTokenRevocations.validAfter, event.validAfter)));
        return;
      }

      const validAfter = event.validAfter.getTime() / 1000;
      const expiresAt = event.expiresAt ? event.expiresAt.getTime() / 1000 : null;
      const token = await keys.issueAccessTokenRevocation({ audience: event.audience, jti, validAfter, expiresAt });
      const body = new URLSearchParams({
        action: "revoke_access_token",
        jti,
        valid_after: String(validAfter),
        revocation_token: token,
      });
      const results = await Promise.all(pending.map((uri) => postBackchannel(uri, body)));
      const deliveredUris = [...new Set([
        ...event.deliveredUris,
        ...pending.filter((_, index) => results[index]),
      ])];
      const allDelivered = uris.every((uri) => deliveredUris.includes(uri));
      await db.update(accessTokenRevocations).set({
        deliveredUris,
        ...(allDelivered ? { deliveredAt: new Date() } : {}),
      }).where(and(
        eq(accessTokenRevocations.jti, jti),
        eq(accessTokenRevocations.validAfter, event.validAfter),
      ));
    } catch (error) {
      // The event is persisted and can be retried by the delivery worker.
      console.warn("Access token revocation delivery failed", error instanceof Error ? error.name : "unknown error");
    }
  }

  async function flush() {
    await db.delete(accessTokenRevocations)
      .where(lte(accessTokenRevocations.expiresAt, new Date(Date.now() - EXPIRATION_RETENTION_MS)));
    const pending = await db.select({ jti: accessTokenRevocations.jti }).from(accessTokenRevocations)
      .where(and(isNull(accessTokenRevocations.deliveredAt), lte(accessTokenRevocations.nextAttemptAt, new Date())))
      .orderBy(accessTokenRevocations.nextAttemptAt).limit(10);
    await Promise.all(pending.map(({ jti }) => deliver(jti)));
  }

  return { deliver, flush };
}
