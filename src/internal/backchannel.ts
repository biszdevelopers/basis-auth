import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { setTimeout as delay } from "node:timers/promises";
import { and, eq, gt, isNull, lt, sql } from "drizzle-orm";
import type { Database } from "../database/client.js";
import { backchannelVerifications } from "../database/schema.js";

const lateCallbackWindowMs = 60_000;
const verificationTimeoutMs = 10_000;
const pollIntervalMs = 100;

export function createBackchannelVerifier(db: Database, timeoutMs = verificationTimeoutMs) {
  async function verifyDestination(audience: string, url: string) {
    const nonce = randomBytes(32).toString("base64url");
    const challenge = randomBytes(32).toString("base64url");
    const expiresAt = new Date(Date.now() + timeoutMs);
    await db.delete(backchannelVerifications)
      .where(lt(backchannelVerifications.expiresAt, new Date(Date.now() - lateCallbackWindowMs)));
    await db.insert(backchannelVerifications).values({ nonce, audience, challenge, expiresAt });

    const signal = AbortSignal.timeout(Math.max(1, expiresAt.getTime() - Date.now()));
    try {
      let response: Response;
      try {
        response = await fetch(url, {
          method: "POST",
          body: new URLSearchParams({ action: "test", nonce, challenge }),
          redirect: "error",
          signal,
        });
      } catch {
        return signal.aborted ? "timeout" : "rejected";
      }
      void response.body?.cancel().catch(() => undefined);
      if (response.status !== 202) return "rejected";

      while (true) {
        const [pending] = await db.select({ validatedAt: backchannelVerifications.validatedAt })
          .from(backchannelVerifications).where(eq(backchannelVerifications.nonce, nonce)).limit(1);
        if (!pending) return "rejected";
        if (pending.validatedAt) return "verified";
        const remaining = expiresAt.getTime() - Date.now();
        if (remaining <= 0) return "timeout";
        await delay(Math.min(pollIntervalMs, remaining));
      }
    } finally {
      // Retain only expired attempts long enough to answer a late callback.
      if (Date.now() < expiresAt.getTime()) {
        await db.delete(backchannelVerifications).where(eq(backchannelVerifications.nonce, nonce));
      }
    }
  }

  async function validate(audience: string, secret: string, nonce: string, challengeHash: string) {
    if (!/^[a-f\d]{64}$/i.test(challengeHash)) return "invalid";
    const match = and(eq(backchannelVerifications.nonce, nonce), eq(backchannelVerifications.audience, audience));
    const [pending] = await db.select().from(backchannelVerifications).where(match).limit(1);
    if (!pending || pending.validatedAt) return "invalid";
    if (pending.expiresAt.getTime() <= Date.now()) return "timeout";

    const expected = createHmac("sha256", secret).update(pending.challenge).digest();
    if (!timingSafeEqual(expected, Buffer.from(challengeHash, "hex"))) return "invalid";

    const [accepted] = await db.update(backchannelVerifications).set({ validatedAt: sql`clock_timestamp()` })
      .where(and(match, isNull(backchannelVerifications.validatedAt), gt(backchannelVerifications.expiresAt, sql`clock_timestamp()`)))
      .returning({ nonce: backchannelVerifications.nonce });
    if (accepted) return "verified";
    return pending.expiresAt.getTime() <= Date.now() ? "timeout" : "invalid";
  }

  return { verifyDestination, validate };
}
