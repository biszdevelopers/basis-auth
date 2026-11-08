import { getConnInfo } from "@hono/node-server/conninfo";
import type { Context, MiddlewareHandler } from "hono";
import { LRUCache } from "lru-cache";

export interface RateLimitOptions {
  windowMs?: number;
  max?: number;
  now?: () => number;
}

interface Bucket {
  count: number;
  resetAt: number;
}

/**
 * Fixed-window in-memory rate limiter.
 *
 * Single-instance only: state lives in the process. For horizontally scaled
 * deployments this must be replaced with a shared store (e.g. Redis).
 */
export class RateLimiter {
  private readonly buckets: LRUCache<string, Bucket>;
  private readonly windowMs: number;
  private readonly max: number;
  private readonly now: () => number;

  constructor(options: RateLimitOptions = {}) {
    this.windowMs = options.windowMs ?? 60_000;
    this.max = options.max ?? 60;
    this.now = options.now ?? Date.now;
    this.buckets = new LRUCache<string, Bucket>({ max: 10_000, ttl: this.windowMs });
  }

  /** Returns true if the request is allowed, false if the limit is exceeded. */
  allow(key: string): boolean {
    const now = this.now();
    const bucket = this.buckets.get(key);
    if (!bucket || bucket.resetAt <= now) {
      this.buckets.set(key, { count: 1, resetAt: now + this.windowMs });
      return true;
    }
    bucket.count += 1;
    return bucket.count <= this.max;
  }

  /** Seconds remaining in the current window for a key (0 when no window is active). */
  retryAfter(key: string): number {
    const bucket = this.buckets.peek(key);
    if (!bucket) return 0;
    return Math.max(0, Math.ceil((bucket.resetAt - this.now()) / 1000));
  }
}

export function rateLimit(
  limiter: RateLimiter,
  keyFor: (c: Context) => string,
): MiddlewareHandler {
  return async (c, next) => {
    if (limiter.allow(keyFor(c))) {
      await next();
      return;
    }
    c.header("Retry-After", String(limiter.retryAfter(keyFor(c))));
    c.status(429);
    return c.json({ error: "too_many_requests", error_description: "Too many requests" });
  };
}

function isTrustedProxy(address: string | undefined): boolean {
  if (!address) return false;
  const value = address.replace(/^\[|\]$/g, "").toLowerCase();
  if (value === "::1" || value === "::ffff:127.0.0.1" || value.startsWith("127.")) return true;
  if (value.startsWith("10.") || value.startsWith("192.168.")) return true;
  const private172 = /^172\.(\d{1,3})\./.exec(value);
  if (private172) {
    const octet = Number(private172[1]);
    if (octet >= 16 && octet <= 31) return true;
  }
  return value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:");
}

export function clientIp(c: Context, remoteAddress?: string): string {
  let remote = remoteAddress;
  if (remote === undefined) {
    try {
      remote = getConnInfo(c).remote.address;
    } catch {
      remote = undefined;
    }
  }
  if (isTrustedProxy(remote)) {
    const forwarded = c.req.header("x-forwarded-for");
    if (forwarded && forwarded.trim()) return forwarded.split(",")[0]!.trim();
    const real = c.req.header("x-real-ip");
    if (real && real.trim()) return real.trim();
  }
  return remote || "unknown";
}
