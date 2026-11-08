import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { clientIp, rateLimit, RateLimiter } from "./rateLimit.js";

describe("RateLimiter", () => {
  it("allows requests up to the maximum within a window", () => {
    let now = 1000;
    const limiter = new RateLimiter({ windowMs: 1000, max: 3, now: () => now });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
  });

  it("isolates counters per key", () => {
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => 1000 });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
    expect(limiter.allow("b")).toBe(true);
  });

  it("resets the window after it expires", () => {
    let now = 1000;
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => now });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
    now = 2001;
    expect(limiter.allow("a")).toBe(true);
  });

  it("reports the remaining seconds in the window", () => {
    let now = 1000;
    const limiter = new RateLimiter({ windowMs: 10_000, max: 1, now: () => now });
    expect(limiter.retryAfter("missing")).toBe(0);
    limiter.allow("a");
    expect(limiter.retryAfter("a")).toBe(10);
    now = 2000;
    expect(limiter.retryAfter("a")).toBe(9);
  });
});

describe("rateLimit middleware", () => {
  function buildApp(limiter: RateLimiter) {
    const app = new Hono();
    app.use("*", rateLimit(limiter, () => "key"));
    app.get("/", (c) => c.text("ok"));
    return app;
  }

  it("passes the request through when under the limit", async () => {
    const app = buildApp(new RateLimiter({ windowMs: 1000, max: 5, now: () => 1000 }));
    const res = await app.request("/");
    expect(res.status).toBe(200);
    expect(await res.text()).toBe("ok");
  });

  it("rejects with 429 and Retry-After when over the limit", async () => {
    const app = buildApp(new RateLimiter({ windowMs: 1000, max: 2, now: () => 1000 }));
    expect((await app.request("/")).status).toBe(200);
    expect((await app.request("/")).status).toBe(200);
    const rejected = await app.request("/");
    expect(rejected.status).toBe(429);
    expect(rejected.headers.get("retry-after")).toBeTypeOf("string");
    expect(await rejected.json()).toMatchObject({ error: "too_many_requests" });
  });
});

describe("RateLimiter defaults", () => {
  it("applies built-in limits when constructed without options", () => {
    const limiter = new RateLimiter();
    expect(limiter.allow("k")).toBe(true);
    expect(limiter.retryAfter("missing")).toBe(0);
  });
});

describe("clientIp", () => {
  function ctxWith(headers: Record<string, string>) {
    return { req: { header: (name: string) => headers[name] ?? null } } as unknown as Parameters<typeof clientIp>[0];
  }

  it("prefers the first X-Forwarded-For address from a trusted proxy", () => {
    expect(clientIp(ctxWith({ "x-forwarded-for": "1.2.3.4, 5.6.7.8" }), "127.0.0.1")).toBe("1.2.3.4");
  });

  it("falls back to X-Real-IP from a trusted proxy", () => {
    expect(clientIp(ctxWith({ "x-real-ip": "9.9.9.9" }), "10.0.0.2")).toBe("9.9.9.9");
  });

  it("ignores forwarded headers from an untrusted client", () => {
    expect(clientIp(
      ctxWith({ "x-forwarded-for": "1.2.3.4", "x-real-ip": "5.6.7.8" }),
      "203.0.113.5",
    )).toBe("203.0.113.5");
  });

  it("falls back to unknown when no address is available", () => {
    expect(clientIp(ctxWith({}))).toBe("unknown");
  });
});

describe("RateLimiter — doubled battery", () => {
  it("allows exactly up to the maximum and blocks the next", () => {
    const limiter = new RateLimiter({ windowMs: 1000, max: 2, now: () => 1000 });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
  });

  it("blocks at the exact window boundary when resetAt equals now", () => {
    let now = 1000;
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => now });
    expect(limiter.allow("a")).toBe(true);
    now = 2000;
    expect(limiter.allow("a")).toBe(true);
    now = 2000;
    expect(limiter.allow("a")).toBe(false);
  });

  it("keeps independent counters for several keys", () => {
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => 1000 });
    for (const key of ["a", "b", "c"]) expect(limiter.allow(key)).toBe(true);
    for (const key of ["a", "b", "c"]) expect(limiter.allow(key)).toBe(false);
  });

  it("reports a decreasing retry-after as the window elapses", () => {
    let now = 1000;
    const limiter = new RateLimiter({ windowMs: 30_000, max: 1, now: () => now });
    limiter.allow("a");
    expect(limiter.retryAfter("a")).toBe(30);
    now = 10_000;
    expect(limiter.retryAfter("a")).toBe(21);
    now = 30_000;
    expect(limiter.retryAfter("a")).toBe(1);
  });

  it("returns zero retry-after for a key with no active window", () => {
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => 1000 });
    expect(limiter.retryAfter("never-seen")).toBe(0);
  });

  it("re-arms the window after expiry for a fresh burst", () => {
    let now = 0;
    const limiter = new RateLimiter({ windowMs: 100, max: 1, now: () => now });
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
    now = 101;
    expect(limiter.allow("a")).toBe(true);
    expect(limiter.allow("a")).toBe(false);
  });
});

describe("rateLimit middleware — doubled battery", () => {
  it("uses a custom key function to separate clients", async () => {
    const app = new Hono();
    const limiter = new RateLimiter({ windowMs: 1000, max: 1, now: () => 1000 });
    app.use("*", rateLimit(limiter, (c) => c.req.header("x-tenant") ?? "default"));
    app.get("/", (c) => c.text("ok"));
    const ok = await app.request("/", { headers: { "x-tenant": "t1" } });
    const blocked = await app.request("/", { headers: { "x-tenant": "t1" } });
    const other = await app.request("/", { headers: { "x-tenant": "t2" } });
    expect(ok.status).toBe(200);
    expect(blocked.status).toBe(429);
    expect(other.status).toBe(200);
  });

  it("returns a Retry-After header on rejection", async () => {
    const app = new Hono();
    const limiter = new RateLimiter({ windowMs: 5000, max: 1, now: () => 1000 });
    app.use("*", rateLimit(limiter, () => "k"));
    app.get("/", (c) => c.text("ok"));
    await app.request("/");
    const res = await app.request("/");
    expect(res.headers.get("retry-after")).toBe("5");
  });
});

describe("clientIp — doubled battery", () => {
  function ctxWith(headers: Record<string, string>) {
    return { req: { header: (name: string) => headers[name] ?? null } } as unknown as Parameters<typeof clientIp>[0];
  }

  it("trims whitespace from the forwarded address", () => {
    expect(clientIp(ctxWith({ "x-forwarded-for": "  10.0.0.1 , 10.0.0.2" }), "127.0.0.1")).toBe("10.0.0.1");
  });

  it("prefers X-Forwarded-For over X-Real-IP", () => {
    expect(clientIp(
      ctxWith({ "x-forwarded-for": "1.1.1.1", "x-real-ip": "2.2.2.2" }),
      "::1",
    )).toBe("1.1.1.1");
  });

  it("uses the trusted proxy address when both headers are absent", () => {
    expect(clientIp(ctxWith({ "x-real-ip": "" }), "127.0.0.1")).toBe("127.0.0.1");
  });

  it("treats private IPv6 addresses as trusted proxies", () => {
    expect(clientIp(ctxWith({ "x-forwarded-for": "1.1.1.1" }), "fd00::1")).toBe("1.1.1.1");
  });
});
