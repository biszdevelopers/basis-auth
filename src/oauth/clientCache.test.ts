import { describe, expect, it, vi } from "vitest";
import { createClientCache, type ClientCache } from "./clientCache.js";
import type { OAuthClient } from "./service.js";

function makeClient(clientId: string, redirectUris: string[], filterContent: string[] = []): OAuthClient {
  return {
    clientId,
    secretHash: null,
    resources: [],
    requireConsent: false,
    filterMode: null,
    filterContent,
    metadata: {
      name: clientId,
      owners: [{ id: "owner", role: "role.ADMIN" }],
      redirectUris,
    public: false,
    scopes: ["openid"],
    permissions: [],
    },
  };
}

describe("createClientCache", () => {
  it("loads through the loader on a miss and caches on subsequent hits", async () => {
    const load = vi.fn(async (id: string) => makeClient(id, ["https://a/cb"]));
    const cache: ClientCache = createClientCache(load, { ttlMs: 1000 });
    const first = await cache.get("c1");
    const second = await cache.get("c1");
    expect(first).toBe(second);
    expect(load).toHaveBeenCalledTimes(1);
    expect(first?.redirectUriSet.has("https://a/cb")).toBe(true);
  });

  it("returns undefined when the loader finds no client", async () => {
    const cache = createClientCache(async () => undefined, { ttlMs: 1000 });
    expect(await cache.get("missing")).toBeUndefined();
  });

  it("builds a filter-content set for O(1) membership", async () => {
    const cache = createClientCache(async () => makeClient("c", [], ["a@x.io", "b@x.io"]), { ttlMs: 1000 });
    const client = await cache.get("c");
    expect(client?.filterContentSet.has("a@x.io")).toBe(true);
    expect(client?.filterContentSet.has("z@x.io")).toBe(false);
  });

  it("reloads after the TTL expires", async () => {
    const load = vi.fn(async () => makeClient("c", ["https://a/cb"]));
    const cache = createClientCache(load, { ttlMs: 1 });
    await cache.get("c");
    await new Promise((resolve) => setTimeout(resolve, 5));
    await cache.get("c");
    expect(load).toHaveBeenCalledTimes(2);
  });

  it("evicts the least recently used entry when over capacity", async () => {
    const load = vi.fn(async (id: string) => makeClient(id, ["https://a/cb"]));
    const cache = createClientCache(load, { max: 1, ttlMs: 1000 });
    await cache.get("c1");
    await cache.get("c2");
    await cache.get("c1");
    expect(load).toHaveBeenCalledTimes(3);
  });

  it("applies default cache options when omitted", async () => {
    const cache = createClientCache(async (id) => makeClient(id, ["https://a/cb"]));
    const client = await cache.get("c");
    expect(client?.redirectUriSet.has("https://a/cb")).toBe(true);
  });

  it("propagates loader errors without caching", async () => {
    const load = vi.fn(async () => {
      throw new Error("db down");
    });
    const cache = createClientCache(load, { ttlMs: 1000 });
    await expect(cache.get("c1")).rejects.toThrow("db down");
    await expect(cache.get("c1")).rejects.toThrow("db down");
    expect(load).toHaveBeenCalledTimes(2);
  });
});

describe("createClientCache — doubled battery", () => {
  it("builds sets for clients with several redirect URIs", async () => {
    const cache = createClientCache(async () => makeClient("c", ["https://a/cb", "https://b/cb"]), { ttlMs: 1000 });
    const client = await cache.get("c");
    expect(client?.redirectUriSet.size).toBe(2);
    expect(client?.redirectUriSet.has("https://b/cb")).toBe(true);
  });

  it("produces an empty filter set when no filter content is configured", async () => {
    const cache = createClientCache(async () => makeClient("c", ["https://a/cb"], []), { ttlMs: 1000 });
    const client = await cache.get("c");
    expect(client?.filterContentSet.size).toBe(0);
  });

  it("returns the same cached instance across repeated lookups", async () => {
    const load = vi.fn(async (id: string) => makeClient(id, ["https://a/cb"]));
    const cache = createClientCache(load, { ttlMs: 1000 });
    const a = await cache.get("c");
    const b = await cache.get("c");
    const c = await cache.get("c");
    expect(a).toBe(b);
    expect(b).toBe(c);
    expect(load).toHaveBeenCalledTimes(1);
  });

  it("reloads after a transient loader failure recovers", async () => {
    let calls = 0;
    const load = vi.fn(async (id: string) => {
      calls += 1;
      if (calls === 1) throw new Error("transient");
      return makeClient(id, ["https://a/cb"]);
    });
    const cache = createClientCache(load, { ttlMs: 1000 });
    await expect(cache.get("c")).rejects.toThrow("transient");
    const client = await cache.get("c");
    expect(client?.clientId).toBe("c");
  });

  it("evicts the oldest entry when capacity is exceeded", async () => {
    const load = vi.fn(async (id: string) => makeClient(id, ["https://a/cb"]));
    const cache = createClientCache(load, { max: 2, ttlMs: 1000 });
    await cache.get("c1");
    await cache.get("c2");
    await cache.get("c3");
    await cache.get("c1");
    expect(load).toHaveBeenCalledTimes(4);
  });

  it("preserves client metadata on the cached object", async () => {
    const cache = createClientCache(async () => makeClient("c", ["https://a/cb"]), { ttlMs: 1000 });
    const client = await cache.get("c");
    expect(client?.metadata.name).toBe("c");
    expect(client?.secretHash).toBeNull();
  });
});
