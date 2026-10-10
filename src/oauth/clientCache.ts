import { LRUCache } from "lru-cache";
import type { OAuthClient } from "./service.js";

export interface CachedClient extends OAuthClient {
  redirectUriSet: Set<string>;
  filterContentSet: Set<string>;
}

export interface ClientCache {
  get(clientId: string): Promise<CachedClient | undefined>;
  invalidate(clientId: string): void;
}

export interface ClientCacheOptions {
  max?: number;
  ttlMs?: number;
}

/**
 * Load-through LRU cache for OIDC clients.
 *
 * Clients rarely change at runtime, so a short TTL (default 60s) bounds
 * staleness while removing repeated database round-trips from the hot path.
 * Membership lookups (`redirectUriSet`, `filterContentSet`) are pre-built
 * `Set`s so per-request `includes` scans become O(1).
 */
export function createClientCache(
  load: (clientId: string) => Promise<OAuthClient | undefined>,
  options: ClientCacheOptions = {},
): ClientCache {
  const cache = new LRUCache<string, CachedClient>({
    max: options.max ?? 200,
    ttl: options.ttlMs ?? 60_000,
  });

  return {
    async get(clientId: string): Promise<CachedClient | undefined> {
      const hit = cache.get(clientId);
      if (hit) return hit;
      const client = await load(clientId);
      if (!client) return undefined;
      const cached: CachedClient = {
        ...client,
        redirectUriSet: new Set(client.metadata.redirectUris),
        filterContentSet: new Set(client.filterContent),
      };
      cache.set(clientId, cached);
      return cached;
    },
    invalidate(clientId: string) {
      cache.delete(clientId);
    },
  };
}
