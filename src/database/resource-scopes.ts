import { and, eq, getTableColumns, notInArray, sql } from "drizzle-orm";
import type { Database } from "./client.js";
import { resourceServers, resourceServerScopes } from "./schema.js";

// Keep resource and scope reads in the same database snapshot.
export const resourceScopeNames = sql<string[]>`(${sql`
  select coalesce(jsonb_agg(${resourceServerScopes.scope} order by ${resourceServerScopes.scope}), '[]'::jsonb)
  from ${resourceServerScopes}
  where ${resourceServerScopes.audience} = ${resourceServers.audience}
`})`;

export const resourceWithScopes = { ...getTableColumns(resourceServers), scopes: resourceScopeNames };

export const resourceWithScopeMappings = {
  ...resourceWithScopes,
  upstreamScopes: sql<Record<string, string | null>>`(${sql`
    select coalesce(jsonb_object_agg(${resourceServerScopes.scope}, ${resourceServerScopes.upstreamScope}), '{}'::jsonb)
    from ${resourceServerScopes}
    where ${resourceServerScopes.audience} = ${resourceServers.audience}
  `})`,
};

type Transaction = Parameters<Parameters<Database["transaction"]>[0]>[0];

// Call after inserting or locking the resource row in the same transaction.
export async function replaceResourceScopes(
  tx: Transaction,
  audience: string,
  scopes: string[],
  upstreamScopes: Record<string, string | null> = {},
) {
  const names = [...new Set(scopes)];
  await tx.delete(resourceServerScopes).where(and(
    eq(resourceServerScopes.audience, audience),
    names.length ? notInArray(resourceServerScopes.scope, names) : undefined,
  ));
  const unmapped = names.filter((scope) => !Object.hasOwn(upstreamScopes, scope));
  if (unmapped.length) {
    await tx.insert(resourceServerScopes).values(unmapped.map((scope) => ({ audience, scope })))
      .onConflictDoNothing();
  }
  const mappings = Object.entries(upstreamScopes).filter(([scope]) => names.includes(scope));
  if (mappings.length) {
    await tx.insert(resourceServerScopes)
      .values(mappings.map(([scope, upstreamScope]) => ({ audience, scope, upstreamScope })))
      .onConflictDoUpdate({
        target: [resourceServerScopes.audience, resourceServerScopes.scope],
        set: { upstreamScope: sql`excluded.upstream_scope` },
      });
  }
}
