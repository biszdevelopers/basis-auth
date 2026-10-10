import { promisify } from "node:util";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { eq, inArray } from "drizzle-orm";
import type { ClientSeed, PermissionDefinitions, ResourceSeed } from "../config.js";
import type { Database } from "./client.js";
import { oidcClientOrganizations, oidcClients, organizations, resourceServers } from "./schema.js";

const scrypt = promisify(scryptCallback);
const defaultClientOwnerId = "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5";

export interface ClientOwner {
  id: string;
  role: "role.ADMIN" | "role.GENERAL";
}

export async function hashClientSecret(secret: string): Promise<string> {
  const salt = randomBytes(16);
  const digest = (await scrypt(secret, salt, 64)) as Buffer;
  return `scrypt:${salt.toString("base64url")}:${digest.toString("base64url")}`;
}

export async function secretMatches(secret: string, encoded: string | null): Promise<boolean> {
  if (!encoded) return false;
  const [algorithm, saltValue, digestValue] = encoded.split(":");
  if (algorithm !== "scrypt" || !saltValue || !digestValue) return false;
  const expected = Buffer.from(digestValue, "base64url");
  const actual = (await scrypt(secret, Buffer.from(saltValue, "base64url"), expected.length)) as Buffer;
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

export interface StoredClientMetadata extends Record<string, unknown> {
  name: string;
  owners: ClientOwner[];
  redirectUris: string[];
  public: boolean;
  scopes: string[];
  resourceScopes?: Record<string, string[]>;
  permissions: PermissionDefinitions;
}

export async function seedConfiguration(
  db: Database,
  clients: ClientSeed[],
  resources: ResourceSeed[],
): Promise<void> {
  for (const resource of resources) {
    await db
      .insert(resourceServers)
      .values({ audience: resource.audience, name: resource.name ?? resource.audience, scopes: resource.scopes })
      .onConflictDoUpdate({
        target: resourceServers.audience,
        set: { name: resource.name ?? resource.audience, scopes: resource.scopes, updatedAt: new Date() },
      });
  }

  for (const client of clients) {
    const linkedOrganizations = await db
      .select({ id: organizations.id, organizationId: organizations.organizationId })
      .from(organizations)
      .where(inArray(organizations.organizationId, client.organizationIds));
    if (linkedOrganizations.length !== client.organizationIds.length) {
      const found = new Set(linkedOrganizations.map((organization) => organization.organizationId));
      const missing = client.organizationIds.filter((organizationId) => !found.has(organizationId));
      throw new Error(`Client ${client.clientId} references unknown organization(s): ${missing.join(", ")}`);
    }
    const metadata: StoredClientMetadata = {
      name: client.name ?? client.clientId,
      owners: [{ id: defaultClientOwnerId, role: "role.ADMIN" }],
      redirectUris: client.redirectUris,
      public: client.public,
      scopes: client.scopes,
      resourceScopes: client.resourceScopes ?? Object.fromEntries(
        client.resources.map((resource) => [resource, client.scopes]),
      ),
      permissions: client.permissions,
    };
    const [existing] = await db
      .select({ secretHash: oidcClients.secretHash })
      .from(oidcClients)
      .where(eq(oidcClients.clientId, client.clientId))
      .limit(1);
    const secretHash = client.clientSecret
      ? (await secretMatches(client.clientSecret, existing?.secretHash ?? null))
        ? existing!.secretHash
        : await hashClientSecret(client.clientSecret)
      : null;

    await db
      .insert(oidcClients)
      .values({
        clientId: client.clientId,
        metadata,
        secretHash,
        resources: client.resources,
        requireConsent: client.requireConsent,
        filterMode: client.filterMode,
        filterContent: client.filterContent,
      })
      .onConflictDoUpdate({
        target: oidcClients.clientId,
        set: {
          metadata,
          secretHash,
          resources: client.resources,
          requireConsent: client.requireConsent,
          filterMode: client.filterMode,
          filterContent: client.filterContent,
          updatedAt: new Date(),
        },
      });
    await db.delete(oidcClientOrganizations).where(eq(oidcClientOrganizations.clientId, client.clientId));
    await db.insert(oidcClientOrganizations).values(
      linkedOrganizations.map((organization) => ({
        clientId: client.clientId,
        organizationId: organization.id,
      })),
    );
  }
}
