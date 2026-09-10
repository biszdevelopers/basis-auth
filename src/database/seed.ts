import { promisify } from "node:util";
import { randomBytes, scrypt as scryptCallback, timingSafeEqual } from "node:crypto";
import { eq } from "drizzle-orm";
import type { ClientSeed, PermissionDefinition, ResourceSeed } from "../config.js";
import type { Database } from "./client.js";
import { oidcClients, resourceServers } from "./schema.js";

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
  permissions: PermissionDefinition[];
}

export async function seedConfiguration(
  db: Database,
  clients: ClientSeed[],
  resources: ResourceSeed[],
): Promise<void> {
  for (const resource of resources) {
    await db
      .insert(resourceServers)
      .values({ audience: resource.audience, scopes: resource.scopes })
      .onConflictDoUpdate({
        target: resourceServers.audience,
        set: { scopes: resource.scopes, updatedAt: new Date() },
      });
  }

  for (const client of clients) {
    const metadata: StoredClientMetadata = {
      name: client.name ?? client.clientId,
      owners: [{ id: defaultClientOwnerId, role: "role.ADMIN" }],
      redirectUris: client.redirectUris,
      public: client.public,
      scopes: client.scopes,
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
  }
}
