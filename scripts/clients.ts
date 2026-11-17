import "dotenv/config";
import { randomBytes } from "node:crypto";
import { stdin as input, stdout as output } from "node:process";
import { createInterface, type Interface } from "node:readline/promises";
import { and, eq, inArray, isNull, sql } from "drizzle-orm";
import {
  backchannelLogoutUriSchema,
  clientInputSchema,
  DEFAULT_ORGANIZATION_ID,
  isEphemeralLocalhostRedirectUri,
  permissionDefinitionsSchema,
  type ClientSeed,
  type PermissionDefinitions,
} from "../src/config.js";
import { createDatabase, type Database } from "../src/database/client.js";
import { replaceResourceScopes, resourceWithScopes } from "../src/database/resource-scopes.js";
import { createBackchannelVerifier } from "../src/internal/backchannel.js";
import {
  hashClientSecret,
  hashNewResourceSecret,
  seedConfiguration,
  syncPermissionCatalog,
  type ClientOwner,
  type StoredClientMetadata,
} from "../src/database/seed.js";
import {
  authorizationCodes,
  authorizationConsents,
  authorizationRequests,
  authorizationSessions,
  defaultPermissions,
  oidcClientOrganizations,
  oidcClients,
  oidcPermissions,
  organizations,
  resourceServers,
  userApplications,
  userPermissions,
  users,
} from "../src/database/schema.js";
import { databaseIdentity } from "../src/serverIdentity.js";

// ponytail: stdlib readline TUI; no prompt dependency.
// Runtime visibility (see src/oauth/service.ts, src/oauth/clientCache.ts):
// new clients register instantly (cache misses aren't cached), client edits
// land within the 60s client-cache TTL, and resource_servers rows are read
// live per authorize request — so writes here need no restart.

export function generateClientSecret(): string {
  return `sk-${randomBytes(32).toString("hex")}`;
}

export function splitList(value: string): string[] {
  return value
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean);
}

export function requireDatabase() {
  if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required");
  const identity = databaseIdentity(process.env.DATABASE_URL);
  if (identity) {
    process.stdout.write(
      `Database ${identity.host}:${identity.port}/${identity.database ?? "unknown"}\n`,
    );
  }
  return createDatabase(process.env.DATABASE_URL);
}

function requireTty(): void {
  if (!process.stdin.isTTY) {
    throw new Error("This command needs an interactive terminal; pass arguments instead (see README).");
  }
}

function parsePermissionDefinitions(value: string): PermissionDefinitions {
  if (!value) return {};
  try {
    return permissionDefinitionsSchema.parse(JSON.parse(value));
  } catch {
    throw new Error('Permission definitions must be a JSON object mapping permission names to descriptions');
  }
}

async function promptPermissionDefinitions(
  rl: Interface,
  initial: PermissionDefinitions,
): Promise<PermissionDefinitions> {
  for (;;) {
    try {
      return parsePermissionDefinitions(
        await ask(
          rl,
          "Permission definitions (JSON object mapping permission names to descriptions)",
          JSON.stringify(initial),
        ),
      );
    } catch (error) {
      process.stdout.write(`${error instanceof Error ? error.message : "Invalid permissions"}\n`);
    }
  }
}

async function promptDefaultPermissions(
  rl: Interface,
  permissions: PermissionDefinitions,
  initial: string[],
): Promise<string[]> {
  const defined = Object.keys(permissions);
  if (!defined.length) return [];
  for (;;) {
    const selected = parsePermissionSelection(await ask(
      rl,
      `Default permissions (comma-separated, available: ${defined.join(", ")}, "none" clears)`,
      initial.join(", "),
    ));
    const invalid = selected.filter((permission) => !defined.includes(permission));
    if (invalid.length) {
      process.stdout.write(`Not in the permission catalog: ${invalid.join(", ")}\n`);
      continue;
    }
    return selected;
  }
}

async function ask(rl: Interface, question: string, defaultValue = ""): Promise<string> {
  const answer = (await rl.question(defaultValue ? `${question} [${defaultValue}]: ` : `${question}: `)).trim();
  return answer || defaultValue;
}

async function askYesNo(rl: Interface, question: string, defaultYes: boolean): Promise<boolean> {
  const answer = (await ask(rl, `${question} (${defaultYes ? "Y/n" : "y/N"})`)).toLowerCase();
  if (!answer) return defaultYes;
  return answer.startsWith("y");
}

export type ListedClient = ClientDetail;

export async function listClients(db: Database): Promise<ListedClient[]> {
  const rows = await db.select().from(oidcClients);
  if (!rows.length) return [];
  const clientIds = rows.map((row) => row.clientId);
  const ownerIds = [...new Set(rows.flatMap((row) => {
    const metadata = row.metadata as Partial<StoredClientMetadata>;
    return (metadata.owners ?? []).map((owner) => owner.id);
  }))];
  const [definitions, defaults, ownerUsers, grantCounts, userCounts, sessionCounts, clientOrganizations] = await Promise.all([
    db
      .select({ clientId: oidcPermissions.clientId, permission: oidcPermissions.permission, description: oidcPermissions.description })
      .from(oidcPermissions)
      .where(inArray(oidcPermissions.clientId, clientIds)),
    db
      .select({ clientId: defaultPermissions.applicationId, permission: defaultPermissions.permission })
      .from(defaultPermissions)
      .where(inArray(defaultPermissions.applicationId, clientIds)),
    ownerIds.length
      ? db
          .select({ id: users.id, email: users.email, displayName: users.displayName })
          .from(users)
          .where(inArray(users.id, ownerIds))
      : Promise.resolve([] as { id: string; email: string; displayName: string | null }[]),
    db
      .select({ clientId: userPermissions.applicationId, count: sql<number>`count(*)::int` })
      .from(userPermissions)
      .where(inArray(userPermissions.applicationId, clientIds))
      .groupBy(userPermissions.applicationId),
    db
      .select({ clientId: userApplications.applicationId, count: sql<number>`count(*)::int` })
      .from(userApplications)
      .where(inArray(userApplications.applicationId, clientIds))
      .groupBy(userApplications.applicationId),
    db
      .select({ clientId: authorizationSessions.clientId, count: sql<number>`count(*)::int` })
      .from(authorizationSessions)
      .where(and(
        inArray(authorizationSessions.clientId, clientIds),
        isNull(authorizationSessions.revokedAt),
      ))
      .groupBy(authorizationSessions.clientId),
    db
      .select({ clientId: oidcClientOrganizations.clientId, organizationId: organizations.organizationId })
      .from(oidcClientOrganizations)
      .innerJoin(organizations, eq(oidcClientOrganizations.organizationId, organizations.id))
      .where(inArray(oidcClientOrganizations.clientId, clientIds)),
  ]);

  const definitionsByClient = new Map<string, PermissionDefinitions>();
  for (const definition of definitions) {
    const catalog = definitionsByClient.get(definition.clientId) ?? {};
    catalog[definition.permission] = definition.description;
    definitionsByClient.set(definition.clientId, catalog);
  }
  const defaultsByClient = new Map<string, string[]>();
  for (const definition of defaults) {
    const list = defaultsByClient.get(definition.clientId) ?? [];
    list.push(definition.permission);
    defaultsByClient.set(definition.clientId, list);
  }
  const ownerLabels = Object.fromEntries(
    ownerUsers.map((user) => [user.id, user.displayName?.trim() || user.email]),
  );
  const countByClient = (items: { clientId: string; count: number }[]) =>
    new Map(items.map((item) => [item.clientId, item.count]));
  const grantCountsByClient = countByClient(grantCounts);
  const userCountsByClient = countByClient(userCounts);
  const sessionCountsByClient = countByClient(sessionCounts);
  const organizationsByClient = new Map<string, string[]>();
  for (const organization of clientOrganizations) {
    const list = organizationsByClient.get(organization.clientId) ?? [];
    list.push(organization.organizationId);
    organizationsByClient.set(organization.clientId, list);
  }

  return rows.map((row) => {
    const metadata = row.metadata as Partial<StoredClientMetadata>;
    const scopes = metadata.scopes ?? [];
    const owners = metadata.owners ?? [];
    const ownerLabelsForClient: Record<string, string> = {};
    for (const owner of owners) {
      const label = ownerLabels[owner.id];
      if (label) ownerLabelsForClient[owner.id] = label;
    }
    return {
      clientId: row.clientId,
      name: metadata.name || row.clientId,
      public: metadata.public ?? row.secretHash === null,
      disabled: metadata.disabled === true,
      hasSecret: row.secretHash !== null,
      redirectUris: metadata.redirectUris ?? [],
      scopes,
      resourceScopes: metadata.resourceScopes ?? Object.fromEntries(
        (row.resources ?? []).map((resource) => [resource, scopes]),
      ),
      permissions: definitionsByClient.get(row.clientId) ?? (metadata.permissions as PermissionDefinitions | undefined) ?? {},
      defaultPermissions: defaultsByClient.get(row.clientId) ?? [],
      resources: row.resources ?? [],
      requireConsent: row.requireConsent,
      filterMode: row.filterMode ?? null,
      filterContent: row.filterContent ?? [],
      owners,
      ownerLabels: ownerLabelsForClient,
      organizationIds: organizationsByClient.get(row.clientId) ?? [],
      permissionCatalogVersion: row.permissionCatalogVersion,
      grantCount: grantCountsByClient.get(row.clientId) ?? 0,
      userCount: userCountsByClient.get(row.clientId) ?? 0,
      sessionCount: sessionCountsByClient.get(row.clientId) ?? 0,
      updatedAt: row.updatedAt.toISOString(),
    };
  }).sort((a, b) => a.name.localeCompare(b.name));
}

export async function deleteClientById(db: Database, clientId: string): Promise<string> {
  const removed = await db
    .delete(oidcClients)
    .where(eq(oidcClients.clientId, clientId))
    .returning({ clientId: oidcClients.clientId });
  if (!removed.length) throw new Error(`Client ${clientId} does not exist`);
  return removed[0]!.clientId;
}

export function printClients(clients: ListedClient[], resources: Map<string, ResourceDetail>): void {
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return;
  }
  clients.forEach((client, index) => {
    process.stdout.write(
      `${index + 1}) ${client.name} (${client.clientId})${client.public ? " [public]" : " [confidential]"}${client.disabled ? " [disabled]" : ""}\n`,
    );
    process.stdout.write(`   client id: ${client.clientId}\n`);
    process.stdout.write(`   type: ${client.public ? "public (PKCE, no secret)" : "confidential (client secret required)"}\n`);
    process.stdout.write(
      `   secret: ${client.hasSecret ? "set (scrypt hash; the value is never shown)" : "none"}\n`,
    );
    process.stdout.write(`   redirect uris: ${client.redirectUris.join(", ") || "(none)"}\n`);
    process.stdout.write("   resources:\n");
    if (!client.resources.length) process.stdout.write("     (none)\n");
    for (const audience of client.resources) {
      const resource = resources.get(audience);
      const allowed = client.resourceScopes[audience] ?? [];
      process.stdout.write(
        `     - ${audience}${resource ? "" : " [MISSING RESOURCE SERVER]"}\n`,
      );
      process.stdout.write(`       allowed scopes: ${allowed.join(", ") || "(none)"}\n`);
      if (resource) {
        process.stdout.write(`       resource name: ${resource.name}\n`);
        process.stdout.write(`       resource scopes: ${resource.scopes.join(", ") || "(none)"}\n`);
        process.stdout.write(
          `       backchannel logout: ${resource.backchannelLogoutUris.join(", ") || "(not configured)"}\n`,
        );
        process.stdout.write(`       resource secret: ${resource.hasSecret ? "set" : "none"}\n`);
      }
    }
    process.stdout.write(`   resource scopes (legacy flat list): ${client.scopes.join(", ") || "(none)"}\n`);
    const permissions = Object.entries(client.permissions);
    process.stdout.write(
      `   permission definitions: ${permissions.length ? permissions.map(([permission, description]) => `${permission} (${description})`).join(", ") : "(none)"}\n`,
    );
    process.stdout.write(
      `   default permissions: ${client.defaultPermissions.join(", ") || "(none)"}\n`,
    );
    process.stdout.write(`   consent: ${client.requireConsent ? "shown" : "skipped"}\n`);
    process.stdout.write(
      `   filter: ${client.filterMode ?? "none"}${client.filterContent.length ? ` (${client.filterContent.join(", ")})` : ""}\n`,
    );
    process.stdout.write(`   organizations: ${client.organizationIds.join(", ") || "(none)"}\n`);
    process.stdout.write(
      `   owners: ${client.owners.map((owner) => {
        const label = client.ownerLabels[owner.id];
        return `${owner.id} (${owner.role}${label ? `, ${label}` : ""})`;
      }).join(", ") || "(none)"}\n`,
    );
    process.stdout.write(
      `   permission catalog version: ${client.permissionCatalogVersion}; ` +
        `users: ${client.userCount}; grants: ${client.grantCount}; active sessions: ${client.sessionCount}\n`,
    );
    process.stdout.write(`   created/updated: ${client.updatedAt}\n`);
    const missing = client.resources.filter((audience) => !resources.has(audience));
    if (missing.length) {
      process.stdout.write(
        `   WARNING: not registered as resource servers: ${missing.join(", ")} — add them in Resources or re-save via Edit\n`,
      );
    }
  });
}

export interface ResourceDetail {
  audience: string;
  name: string;
  scopes: string[];
  hasSecret: boolean;
  backchannelLogoutUris: string[];
  createdBy: string | null;
  createdByLabel: string | null;
  updatedAt: string;
  clientIds: string[];
}

export async function listResources(db: Database): Promise<ResourceDetail[]> {
  const resources = await db.select(resourceWithScopes).from(resourceServers).orderBy(resourceServers.audience);
  const clients = await db
    .select({ clientId: oidcClients.clientId, resources: oidcClients.resources })
    .from(oidcClients);
  const clientsByAudience = new Map<string, string[]>();
  for (const client of clients) {
    for (const audience of client.resources ?? []) {
      const list = clientsByAudience.get(audience) ?? [];
      list.push(client.clientId);
      clientsByAudience.set(audience, list);
    }
  }
  const creatorIds = [...new Set(resources.map((resource) => resource.createdBy).filter(Boolean))] as string[];
  const creators = creatorIds.length
    ? await db
        .select({ id: users.id, email: users.email, displayName: users.displayName })
        .from(users)
        .where(inArray(users.id, creatorIds))
    : [];
  const creatorLabels = new Map(
    creators.map((user) => [user.id, user.displayName?.trim() || user.email]),
  );
  return resources.map((resource) => ({
    audience: resource.audience,
    name: resource.name,
    scopes: resource.scopes,
    hasSecret: Boolean(resource.secretHash),
    backchannelLogoutUris: resource.backchannelLogoutUris,
    createdBy: resource.createdBy,
    createdByLabel: resource.createdBy ? creatorLabels.get(resource.createdBy) ?? null : null,
    updatedAt: resource.updatedAt.toISOString(),
    clientIds: (clientsByAudience.get(resource.audience) ?? []).sort(),
  }));
}

export function printResources(resources: ResourceDetail[]): void {
  if (!resources.length) {
    process.stdout.write("No resources registered.\n");
    return;
  }
  resources.forEach((resource, index) => {
    process.stdout.write(`${index + 1}) ${resource.name} (${resource.audience})\n`);
    process.stdout.write(`   scopes: ${resource.scopes.join(", ") || "(none)"}\n`);
    process.stdout.write(
      `   backchannel logout: ${resource.backchannelLogoutUris.join(", ") || "(not configured)"}\n`,
    );
    process.stdout.write(
      `   secret: ${resource.hasSecret ? "set (scrypt hash; the value is never shown)" : "none"}\n`,
    );
    process.stdout.write(
      `   created by: ${resource.createdBy ? `${resource.createdBy}${resource.createdByLabel ? ` (${resource.createdByLabel})` : ""}` : "(unknown)"}\n`,
    );
    process.stdout.write(
      `   clients: ${resource.clientIds.length ? resource.clientIds.join(", ") : "(none)"}\n`,
    );
    process.stdout.write(`   updated: ${resource.updatedAt}\n`);
  });
}

// A client referencing an unregistered audience fails authorize with
// unknown_resource (14407). Insert-only: existing rows keep their scopes.
export async function ensureResourcesRegistered(
  db: Database,
  registrations: { audience: string; scopes: string[] }[],
): Promise<string[]> {
  if (!registrations.length) return [];
  const existing = await db.select({ audience: resourceServers.audience }).from(resourceServers);
  const known = new Set(existing.map((row) => row.audience));
  const missing = registrations.filter((reg) => !known.has(reg.audience));
  for (const reg of missing) {
    const secretHash = await hashNewResourceSecret();
    await db.transaction(async (tx) => {
      const [created] = await tx.insert(resourceServers)
        .values({ audience: reg.audience, name: reg.audience, secretHash })
        .onConflictDoNothing({ target: resourceServers.audience })
        .returning({ audience: resourceServers.audience });
      if (created) await replaceResourceScopes(tx, reg.audience, reg.scopes);
    });
  }
  return missing.map((reg) => reg.audience);
}

export async function saveClient(
  db: Database,
  input: Omit<ClientSeed, "clientId">,
  resourceScopes: Map<string, string[]> = new Map(),
  resourceDefinitions: Map<string, string[]> = new Map(),
): Promise<ClientSeed> {
  await ensureResourcesRegistered(
    db,
    input.resources.map((audience) => ({
      audience,
      scopes: resourceDefinitions.get(audience) ?? resourceScopes.get(audience) ?? [],
    })),
  );
  const client: ClientSeed = { ...input, clientId: crypto.randomUUID() };
  await seedConfiguration(db, [client], []);
  return client;
}

async function promptRedirectUris(rl: Interface, initial: string, isPublic: boolean): Promise<string[]> {
  for (;;) {
    const candidates = splitList(await ask(rl, "Redirect URIs (comma-separated)", initial));
    const invalid = candidates.filter((uri) => {
      if (isEphemeralLocalhostRedirectUri(uri)) return false;
      try {
        const url = new URL(uri);
        return !(url.protocol === "http:" || url.protocol === "https:") ||
          Boolean(url.username || url.password);
      } catch {
        return true;
      }
    });
    if (!candidates.length) process.stdout.write("At least one redirect URI is required.\n");
    else if (!isPublic && candidates.some(isEphemeralLocalhostRedirectUri)) {
      process.stdout.write("Ephemeral localhost redirect URIs are only supported for public clients.\n");
    }
    else if (invalid.length) process.stdout.write(`Invalid URL(s): ${invalid.join(", ")}\n`);
    else return candidates;
  }
}

async function promptResources(rl: Interface, audiences: string[], initial: string): Promise<string[]> {
  if (audiences.length) {
    process.stdout.write("Registered resources:\n");
    audiences.forEach((audience, index) => process.stdout.write(`  ${index + 1}) ${audience}\n`));
  }
  for (;;) {
    const resources = splitList(await ask(rl, "Dedicated resource (number or value)", initial)).map(
      (entry) => {
        const byNumber = /^\d+$/.test(entry) ? audiences[Number(entry) - 1] : undefined;
        return byNumber ?? entry;
      },
    );
    if (!resources.length) process.stdout.write("At least one resource is required.\n");
    else return resources;
  }
}

async function promptFilterMode(rl: Interface, initial: string): Promise<"whitelist" | "blacklist" | null> {
  for (;;) {
    const raw = (await ask(rl, "Account filter (blank, whitelist, blacklist)", initial)).toLowerCase();
    if (!raw) return null;
    if (raw === "whitelist" || raw === "blacklist") return raw;
    process.stdout.write('Enter blank, "whitelist", or "blacklist".\n');
  }
}

async function promptOrganizationIds(rl: Interface, initial: string[]): Promise<string[]> {
  for (;;) {
    const values = splitList(await ask(rl, "Organization IDs (comma-separated)", initial.join(", ")));
    const invalid = values.filter((value) => !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(value));
    if (!values.length) process.stdout.write("At least one organization ID is required.\n");
    else if (invalid.length) process.stdout.write(`Invalid organization ID(s): ${invalid.join(", ")}\n`);
    else if (new Set(values).size !== values.length) process.stdout.write("Organization IDs must be unique.\n");
    else return values;
  }
}

async function promptMissingResourceScopes(
  rl: Interface,
  resources: string[],
  known: Set<string>,
): Promise<Map<string, string[]>> {
  const scopes = new Map<string, string[]>();
  for (const audience of resources) {
    if (known.has(audience)) continue;
    process.stdout.write(`Resource ${audience} is not registered yet and will be created live.\n`);
    scopes.set(audience, await promptScopes(rl, `Scopes for ${audience}`, []));
  }
  return scopes;
}

function parseScopes(value: string): string[] {
  const scopes = splitList(value);
  const invalid = scopes.filter((scope) => !/^[\x21\x23-\x5b\x5d-\x7e]+$/.test(scope));
  if (invalid.length) throw new Error(`Invalid OAuth scope(s): ${invalid.join(", ")}`);
  const seen = new Set<string>();
  const duplicates = scopes.filter((scope) => {
    if (seen.has(scope)) return true;
    seen.add(scope);
    return false;
  });
  if (duplicates.length) throw new Error(`Duplicate scope(s): ${duplicates.join(", ")}`);
  return scopes;
}

async function promptScopes(rl: Interface, label: string, initial: string[]): Promise<string[]> {
  for (;;) {
    const raw = await ask(rl, `${label} (comma-separated, blank = none, "none" clears)`, initial.join(", "));
    try {
      return raw.toLowerCase() === "none" ? [] : parseScopes(raw);
    } catch (error) {
      process.stdout.write(`${error instanceof Error ? error.message : "Invalid scopes"}\n`);
    }
  }
}

async function promptAllowedResourceScopes(
  rl: Interface,
  resources: string[],
  available: Map<string, string[]>,
  initial: Map<string, string[]>,
  defaultToAllAvailable: boolean,
): Promise<Map<string, string[]>> {
  const allowed = new Map<string, string[]>();
  for (const audience of resources) {
    const registered = available.get(audience) ?? [];
    const registeredSet = new Set(registered);
    const fallback = initial.get(audience) ?? (defaultToAllAvailable ? registered : []);
    process.stdout.write(
      `\n${audience}\n  registered scopes: ${registered.join(", ") || "(none)"}\n`,
    );
    for (;;) {
      const scopes = await promptScopes(rl, "Allowed scopes", fallback);
      const unregistered = scopes.filter((scope) => !registeredSet.has(scope));
      if (unregistered.length) {
        process.stdout.write(
          `Not registered on this resource: ${unregistered.join(", ")}. Edit the resource scopes first.\n`,
        );
        continue;
      }
      allowed.set(audience, scopes);
      break;
    }
  }
  return allowed;
}

function parsePermissionSelection(value: string): string[] {
  return value.toLowerCase() === "none" ? [] : splitList(value);
}

function allScopes(resourceScopes: Map<string, string[]>): string[] {
  return [...new Set([...resourceScopes.values()].flat())];
}

function printClientSummary(
  input: {
    clientId?: string;
    name?: string;
    public: boolean;
    disabled?: boolean;
    redirectUris: string[];
    resources: string[];
    scopes: string[];
    permissions: PermissionDefinitions;
    defaultPermissions?: string[];
    requireConsent: boolean;
    filterMode: "whitelist" | "blacklist" | null;
    filterContent: string[];
    organizationIds: string[];
  },
  resourceScopes: Map<string, string[]>,
  owners: ClientOwner[] = [],
): void {
  process.stdout.write(
    `${input.clientId ? `\nClient ID: ${input.clientId}\n` : "\n"}Name: ${input.name ?? "(none)"}\nType: ${input.public ? "public" : "confidential"}\n` +
      `Disabled: ${input.disabled ? "yes" : "no"}\n` +
      `Redirects: ${input.redirectUris.join(", ")}\n` +
      `Resources:\n${input.resources.map((resource) =>
        `  - ${resource}: ${(resourceScopes.get(resource) ?? []).join(", ") || "(no scopes)"}`,
      ).join("\n")}\n` +
      `Permission definitions: ${Object.entries(input.permissions).map(([permission, description]) => `${permission} (${description})`).join(", ") || "(none)"}\n` +
      `Default permissions: ${(input.defaultPermissions ?? []).join(", ") || "(none)"}\n` +
      `Consent: ${input.requireConsent ? "shown" : "skipped"}\n` +
      `Organizations: ${input.organizationIds.join(", ")}\n` +
      `Filter: ${input.filterMode ?? "none"}${input.filterContent.length ? ` (${input.filterContent.join(", ")})` : ""}\n` +
      `Owners: ${owners.map((owner) => `${owner.id} (${owner.role})`).join(", ") || "(unchanged)"}\n`,
  );
}

export interface NewClient {
  input: Omit<ClientSeed, "clientId">;
  generatedSecret: string | null;
  resourceScopes: Map<string, string[]>;
  resourceDefinitions: Map<string, string[]>;
}

export async function promptNewClient(
  rl: Interface,
  resourceDetails: ResourceDetail[],
): Promise<NewClient | null> {
  const audiences = resourceDetails.map((resource) => resource.audience);
  const name = await ask(rl, "Display name");
  const isPublic = await askYesNo(rl, "Public client (no secret)?", false);

  let clientSecret: string | undefined;
  let generatedSecret: string | null = null;
  if (!isPublic) {
    const provided = await ask(rl, "Client secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    clientSecret = provided || (generatedSecret = generateClientSecret());
  }

  const redirectUris = await promptRedirectUris(rl, "", isPublic);
  const resources = await promptResources(rl, audiences, "");
  const available = new Map(resourceDetails.map((resource) => [resource.audience, resource.scopes]));
  const missing = await promptMissingResourceScopes(rl, resources, new Set(audiences));
  for (const [audience, scopes] of missing) available.set(audience, scopes);
  const resourceScopes = await promptAllowedResourceScopes(
    rl, resources, available, new Map(), true,
  );
  const scopes = allScopes(resourceScopes);

  const permissions = await promptPermissionDefinitions(rl, {});
  const defaultPermissions = await promptDefaultPermissions(rl, permissions, []);
  const requireConsent = await askYesNo(rl, "Show consent screen?", true);
  const filterMode = await promptFilterMode(rl, "");
  const filterContent = filterMode ? splitList(await ask(rl, "Filter emails (comma-separated)")) : [];
  const organizationIds = await promptOrganizationIds(rl, [DEFAULT_ORGANIZATION_ID]);

  const input = clientInputSchema.parse({
    ...(name ? { name } : {}),
    ...(clientSecret ? { clientSecret } : {}),
    redirectUris,
    public: isPublic,
    ...(scopes.length ? { scopes } : {}),
    resourceScopes: Object.fromEntries(resourceScopes),
    permissions,
    defaultPermissions,
    resources,
    requireConsent,
    filterMode,
    filterContent,
    organizationIds,
  });

  printClientSummary(input, resourceScopes);
  if (!(await askYesNo(rl, "Create this client?", true))) return null;
  return { input, generatedSecret, resourceScopes, resourceDefinitions: missing };
}

export async function runAddFlow(db: Database): Promise<void> {
  requireTty();
  const resources = await listResources(db);
  const known = new Set(resources.map((resource) => resource.audience));
  const rl = createInterface({ input, output });
  try {
    const created = await promptNewClient(rl, resources);
    if (!created) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const client = await saveClient(
      db, created.input, created.resourceScopes, created.resourceDefinitions,
    );
    process.stdout.write(`Created client ${client.clientId}\n`);
    const registered = created.input.resources.filter((audience) => !known.has(audience));
    if (registered.length) {
      process.stdout.write(`Registered new resource(s) live, no restart needed: ${registered.join(", ")}\n`);
      process.stdout.write(
        "Their initial secrets were not shown; use Resources > Rotate resource secret to issue one before wiring callers.\n",
      );
    }
    if (created.generatedSecret) {
      process.stdout.write(`Client secret (copy now, only a hash is stored): ${created.generatedSecret}\n`);
    }
  } finally {
    rl.close();
  }
}

async function pickClient(rl: Interface, clients: ListedClient[], verb: string): Promise<ListedClient> {
  const raw = await ask(rl, `Client to ${verb} (number or id)`);
  const byNumber = /^\d+$/.test(raw) ? clients[Number(raw) - 1] : undefined;
  const selected = byNumber ?? clients.find((client) => client.clientId === raw);
  if (!selected) throw new Error(`No client matches "${raw}"`);
  return selected;
}

async function resourceDetailMap(db: Database): Promise<Map<string, ResourceDetail>> {
  return new Map((await listResources(db)).map((resource) => [resource.audience, resource]));
}

async function listedOrEmpty(db: Database): Promise<ListedClient[] | null> {
  const clients = await listClients(db);
  if (!clients.length) {
    process.stdout.write("No clients registered.\n");
    return null;
  }
  printClients(clients, await resourceDetailMap(db));
  return clients;
}

export async function runRemoveFlow(db: Database, preselected?: string): Promise<void> {
  if (preselected) {
    process.stdout.write(`${await deleteClientById(db, preselected)}\n`);
    return;
  }
  requireTty();
  const clients = await listedOrEmpty(db);
  if (!clients) return;
  const rl = createInterface({ input, output });
  try {
    const selected = await pickClient(rl, clients, "remove");
    if (
      !(await askYesNo(
        rl,
        `Delete ${selected.name} (${selected.clientId})? Authorization data goes with it`,
        false,
      ))
    ) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    process.stdout.write(`${await deleteClientById(db, selected.clientId)}\n`);
  } finally {
    rl.close();
  }
}

export interface ClientDetail {
  clientId: string;
  name: string;
  public: boolean;
  disabled: boolean;
  hasSecret: boolean;
  redirectUris: string[];
  scopes: string[];
  resourceScopes: Record<string, string[]>;
  permissions: PermissionDefinitions;
  defaultPermissions: string[];
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  owners: ClientOwner[];
  ownerLabels: Record<string, string>;
  organizationIds: string[];
  permissionCatalogVersion: number;
  grantCount: number;
  userCount: number;
  sessionCount: number;
  updatedAt: string;
}

export async function getClientDetail(db: Database, clientId: string): Promise<ClientDetail> {
  const [row] = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
  if (!row) throw new Error(`Client ${clientId} does not exist`);
  const metadata = row.metadata as Partial<StoredClientMetadata>;
  const [definitions, defaults, ownerRows, counts, affiliationCount, sessionCount] = await Promise.all([
    db
      .select({ permission: oidcPermissions.permission, description: oidcPermissions.description })
      .from(oidcPermissions)
      .where(eq(oidcPermissions.clientId, clientId)),
    db
      .select({ permission: defaultPermissions.permission })
      .from(defaultPermissions)
      .where(eq(defaultPermissions.applicationId, clientId)),
    Promise.resolve(metadata.owners ?? []).then((owners) => owners.length
      ? db
          .select({ id: users.id, email: users.email, displayName: users.displayName })
          .from(users)
          .where(inArray(users.id, owners.map((owner) => owner.id)))
      : []),
    db
      .select({ grants: sql<number>`count(*)::int` })
      .from(userPermissions)
      .where(eq(userPermissions.applicationId, clientId)),
    db
      .select({ users: sql<number>`count(*)::int` })
      .from(userApplications)
      .where(eq(userApplications.applicationId, clientId)),
    db
      .select({ sessions: sql<number>`count(*)::int` })
      .from(authorizationSessions)
      .where(and(
        eq(authorizationSessions.clientId, clientId),
        isNull(authorizationSessions.revokedAt),
      )),
  ]);
  const legacyDefinitions = metadata.permissions && typeof metadata.permissions === "object"
    ? metadata.permissions as PermissionDefinitions
    : {};
  const owners = metadata.owners ?? [];
  return {
    clientId: row.clientId,
    name: metadata.name || row.clientId,
    public: metadata.public ?? row.secretHash === null,
    disabled: metadata.disabled === true,
    hasSecret: row.secretHash !== null,
    redirectUris: metadata.redirectUris ?? [],
    scopes: metadata.scopes ?? [],
    resourceScopes: metadata.resourceScopes ?? Object.fromEntries(
      (row.resources ?? []).map((resource) => [resource, metadata.scopes ?? []]),
    ),
    permissions: definitions.length
      ? Object.fromEntries(definitions.map((definition) => [definition.permission, definition.description]))
      : legacyDefinitions,
    defaultPermissions: defaults.map((definition) => definition.permission),
    resources: row.resources ?? [],
    requireConsent: row.requireConsent,
    filterMode: row.filterMode ?? null,
    filterContent: row.filterContent ?? [],
    owners,
    ownerLabels: Object.fromEntries(
      ownerRows.map((user) => [user.id, user.displayName?.trim() || user.email]),
    ),
    organizationIds: (await db
      .select({ organizationId: organizations.organizationId })
      .from(oidcClientOrganizations)
      .innerJoin(organizations, eq(oidcClientOrganizations.organizationId, organizations.id))
      .where(eq(oidcClientOrganizations.clientId, clientId)))
      .map((organization) => organization.organizationId),
    permissionCatalogVersion: row.permissionCatalogVersion,
    grantCount: counts[0]?.grants ?? 0,
    userCount: affiliationCount[0]?.users ?? 0,
    sessionCount: sessionCount[0]?.sessions ?? 0,
    updatedAt: row.updatedAt.toISOString(),
  };
}

export interface EditedClient {
  clientId: string;
  name: string;
  public: boolean;
  disabled: boolean;
  newSecret: string | null | undefined;
  redirectUris: string[];
  scopes: string[];
  permissions: PermissionDefinitions;
  defaultPermissions: string[];
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  organizationIds: string[];
  owners: ClientOwner[];
  resourceScopes: Map<string, string[]>;
  resourceDefinitions?: Map<string, string[]>;
}

async function promptOwners(
  rl: Interface,
  owners: ClientOwner[],
  labels: Record<string, string>,
): Promise<ClientOwner[]> {
  const formatted = owners.map((owner) => `${owner.id}:${owner.role}`).join(", ");
  process.stdout.write(
    `Current owners: ${owners.map((owner) =>
      `${owner.id} (${owner.role}${labels[owner.id] ? `, ${labels[owner.id]}` : ""})`,
    ).join(", ") || "(none)"}\n`,
  );
  for (;;) {
    const raw = await ask(
      rl,
      'Owners (comma-separated id:role.ADMIN|role.GENERAL, blank = keep, "none" = remove all)',
      formatted,
    );
    if (!raw || raw === formatted) return owners;
    if (raw.toLowerCase() === "none") return [];
    try {
      const seen = new Set<string>();
      return raw.split(",").map((entry) => {
        const [id, role, ...extra] = entry.split(":");
        const trimmedId = id?.trim() ?? "";
        const normalizedRole = (role?.trim() ?? "") as ClientOwner["role"];
        if (extra.length || !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(trimmedId)) {
          throw new Error(`Invalid owner entry "${entry.trim()}". Use <uuid>:role.ADMIN or <uuid>:role.GENERAL`);
        }
        if (normalizedRole !== "role.ADMIN" && normalizedRole !== "role.GENERAL") {
          throw new Error(`Invalid owner role in "${entry.trim()}". Use role.ADMIN or role.GENERAL`);
        }
        if (seen.has(trimmedId)) throw new Error(`Duplicate owner ${trimmedId}`);
        seen.add(trimmedId);
        return { id: trimmedId, role: normalizedRole };
      });
    } catch (error) {
      process.stdout.write(`${error instanceof Error ? error.message : "Invalid owners"}\n`);
    }
  }
}

export async function promptEditClient(
  rl: Interface,
  current: ClientDetail,
  resourceDetails: ResourceDetail[],
): Promise<EditedClient | null> {
  const audiences = resourceDetails.map((resource) => resource.audience);
  const name = await ask(rl, "Display name", current.name);
  const requestedClientId = await ask(
    rl,
    'Client ID (blank = keep, "new" = generate a UUID)',
    current.clientId,
  );
  const clientId = requestedClientId === "new" ? crypto.randomUUID() : requestedClientId;
  if (!clientId.trim()) throw new Error("Client ID must not be empty");
  const isPublic = await askYesNo(rl, "Public client (no secret)?", current.public);
  const disabled = await askYesNo(rl, "Disable this client?", current.disabled);

  let newSecret: string | null | undefined;
  if (isPublic) {
    if (!current.public) process.stdout.write("The existing secret will be dropped.\n");
    newSecret = null;
  } else if (current.public || !current.hasSecret) {
    const provided = await ask(rl, "Client secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    newSecret = provided || generateClientSecret();
  } else if (await askYesNo(rl, "Rotate secret?", false)) {
    const provided = await ask(rl, "New secret (blank = auto-generate sk-...)");
    if (provided && provided.length < 16) throw new Error("Client secret must be at least 16 characters");
    newSecret = provided || generateClientSecret();
  }

  const redirectUris = await promptRedirectUris(rl, current.redirectUris.join(", "), isPublic);
  const resources = await promptResources(rl, audiences, current.resources.join(", "));
  const available = new Map(resourceDetails.map((resource) => [resource.audience, resource.scopes]));
  const missing = await promptMissingResourceScopes(rl, resources, new Set(audiences));
  for (const [audience, scopes] of missing) available.set(audience, scopes);
  const resourceScopes = await promptAllowedResourceScopes(
    rl, resources, available, new Map(Object.entries(current.resourceScopes)), false,
  );
  const scopes = allScopes(resourceScopes);

  const permissions = await promptPermissionDefinitions(rl, current.permissions);
  const defaultPermissions = await promptDefaultPermissions(
    rl, permissions, current.defaultPermissions,
  );
  const requireConsent = await askYesNo(rl, "Show consent screen?", current.requireConsent);
  const filterMode = await promptFilterMode(rl, current.filterMode ?? "");
  const filterDefault = filterMode === current.filterMode ? current.filterContent.join(", ") : "";
  const filterContent = filterMode ? splitList(await ask(rl, "Filter emails (comma-separated)", filterDefault)) : [];
  const organizationIds = await promptOrganizationIds(rl, current.organizationIds);
  const owners = await promptOwners(rl, current.owners, current.ownerLabels);

  const input = clientInputSchema.parse({
    name,
    ...(typeof newSecret === "string" ? { clientSecret: newSecret } : {}),
    redirectUris,
    public: isPublic,
    scopes,
    resourceScopes: Object.fromEntries(resourceScopes),
    permissions,
    defaultPermissions,
    resources,
    requireConsent,
    filterMode,
    filterContent,
    organizationIds,
  });

  printClientSummary({ ...input, clientId, disabled }, resourceScopes, owners);
  process.stdout.write(
    `Secret: ${newSecret === undefined ? "kept" : newSecret === null ? "dropped" : "rotated (shown once after save)"}\n`,
  );
  if (!(await askYesNo(rl, "Save changes?", true))) return null;
  return {
    ...input,
    clientId,
    name: input.name ?? current.clientId,
    disabled,
    newSecret,
    owners,
    resourceScopes,
    resourceDefinitions: missing,
  };
}

export async function applyClientEdit(db: Database, clientId: string, edit: EditedClient): Promise<string | null> {
  const [row] = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
  if (!row) throw new Error(`Client ${clientId} does not exist`);
  const targetClientId = edit.clientId;
  if (!targetClientId.trim()) throw new Error("Client ID must not be empty");
  if (targetClientId !== clientId) {
    const [existing] = await db
      .select({ clientId: oidcClients.clientId })
      .from(oidcClients)
      .where(eq(oidcClients.clientId, targetClientId))
      .limit(1);
    if (existing) throw new Error(`Client ${targetClientId} already exists`);
  }
  const { permissions: _legacyPermissions, ...current } = row.metadata as Partial<StoredClientMetadata>;
  const metadata: StoredClientMetadata = {
    ...current,
    name: edit.name,
    owners: edit.owners,
    redirectUris: edit.redirectUris,
    public: edit.public,
    scopes: edit.scopes,
    resourceScopes: Object.fromEntries(
      edit.resources.map((resource) => [resource, edit.resourceScopes.get(resource) ?? edit.scopes]),
    ),
    ...(edit.disabled ? { disabled: true } : {}),
  } as StoredClientMetadata;
  if (!edit.disabled) delete metadata.disabled;

  let secretHash = row.secretHash;
  let rotatedSecret: string | null = null;
  if (edit.newSecret === null) secretHash = null;
  else if (edit.newSecret !== undefined) {
    rotatedSecret = edit.newSecret;
    secretHash = await hashClientSecret(edit.newSecret);
  }

  await ensureResourcesRegistered(
    db,
    edit.resources.map((audience) => ({
      audience,
      scopes: edit.resourceDefinitions?.get(audience) ?? edit.resourceScopes.get(audience) ?? [],
    })),
  );
  const linkedOrganizations = await db
    .select({ id: organizations.id })
    .from(organizations)
    .where(inArray(organizations.organizationId, edit.organizationIds));
  if (linkedOrganizations.length !== edit.organizationIds.length) {
    throw new Error("One or more organizations do not exist");
  }
  await db.transaction(async (tx) => {
    const values = {
      metadata,
      secretHash,
      resources: edit.resources,
      requireConsent: edit.requireConsent,
      filterMode: edit.filterMode,
      filterContent: edit.filterContent,
      updatedAt: new Date(),
    };
    if (targetClientId === clientId) {
      await tx.update(oidcClients).set(values).where(eq(oidcClients.clientId, clientId));
    } else {
      await tx.insert(oidcClients).values({
        clientId: targetClientId,
        ...values,
        permissionCatalogVersion: row.permissionCatalogVersion,
      });
      const catalog = await tx
        .select({ permission: oidcPermissions.permission, description: oidcPermissions.description })
        .from(oidcPermissions)
        .where(eq(oidcPermissions.clientId, clientId));
      if (catalog.length) {
        await tx.insert(oidcPermissions).values(
          catalog.map((definition) => ({ clientId: targetClientId, ...definition })),
        );
      }
      await tx.update(defaultPermissions).set({ applicationId: targetClientId }).where(eq(defaultPermissions.applicationId, clientId));
      await tx.update(userPermissions).set({ applicationId: targetClientId }).where(eq(userPermissions.applicationId, clientId));
      await tx.update(userApplications).set({ applicationId: targetClientId }).where(eq(userApplications.applicationId, clientId));
      await tx.update(authorizationRequests).set({ clientId: targetClientId }).where(eq(authorizationRequests.clientId, clientId));
      await tx.update(authorizationCodes).set({ clientId: targetClientId }).where(eq(authorizationCodes.clientId, clientId));
      await tx.update(authorizationSessions).set({ clientId: targetClientId }).where(eq(authorizationSessions.clientId, clientId));
      await tx.update(authorizationConsents).set({ clientId: targetClientId }).where(eq(authorizationConsents.clientId, clientId));
      await tx.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
    }
    await tx.delete(oidcClientOrganizations).where(eq(oidcClientOrganizations.clientId, targetClientId));
    await tx.insert(oidcClientOrganizations).values(
      linkedOrganizations.map((organization) => ({ clientId: targetClientId, organizationId: organization.id })),
    );
  });
  await syncPermissionCatalog(db, targetClientId, edit.permissions);
  await db.transaction(async (tx) => {
    await tx.delete(defaultPermissions).where(eq(defaultPermissions.applicationId, targetClientId));
    if (edit.defaultPermissions.length) {
      await tx.insert(defaultPermissions).values(
        edit.defaultPermissions.map((permission) => ({ applicationId: targetClientId, permission })),
      );
    }
  });
  return rotatedSecret;
}

export async function runEditFlow(db: Database): Promise<void> {
  requireTty();
  const clients = await listedOrEmpty(db);
  if (!clients) return;
  const resourceDetails = await listResources(db);
  const known = new Set(resourceDetails.map((resource) => resource.audience));
  const rl = createInterface({ input, output });
  try {
    const selected = await pickClient(rl, clients, "edit");
    const edited = await promptEditClient(
      rl,
      await getClientDetail(db, selected.clientId),
      resourceDetails,
    );
    if (!edited) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const rotatedSecret = await applyClientEdit(db, selected.clientId, edited);
    process.stdout.write(
      `Updated client ${edited.clientId}${edited.clientId !== selected.clientId ? ` (was ${selected.clientId})` : ""} ` +
        "(applies within ~60s, no restart needed)\n",
    );
    if (edited.clientId !== selected.clientId) {
      process.stdout.write(
        `Client ID changed. Update downstream client configurations, and remove the old ID from OIDC_CLIENTS_JSON or the startup seed will recreate it.\n`,
      );
    }
    const registered = edited.resources.filter((audience) => !known.has(audience));
    if (registered.length) {
      process.stdout.write(`Registered new resource(s) live, no restart needed: ${registered.join(", ")}\n`);
    }
    if (rotatedSecret) {
      process.stdout.write(`New client secret (copy now, only a hash is stored): ${rotatedSecret}\n`);
    }
  } finally {
    rl.close();
  }
}

export async function runRotateClientSecretFlow(db: Database): Promise<void> {
  requireTty();
  const clients = await listedOrEmpty(db);
  if (!clients) return;
  const rl = createInterface({ input, output });
  try {
    const selected = await pickClient(rl, clients, "rotate the secret for");
    if (selected.public) {
      process.stdout.write(
        `${selected.clientId} is a public client and has no secret. Use Edit client to change its type first.\n`,
      );
      return;
    }
    if (!(await askYesNo(
      rl,
      `Rotate the secret for ${selected.name} (${selected.clientId})? Downstream login fails until updated`,
      false,
    ))) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const secret = generateClientSecret();
    await db.update(oidcClients).set({
      secretHash: await hashClientSecret(secret),
      updatedAt: new Date(),
    }).where(eq(oidcClients.clientId, selected.clientId));
    process.stdout.write(`New client secret (copy now, only a hash is stored): ${secret}\n`);
  } finally {
    rl.close();
  }
}

async function pickResource(
  rl: Interface,
  resources: ResourceDetail[],
  verb: string,
): Promise<ResourceDetail> {
  const raw = await ask(rl, `Resource to ${verb} (number or audience)`);
  const byNumber = /^\d+$/.test(raw) ? resources[Number(raw) - 1] : undefined;
  const selected = byNumber ?? resources.find((resource) => resource.audience === raw);
  if (!selected) throw new Error(`No resource matches "${raw}"`);
  return selected;
}

async function promptBackchannelUris(
  rl: Interface,
  initial: string[],
  allowKeep: boolean,
): Promise<string[] | undefined> {
  for (;;) {
    const raw = await ask(
      rl,
      `Backchannel logout URLs (comma-separated, ${allowKeep ? 'blank = keep, ' : ""}"none" = clear)`,
      initial.join(", "),
    );
    if (!raw) return allowKeep ? undefined : [];
    if (raw.toLowerCase() === "none") return [];
    const uris = [...new Set(splitList(raw))];
    const invalid = uris.filter((uri) => !backchannelLogoutUriSchema.safeParse(uri).success);
    if (invalid.length) {
      process.stdout.write(
        `Invalid URL(s): ${invalid.join(", ")}. Use HTTPS, or HTTP with hostname exactly localhost; no credentials or fragment.\n`,
      );
      continue;
    }
    return uris;
  }
}

async function confirmBackchannelUris(
  db: Database,
  rl: Interface,
  audience: string,
  uris: string[],
): Promise<string[] | null> {
  if (!(await askYesNo(
    rl,
    "Verify the webhook URLs now? The receivers and basis-auth internal listener must be reachable",
    true,
  ))) return uris;
  const verifier = createBackchannelVerifier(db);
  process.stdout.write(`Sending action=test to ${uris.length} URL(s) and waiting up to 10 seconds...\n`);
  const results = await Promise.all(uris.map(async (uri) => ({
    uri,
    result: await verifier.verifyDestination(audience, uri),
  })));
  const verified = results.filter((entry) => entry.result === "verified").map((entry) => entry.uri);
  const failed = results
    .filter((entry) => entry.result !== "verified")
    .map((entry) => `${entry.uri} (${entry.result})`);
  if (!failed.length) {
    process.stdout.write("All webhooks verified.\n");
    return uris;
  }
  process.stdout.write(
    `Verification failed: ${failed.join(", ")}. A receiver must return 202 and post the HMAC proof to the internal API.\n`,
  );
  if (verified.length) {
    if (await askYesNo(rl, `Save only the ${verified.length} verified URL(s)?`, true)) return verified;
  }
  return (await askYesNo(rl, "Save the URLs without verification anyway?", false)) ? uris : null;
}

export async function runRegisterResourceFlow(db: Database): Promise<void> {
  requireTty();
  const existing = await listResources(db);
  if (existing.length) printResources(existing);
  const rl = createInterface({ input, output });
  try {
    const audience = await ask(rl, "New resource audience (e.g. urn:basis:api:example)");
    if (!audience) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    if (existing.some((resource) => resource.audience === audience)) {
      process.stdout.write(`${audience} is already registered. Use Edit resource instead.\n`);
      return;
    }
    const name = await ask(rl, "Display name", audience);
    const scopes = await promptScopes(rl, "Resource scopes", []);
    const backchannelLogoutUris = await promptBackchannelUris(rl, [], false);
    const secret = generateClientSecret();
    const secretHash = await hashClientSecret(secret);
    await db.transaction(async (tx) => {
      await tx.insert(resourceServers).values({ audience, name: name || audience, secretHash });
      await replaceResourceScopes(tx, audience, scopes);
    });
    let savedLogoutUris: string[] = [];
    if (backchannelLogoutUris?.length) {
      const accepted = await confirmBackchannelUris(db, rl, audience, backchannelLogoutUris);
      if (accepted?.length) {
        await db.update(resourceServers).set({ backchannelLogoutUris: accepted, updatedAt: new Date() })
          .where(eq(resourceServers.audience, audience));
        savedLogoutUris = accepted;
      }
    }
    process.stdout.write(`Registered ${audience} live, no restart needed\n`);
    process.stdout.write(`Resource secret (copy now, only a hash is stored): ${secret}\n`);
    if (!savedLogoutUris.length) {
      process.stdout.write(
        "No backchannel logout URL: authorization-code sign-in and refresh for this resource fail with 14408 until one is configured.\n",
      );
    }
  } finally {
    rl.close();
  }
}

export async function runListResourcesFlow(db: Database): Promise<void> {
  printResources(await listResources(db));
}

export async function runEditResourceFlow(db: Database): Promise<void> {
  requireTty();
  const resources = await listResources(db);
  if (!resources.length) {
    process.stdout.write("No resources registered.\n");
    return;
  }
  printResources(resources);
  const rl = createInterface({ input, output });
  try {
    const selected = await pickResource(rl, resources, "edit");
    const name = await ask(rl, "Display name", selected.name);
    const clientRows = await db
      .select({ clientId: oidcClients.clientId, resources: oidcClients.resources, metadata: oidcClients.metadata })
      .from(oidcClients)
      .where(sql`${oidcClients.resources} @> ${JSON.stringify([selected.audience])}::jsonb`);
    let scopes: string[] = selected.scopes;
    for (;;) {
      const candidate = await promptScopes(rl, "Resource scopes", scopes);
      const candidateSet = new Set(candidate);
      const removed = selected.scopes.filter((scope) => !candidateSet.has(scope));
      const removedSet = new Set(removed);
      const conflicts = clientRows.flatMap((row) => {
        const metadata = row.metadata as Partial<StoredClientMetadata>;
        const allowed = metadata.resourceScopes?.[selected.audience] ?? metadata.scopes ?? [];
        const affected = allowed.filter((scope) => removedSet.has(scope));
        return affected.length ? [`${row.clientId} (${affected.join(", ")})`] : [];
      });
      scopes = candidate;
      if (!conflicts.length) break;
      process.stdout.write(
        `Cannot remove scopes still allowed for clients: ${conflicts.join(", ")}. Update those clients first.\n`,
      );
    }
    const requestedLogoutUris = await promptBackchannelUris(
      rl, selected.backchannelLogoutUris, true,
    );
    const acceptedLogoutUris = requestedLogoutUris === undefined
      ? undefined
      : requestedLogoutUris.length === 0
        ? []
        : await confirmBackchannelUris(db, rl, selected.audience, requestedLogoutUris) ?? undefined;
    await db.transaction(async (tx) => {
      const [updated] = await tx.update(resourceServers).set({
        name: name || selected.audience,
        ...(acceptedLogoutUris === undefined ? {} : { backchannelLogoutUris: acceptedLogoutUris }),
        updatedAt: new Date(),
      }).where(eq(resourceServers.audience, selected.audience)).returning({ audience: resourceServers.audience });
      if (!updated) throw new Error(`Resource ${selected.audience} is no longer registered`);
      await replaceResourceScopes(tx, selected.audience, scopes);
    });
    process.stdout.write(`Updated resource ${selected.audience}\n`);
    if (acceptedLogoutUris?.length === 0) {
      process.stdout.write(
        "Backchannel logout cleared: authorization-code sign-in and refresh for this resource now fail with 14408.\n",
      );
    } else if (requestedLogoutUris !== undefined && acceptedLogoutUris === undefined) {
      process.stdout.write("Backchannel logout URLs were left unchanged.\n");
    }
  } finally {
    rl.close();
  }
}

export async function runRotateResourceSecretFlow(db: Database): Promise<void> {
  requireTty();
  const resources = await listResources(db);
  if (!resources.length) {
    process.stdout.write("No resources registered.\n");
    return;
  }
  printResources(resources);
  const rl = createInterface({ input, output });
  try {
    const selected = await pickResource(rl, resources, "rotate the secret for");
    if (!(await askYesNo(
      rl,
      `Rotate ${selected.audience}? Every caller using the old secret fails until updated`,
      false,
    ))) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    const secret = generateClientSecret();
    await db.update(resourceServers).set({
      secretHash: await hashClientSecret(secret),
      updatedAt: new Date(),
    }).where(eq(resourceServers.audience, selected.audience));
    process.stdout.write(`Resource secret (copy now, only a hash is stored): ${secret}\n`);
    process.stdout.write(
      "Update the backchannel receiver, internal API callers, and any other service that authenticates as this resource.\n",
    );
  } finally {
    rl.close();
  }
}

export async function runDeleteResourceFlow(db: Database): Promise<void> {
  requireTty();
  const resources = await listResources(db);
  if (!resources.length) {
    process.stdout.write("No resources registered.\n");
    return;
  }
  printResources(resources);
  const rl = createInterface({ input, output });
  try {
    const selected = await pickResource(rl, resources, "delete");
    if (selected.clientIds.length) {
      process.stdout.write(
        `WARNING: these clients still reference ${selected.audience}: ${selected.clientIds.join(", ")}\n`,
      );
    }
    if (!(await askYesNo(
      rl,
      `Delete ${selected.name} (${selected.audience})? Verification data and the secret go with it`,
      false,
    ))) {
      process.stdout.write("Cancelled.\n");
      return;
    }
    await db.delete(resourceServers).where(eq(resourceServers.audience, selected.audience));
    process.stdout.write(`Deleted resource ${selected.audience}\n`);
    if (selected.clientIds.length) {
      process.stdout.write(
        `Remove ${selected.audience} from clients ${selected.clientIds.join(", ")} before their next sign-in.\n`,
      );
    }
  } finally {
    rl.close();
  }
}

export async function runMenu(db: Database): Promise<void> {
  requireTty();
  for (;;) {
    process.stdout.write(
      "\nbasis-auth administration\n" +
        "Clients\n" +
        "  1) List clients\n" +
        "  2) Add client\n" +
        "  3) Edit client\n" +
        "  4) Rotate client secret\n" +
        "  5) Remove client\n" +
        "Resources\n" +
        "  6) List resources\n" +
        "  7) Add resource\n" +
        "  8) Edit resource\n" +
        "  9) Rotate resource secret\n" +
        " 10) Delete resource\n" +
        " 11) Quit\n",
    );
    const rl = createInterface({ input, output });
    let choice: string;
    try {
      choice = (await rl.question("Choice: ")).trim();
    } finally {
      rl.close();
    }
    if (choice === "1") await listedOrEmpty(db);
    else if (choice === "2") await runAddFlow(db);
    else if (choice === "3") await runEditFlow(db);
    else if (choice === "4") await runRotateClientSecretFlow(db);
    else if (choice === "5") await runRemoveFlow(db);
    else if (choice === "6") await runListResourcesFlow(db);
    else if (choice === "7") await runRegisterResourceFlow(db);
    else if (choice === "8") await runEditResourceFlow(db);
    else if (choice === "9") await runRotateResourceSecretFlow(db);
    else if (choice === "10") await runDeleteResourceFlow(db);
    else if (choice === "11" || /^q(uit)?$/i.test(choice)) return;
    else process.stdout.write("Enter 1-11.\n");
  }
}

if (/clients\.(ts|js)$/.test(process.argv[1] ?? "")) {
  const { db, pool } = requireDatabase();
  try {
    await runMenu(db);
  } finally {
    await pool.end();
  }
}
