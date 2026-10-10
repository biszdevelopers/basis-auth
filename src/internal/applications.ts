import { randomBytes, randomUUID } from "node:crypto";
import { DelegatedPermissionSet, type Permission } from "@basis/schema/permissions";
import { eq, inArray, sql } from "drizzle-orm";
import { isEphemeralLocalhostRedirectUri } from "../config.js";
import type { Database } from "../database/client.js";
import { oidcClientOrganizations, oidcClients, organizations, resourceServers, users } from "../database/schema.js";
import { hashClientSecret, type ClientOwner, type StoredClientMetadata } from "../database/seed.js";

export const applicationPermissions = {
  read: "BiszPortal.Applications.read",
  create: "BiszPortal.Applications.create",
  update: "BiszPortal.Applications.update",
  delete: "BiszPortal.Applications.delete",
  owners: "BiszPortal.ApplicationOwners.manage",
  resources: "BiszPortal.ApplicationResources.manage",
  scopes: "BiszPortal.ApplicationScopes.manage",
  permissions: "BiszPortal.ApplicationPermissions.manage",
  redirects: "BiszPortal.ApplicationRedirectUris.manage",
  credentials: "BiszPortal.ApplicationCredentials.manage",
} as const;

export type ApplicationActor = { id: string; permissions: string[] };
export type ApplicationSettingsInput = {
  name: string;
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  organizationIds: string[];
};

export class InternalApplicationError extends Error {
  constructor(readonly status: 400 | 403 | 404 | 409, readonly code: string, message: string) {
    super(message);
  }
}

function metadataOf(row: typeof oidcClients.$inferSelect): StoredClientMetadata & { resourceScopes: Record<string, string[]> } {
  const metadata = row.metadata as Partial<StoredClientMetadata>;
  const scopes = Array.isArray(metadata.scopes) ? metadata.scopes : [];
  const resourceScopes = metadata.resourceScopes && typeof metadata.resourceScopes === "object"
    ? metadata.resourceScopes
    : row.resources.length === 1 ? { [row.resources[0]!]: scopes } : {};
  return {
    ...metadata,
    name: typeof metadata.name === "string" ? metadata.name : row.clientId,
    public: typeof metadata.public === "boolean" ? metadata.public : row.secretHash === null,
    redirectUris: Array.isArray(metadata.redirectUris) ? metadata.redirectUris : [],
    scopes,
    resourceScopes,
    permissions: metadata.permissions ?? {},
    owners: Array.isArray(metadata.owners) ? metadata.owners : [],
  } as StoredClientMetadata & { resourceScopes: Record<string, string[]> };
}

function hasPermission(actor: ApplicationActor, permission: string) {
  return new DelegatedPermissionSet(actor.permissions).has(permission as Permission);
}

function requireGlobal(actor: ApplicationActor, permission: string) {
  if (!hasPermission(actor, permission)) {
    throw new InternalApplicationError(403, "forbidden", "The required application permission is missing");
  }
}

function requireAdmin(role: ClientOwner["role"]) {
  if (role !== "role.ADMIN") throw new InternalApplicationError(403, "forbidden", "An application admin is required");
}

function unique(values: string[]) {
  return [...new Set(values)];
}

function generatedSecret() {
  return `sk-${randomBytes(32).toString("base64url")}`;
}

function validRedirectUri(value: string, isPublic: boolean) {
  if (isEphemeralLocalhostRedirectUri(value)) return isPublic;
  try { new URL(value); return true; } catch { return false; }
}

export function createInternalApplicationService(db: Database, issuer: string, invalidateClient: (clientId: string) => void) {
  async function clientRow(clientId: string) {
    const [row] = await db.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
    return row;
  }

  async function accessible(clientId: string, actor: ApplicationActor, permission: string = applicationPermissions.read) {
    requireGlobal(actor, permission);
    const row = await clientRow(clientId);
    if (!row) throw new InternalApplicationError(404, "not_found", "Application not found");
    const metadata = metadataOf(row);
    const membership = metadata.owners.find((owner) => owner.id === actor.id);
    if (!membership) throw new InternalApplicationError(404, "not_found", "Application not found");
    return { row, metadata, membership };
  }

  async function organizationRows(organizationIds: string[]) {
    const rows = await db.select().from(organizations).where(inArray(organizations.organizationId, organizationIds));
    if (rows.length !== organizationIds.length) throw new InternalApplicationError(400, "invalid_organizations", "One or more organizations do not exist");
    return rows;
  }

  async function saveMetadata(clientId: string, metadata: StoredClientMetadata) {
    await db.update(oidcClients).set({ metadata, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function list(actor: ApplicationActor) {
    requireGlobal(actor, applicationPermissions.read);
    const rows = await db.select().from(oidcClients);
    return rows.map((row) => ({ row, metadata: metadataOf(row) }))
      .filter(({ metadata }) => metadata.owners.some((owner) => owner.id === actor.id))
      .map(({ row, metadata }) => ({ clientId: row.clientId, name: metadata.name }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async function listOrganizations(actor: ApplicationActor) {
    requireGlobal(actor, applicationPermissions.read);
    return db.select({ organizationId: organizations.organizationId, firstParty: organizations.firstParty }).from(organizations);
  }

  async function createApplication(actor: ApplicationActor, input: ApplicationSettingsInput & { public: boolean; redirectUris: string[] }) {
    requireGlobal(actor, applicationPermissions.create);
    requireGlobal(actor, applicationPermissions.read);
    if (input.redirectUris.some((uri) => !validRedirectUri(uri, input.public))) {
      throw new InternalApplicationError(400, "invalid_redirect_uris", "One or more redirect URIs are invalid for this client type");
    }
    const linkedOrganizations = await organizationRows(unique(input.organizationIds));
    const clientId = randomUUID();
    const resourceId = `urn:basis:api:${clientId}`;
    const clientSecret = input.public ? null : generatedSecret();
    const metadata: StoredClientMetadata = {
      name: input.name,
      owners: [{ id: actor.id, role: "role.ADMIN" }],
      redirectUris: unique(input.redirectUris),
      public: input.public,
      scopes: [],
      resourceScopes: { [resourceId]: [] },
      permissions: {},
    };
    await db.transaction(async (tx) => {
      await tx.insert(resourceServers).values({ audience: resourceId, name: `${input.name} API`, scopes: [] });
      await tx.insert(oidcClients).values({
        clientId,
        metadata,
        secretHash: clientSecret ? await hashClientSecret(clientSecret) : null,
        resources: [resourceId],
        requireConsent: input.requireConsent,
        filterMode: input.filterMode,
        filterContent: input.filterMode ? unique(input.filterContent.map((value) => value.trim().toLowerCase())) : [],
      });
      await tx.insert(oidcClientOrganizations).values(linkedOrganizations.map((organization) => ({ clientId, organizationId: organization.id })));
    });
    return { clientId, clientSecret };
  }

  async function detail(clientId: string, actor: ApplicationActor) {
    const { row, metadata, membership } = await accessible(clientId, actor);
    const [resources, allClients, linkedOrganizations, availableOrganizations] = await Promise.all([
      db.select().from(resourceServers).where(inArray(resourceServers.audience, row.resources)),
      db.select({ clientId: oidcClients.clientId, resources: oidcClients.resources }).from(oidcClients),
      db.select({ organizationId: organizations.organizationId }).from(oidcClientOrganizations)
        .innerJoin(organizations, eq(oidcClientOrganizations.organizationId, organizations.id))
        .where(eq(oidcClientOrganizations.clientId, clientId)),
      db.select({ organizationId: organizations.organizationId, firstParty: organizations.firstParty }).from(organizations),
    ]);
    const ownerIds = metadata.owners.map((owner) => owner.id);
    const people = ownerIds.length ? await db.select({
      id: users.id,
      displayName: users.displayName,
      disabled: users.disabled,
      hasPicture: sql<boolean>`${users.picture} is not null and ${users.pictureContentType} is not null`,
    }).from(users).where(inArray(users.id, ownerIds)) : [];
    const peopleById = new Map(people.map((person) => [person.id, person]));
    return {
      clientId: row.clientId,
      authorizationEndpoint: `${issuer}/oauth/authorize`,
      name: metadata.name,
      public: metadata.public,
      requireConsent: row.requireConsent,
      filterMode: row.filterMode,
      filterContent: row.filterContent,
      organizationIds: linkedOrganizations.map((organization) => organization.organizationId),
      availableOrganizations,
      updatedAt: row.updatedAt.toISOString(),
      role: membership.role,
      capabilities: {
        update: membership.role === "role.ADMIN" && hasPermission(actor, applicationPermissions.update),
        delete: membership.role === "role.ADMIN" && hasPermission(actor, applicationPermissions.delete),
        manageOwners: membership.role === "role.ADMIN" && hasPermission(actor, applicationPermissions.owners),
        manageResources: hasPermission(actor, applicationPermissions.resources),
        manageScopes: hasPermission(actor, applicationPermissions.scopes),
        managePermissions: hasPermission(actor, applicationPermissions.permissions),
        manageRedirectUris: hasPermission(actor, applicationPermissions.redirects),
        manageCredentials: membership.role === "role.ADMIN" && hasPermission(actor, applicationPermissions.credentials),
      },
      owners: metadata.owners.map((owner) => {
        const person = peopleById.get(owner.id);
        return { userId: owner.id, displayName: person?.displayName?.trim() || "Unknown user", image: person?.hasPicture ? `${issuer}/api/picture/${owner.id}` : null, disabled: person?.disabled ?? true, role: owner.role };
      }),
      resources: resources.map((resource) => ({
        resourceId: resource.audience,
        name: resource.name,
        availableScopes: resource.scopes,
        grantedScopes: metadata.resourceScopes[resource.audience] ?? [],
        claimCount: allClients.filter((client) => client.resources.includes(resource.audience)).length,
      })),
      availableResources: (await db.select().from(resourceServers)).map((resource) => ({ resourceId: resource.audience, name: resource.name, availableScopes: resource.scopes })),
      permissions: Object.entries(metadata.permissions).map(([permission, description]) => ({ permission, description })),
      redirectUris: metadata.redirectUris,
    };
  }

  async function updateApplication(clientId: string, actor: ApplicationActor, input: ApplicationSettingsInput) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.update);
    requireAdmin(membership.role);
    const linkedOrganizations = await organizationRows(unique(input.organizationIds));
    await db.transaction(async (tx) => {
      await tx.update(oidcClients).set({
        metadata: { ...metadata, name: input.name },
        requireConsent: input.requireConsent,
        filterMode: input.filterMode,
        filterContent: input.filterMode ? unique(input.filterContent.map((value) => value.trim().toLowerCase())) : [],
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
      await tx.delete(oidcClientOrganizations).where(eq(oidcClientOrganizations.clientId, clientId));
      await tx.insert(oidcClientOrganizations).values(linkedOrganizations.map((organization) => ({ clientId, organizationId: organization.id })));
    });
    invalidateClient(clientId);
  }

  async function deleteApplication(clientId: string, actor: ApplicationActor) {
    const { membership } = await accessible(clientId, actor, applicationPermissions.delete);
    requireAdmin(membership.role);
    await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function rotateSecret(clientId: string, actor: ApplicationActor) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.credentials);
    requireAdmin(membership.role);
    if (metadata.redirectUris.some(isEphemeralLocalhostRedirectUri)) {
      throw new InternalApplicationError(409, "invalid_client_type", "Remove ephemeral localhost redirect URIs before making this client confidential");
    }
    const clientSecret = generatedSecret();
    await db.update(oidcClients).set({ secretHash: await hashClientSecret(clientSecret), metadata: { ...metadata, public: false }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
    return clientSecret;
  }

  async function removeSecret(clientId: string, actor: ApplicationActor) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.credentials);
    requireAdmin(membership.role);
    await db.update(oidcClients).set({ secretHash: null, metadata: { ...metadata, public: true }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function addOwner(clientId: string, actor: ApplicationActor, userId: string, role: ClientOwner["role"]) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    if (metadata.owners.some((owner) => owner.id === userId)) throw new InternalApplicationError(409, "conflict", "User is already a member");
    const [person] = await db.select({ id: users.id, disabled: users.disabled }).from(users).where(eq(users.id, userId)).limit(1);
    if (!person || person.disabled) throw new InternalApplicationError(400, "invalid_user", "User does not exist or is disabled");
    await saveMetadata(clientId, { ...metadata, owners: [...metadata.owners, { id: userId, role }] });
  }

  async function updateOwner(clientId: string, actor: ApplicationActor, userId: string, role: ClientOwner["role"]) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    const target = metadata.owners.find((owner) => owner.id === userId);
    if (!target) throw new InternalApplicationError(404, "not_found", "Application member not found");
    if (target.role === "role.ADMIN" && role !== "role.ADMIN" && metadata.owners.filter((owner) => owner.role === "role.ADMIN").length === 1) throw new InternalApplicationError(409, "last_admin", "The final application admin cannot be demoted");
    await saveMetadata(clientId, { ...metadata, owners: metadata.owners.map((owner) => owner.id === userId ? { ...owner, role } : owner) });
  }

  async function removeOwner(clientId: string, actor: ApplicationActor, userId: string) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    const target = metadata.owners.find((owner) => owner.id === userId);
    if (!target) throw new InternalApplicationError(404, "not_found", "Application member not found");
    if (target.role === "role.ADMIN" && metadata.owners.filter((owner) => owner.role === "role.ADMIN").length === 1) throw new InternalApplicationError(409, "last_admin", "The final application admin cannot be removed");
    await saveMetadata(clientId, { ...metadata, owners: metadata.owners.filter((owner) => owner.id !== userId) });
  }

  async function attachResource(clientId: string, actor: ApplicationActor, resourceId: string) {
    const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources);
    if (row.resources.includes(resourceId)) throw new InternalApplicationError(409, "conflict", "Resource is already attached");
    const [resource] = await db.select().from(resourceServers).where(eq(resourceServers.audience, resourceId)).limit(1);
    if (!resource) throw new InternalApplicationError(404, "resource_not_found", "Resource not found");
    await db.update(oidcClients).set({ resources: [...row.resources, resourceId], metadata: { ...metadata, resourceScopes: { ...metadata.resourceScopes, [resourceId]: [] } }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function createResource(clientId: string, actor: ApplicationActor, input: { resourceId: string; name: string; availableScopes: string[] }) {
    const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources);
    const [existing] = await db.select().from(resourceServers).where(eq(resourceServers.audience, input.resourceId)).limit(1);
    if (existing) throw new InternalApplicationError(409, "conflict", "Resource already exists");
    await db.transaction(async (tx) => {
      await tx.insert(resourceServers).values({ audience: input.resourceId, name: input.name, scopes: unique(input.availableScopes) });
      await tx.update(oidcClients).set({ resources: [...row.resources, input.resourceId], metadata: { ...metadata, resourceScopes: { ...metadata.resourceScopes, [input.resourceId]: [] } }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function updateResource(clientId: string, actor: ApplicationActor, input: { resourceId: string; name: string; availableScopes: string[] }) {
    const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources);
    if (!row.resources.includes(input.resourceId)) throw new InternalApplicationError(404, "not_found", "Resource not found");
    const clients = await db.select({ resources: oidcClients.resources }).from(oidcClients);
    if (clients.filter((client) => client.resources.includes(input.resourceId)).length > 1) throw new InternalApplicationError(409, "resource_shared", "Shared resources cannot be edited from an application");
    const availableScopes = unique(input.availableScopes);
    const granted = (metadata.resourceScopes[input.resourceId] ?? []).filter((scope) => availableScopes.includes(scope));
    const resourceScopes = { ...metadata.resourceScopes, [input.resourceId]: granted };
    await db.transaction(async (tx) => {
      await tx.update(resourceServers).set({ name: input.name, scopes: availableScopes, updatedAt: new Date() }).where(eq(resourceServers.audience, input.resourceId));
      await tx.update(oidcClients).set({ metadata: { ...metadata, resourceScopes, scopes: unique(Object.values(resourceScopes).flat()) }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function removeResource(clientId: string, actor: ApplicationActor, resourceId: string, deleteDefinition: boolean) {
    const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources);
    if (!row.resources.includes(resourceId)) throw new InternalApplicationError(404, "not_found", "Resource not found");
    if (row.resources.length === 1) throw new InternalApplicationError(409, "last_resource", "An application must retain at least one resource");
    const clients = await db.select({ resources: oidcClients.resources }).from(oidcClients);
    const claims = clients.filter((client) => client.resources.includes(resourceId));
    if (deleteDefinition && claims.length > 1) throw new InternalApplicationError(409, "resource_shared", "Shared resources cannot be deleted");
    const resourceScopes = { ...metadata.resourceScopes };
    delete resourceScopes[resourceId];
    await db.transaction(async (tx) => {
      await tx.update(oidcClients).set({ resources: row.resources.filter((resource) => resource !== resourceId), metadata: { ...metadata, resourceScopes, scopes: unique(Object.values(resourceScopes).flat()) }, updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
      if (deleteDefinition) await tx.delete(resourceServers).where(eq(resourceServers.audience, resourceId));
    });
    invalidateClient(clientId);
  }

  async function updateScopes(clientId: string, actor: ApplicationActor, input: Record<string, string[]>) {
    const { row, metadata } = await accessible(clientId, actor, applicationPermissions.scopes);
    if (Object.keys(input).some((resource) => !row.resources.includes(resource))) throw new InternalApplicationError(400, "invalid_scopes", "Scopes contain an unclaimed resource");
    const resources = await db.select().from(resourceServers).where(inArray(resourceServers.audience, row.resources));
    for (const resource of resources) if ((input[resource.audience] ?? []).some((scope) => !resource.scopes.includes(scope))) throw new InternalApplicationError(400, "invalid_scopes", `Unsupported scope for ${resource.audience}`);
    const resourceScopes = Object.fromEntries(row.resources.map((resource) => [resource, unique(input[resource] ?? [])]));
    await saveMetadata(clientId, { ...metadata, resourceScopes, scopes: unique(Object.values(resourceScopes).flat()) });
  }

  async function createPermission(clientId: string, actor: ApplicationActor, permission: string, description: string) {
    const { metadata } = await accessible(clientId, actor, applicationPermissions.permissions);
    if (permission in metadata.permissions) throw new InternalApplicationError(409, "conflict", "Permission definition already exists");
    await saveMetadata(clientId, { ...metadata, permissions: { ...metadata.permissions, [permission]: description } });
  }

  async function updatePermission(clientId: string, actor: ApplicationActor, permission: string, description: string) {
    const { metadata } = await accessible(clientId, actor, applicationPermissions.permissions);
    if (!(permission in metadata.permissions)) throw new InternalApplicationError(404, "not_found", "Permission definition not found");
    await saveMetadata(clientId, { ...metadata, permissions: { ...metadata.permissions, [permission]: description } });
  }

  async function deletePermission(clientId: string, actor: ApplicationActor, permission: string) {
    const { metadata } = await accessible(clientId, actor, applicationPermissions.permissions);
    if (!(permission in metadata.permissions)) throw new InternalApplicationError(404, "not_found", "Permission definition not found");
    const permissions = { ...metadata.permissions };
    delete permissions[permission];
    await saveMetadata(clientId, { ...metadata, permissions });
  }

  async function updateRedirectUris(clientId: string, actor: ApplicationActor, redirectUris: string[]) {
    const { metadata } = await accessible(clientId, actor, applicationPermissions.redirects);
    const values = unique(redirectUris);
    if (!values.length || values.length !== redirectUris.length || values.some((uri) => !validRedirectUri(uri, metadata.public))) throw new InternalApplicationError(400, "invalid_redirect_uris", "Redirect URIs must be unique and valid for this client type");
    await saveMetadata(clientId, { ...metadata, redirectUris: values });
  }

  return { list, listOrganizations, detail, createApplication, updateApplication, deleteApplication, rotateSecret, removeSecret, addOwner, updateOwner, removeOwner, attachResource, createResource, updateResource, removeResource, updateScopes, createPermission, updatePermission, deletePermission, updateRedirectUris };
}

export type InternalApplicationService = ReturnType<typeof createInternalApplicationService>;
