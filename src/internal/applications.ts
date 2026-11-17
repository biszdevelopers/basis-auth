import { randomUUID } from "node:crypto";
import { DelegatedPermissionSet, type Permission } from "@basis/schema/permissions";
import { and, eq, inArray, sql } from "drizzle-orm";
import { isEphemeralLocalhostRedirectUri } from "../config.js";
import type { Database } from "../database/client.js";
import { replaceResourceScopes, resourceWithScopeMappings, resourceWithScopes } from "../database/resource-scopes.js";
import { defaultPermissions, oidcClientOrganizations, oidcClients, oidcPermissions, organizations, resourceServers, users } from "../database/schema.js";
import { generateSecret, hashClientSecret, hashNewResourceSecret, type ClientOwner, type StoredClientMetadata } from "../database/seed.js";
import { scopesCover } from "../oauth/scopes.js";
import { createBackchannelVerifier } from "./backchannel.js";

export const applicationPermissions = {
  create: "BiszPortal.Applications.create",
  owners: "BiszPortal.ApplicationOwners.manage",
  resources: "BiszPortal.ApplicationResources.manage",
  permissions: "BiszPortal.ApplicationPermissions.manage",
  redirects: "BiszPortal.ApplicationRedirectUris.manage",
  credentials: "BiszPortal.ApplicationCredentials.manage",
} as const;

export type ApplicationActor = { id: string; permissions: string[] };
type ScopedAction = "read" | "update" | "delete";
type ResourceRow = typeof resourceServers.$inferSelect;
type ResourceWithScopes = ResourceRow & { scopes: string[] };
type ResourceDefinitionInput = {
  resourceId: string;
  name: string;
  availableScopes: string[];
  upstreamScopes?: Record<string, string | null>;
};
type ResourceScopeChange =
  | { action: "add"; scope: string; upstreamScope?: string | null }
  | { action: "update"; scope: string; upstreamScope: string | null }
  | { action: "remove"; scope: string };
type Transaction = Parameters<Parameters<Database["transaction"]>[0]>[0];
export type ApplicationSettingsInput = {
  name: string;
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  organizationIds: string[];
};

export class InternalApplicationError extends Error {
  constructor(readonly status: 400 | 403 | 404 | 409 | 502 | 504, readonly code: string, message: string) {
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
    owners: Array.isArray(metadata.owners) ? metadata.owners : [],
  } as StoredClientMetadata & { resourceScopes: Record<string, string[]> };
}

function assignedScopes(metadata: ReturnType<typeof metadataOf>, resourceId: string) {
  return Object.hasOwn(metadata.resourceScopes, resourceId)
    ? metadata.resourceScopes[resourceId]!
    : metadata.scopes;
}

function hasPermission(actor: ApplicationActor, permission: string) {
  return new DelegatedPermissionSet(actor.permissions).has(permission as Permission);
}

function requireGlobal(actor: ApplicationActor, permission: string) {
  if (!hasPermission(actor, permission)) {
    throw new InternalApplicationError(403, "forbidden", "The required application permission is missing");
  }
}

function hasScopedPermission(
  actor: ApplicationActor,
  section: "Applications" | "Resources",
  action: ScopedAction,
  own: boolean,
) {
  return hasPermission(actor, `BiszPortal.${section}.${action}.${own ? "me" : "others"}`);
}

function requireScopedAccess(
  actor: ApplicationActor,
  section: "Applications" | "Resources",
  action: ScopedAction,
) {
  if (!hasScopedPermission(actor, section, action, true) && !hasScopedPermission(actor, section, action, false)) {
    throw new InternalApplicationError(403, "forbidden", `The required ${section.toLowerCase()} permission is missing`);
  }
}

function canAccessResource(actor: ApplicationActor, resource: ResourceRow, action: ScopedAction) {
  return hasScopedPermission(actor, "Resources", action, resource.createdBy === actor.id);
}

function requireResourceAccess<T extends ResourceRow>(actor: ApplicationActor, resource: T | undefined, action: ScopedAction) {
  if (!resource || !canAccessResource(actor, resource, "read")) {
    throw new InternalApplicationError(404, "resource_not_found", "Resource not found");
  }
  if (!canAccessResource(actor, resource, action)) {
    throw new InternalApplicationError(403, "forbidden", "You do not have permission for this resource action");
  }
  return resource;
}

function requireAdmin(role: ClientOwner["role"]) {
  if (role !== "role.ADMIN") throw new InternalApplicationError(403, "forbidden", "An application admin is required");
}

function unique(values: string[]) {
  return [...new Set(values)];
}

function validRedirectUri(value: string, isPublic: boolean) {
  if (isEphemeralLocalhostRedirectUri(value)) return isPublic;
  try {
    const url = new URL(value);
    return (url.protocol === "http:" || url.protocol === "https:") &&
      !url.username && !url.password;
  } catch {
    return false;
  }
}

export function createInternalApplicationService(
  db: Database,
  issuer: string,
  invalidateClient: (clientId: string) => void,
  backchannel = createBackchannelVerifier(db),
) {
  async function clientRow(clientId: string, database: Database | Transaction = db) {
    const [row] = await database.select().from(oidcClients).where(eq(oidcClients.clientId, clientId)).limit(1);
    return row;
  }

  async function readApplication(clientId: string, actor: ApplicationActor, action: ScopedAction = "read", database: Database | Transaction = db) {
    requireScopedAccess(actor, "Applications", action);
    const row = await clientRow(clientId, database);
    if (!row) throw new InternalApplicationError(404, "not_found", "Application not found");
    const metadata = metadataOf(row);
    const membership = metadata.owners.find((owner) => owner.id === actor.id);
    if (!hasScopedPermission(actor, "Applications", action, Boolean(membership))) {
      throw new InternalApplicationError(404, "not_found", "Application not found");
    }
    if (action !== "read" && membership) requireAdmin(membership.role);
    return { row, metadata, membership };
  }

  async function accessible(clientId: string, actor: ApplicationActor, permission: string, database: Database | Transaction = db) {
    requireGlobal(actor, permission);
    const { row, metadata, membership } = await readApplication(clientId, actor, "read", database);
    if (!membership) throw new InternalApplicationError(404, "not_found", "Application not found");
    return { row, metadata, membership };
  }

  async function organizationRows(organizationIds: string[]) {
    const rows = await db.select().from(organizations).where(inArray(organizations.organizationId, organizationIds));
    if (rows.length !== organizationIds.length) throw new InternalApplicationError(400, "invalid_organizations", "One or more organizations do not exist");
    return rows;
  }

  function metadataPatch(fields: Partial<StoredClientMetadata>) {
    return sql`${oidcClients.metadata} || ${JSON.stringify(fields)}::jsonb`;
  }

  async function saveMetadata(clientId: string, fields: Partial<StoredClientMetadata>) {
    await db.update(oidcClients).set({ metadata: metadataPatch(fields), updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function list(actor: ApplicationActor) {
    requireScopedAccess(actor, "Applications", "read");
    const rows = await db.select().from(oidcClients);
    return rows.map((row) => ({ row, metadata: metadataOf(row) }))
      .filter(({ metadata }) => hasScopedPermission(actor, "Applications", "read", metadata.owners.some((owner) => owner.id === actor.id)))
      .map(({ row, metadata }) => ({ clientId: row.clientId, name: metadata.name }))
      .sort((a, b) => a.name.localeCompare(b.name));
  }

  async function listOrganizations(actor: ApplicationActor) {
    requireScopedAccess(actor, "Applications", "read");
    return db.select({ organizationId: organizations.organizationId, firstParty: organizations.firstParty }).from(organizations);
  }

  async function createApplication(actor: ApplicationActor, input: ApplicationSettingsInput & { public: boolean; redirectUris: string[] }) {
    requireGlobal(actor, applicationPermissions.create);
    requireGlobal(actor, "BiszPortal.Applications.read.me");
    if (input.redirectUris.some((uri) => !validRedirectUri(uri, input.public))) {
      throw new InternalApplicationError(400, "invalid_redirect_uris", "One or more redirect URIs are invalid for this client type");
    }
    const linkedOrganizations = await organizationRows(unique(input.organizationIds));
    const clientId = randomUUID();
    const resourceId = `urn:basis:api:${clientId}`;
    const clientSecret = input.public ? null : generateSecret();
    const resourceSecretHash = await hashNewResourceSecret();
    const metadata: StoredClientMetadata = {
      name: input.name,
      owners: [{ id: actor.id, role: "role.ADMIN" }],
      redirectUris: unique(input.redirectUris),
      public: input.public,
      scopes: [],
      resourceScopes: { [resourceId]: [] },
    };
    await db.transaction(async (tx) => {
      await tx.insert(resourceServers).values({
        audience: resourceId, name: `${input.name} API`, createdBy: actor.id, secretHash: resourceSecretHash,
      });
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
    const { row, metadata, membership } = await readApplication(clientId, actor);
    const own = Boolean(membership);
    const isAdmin = membership?.role === "role.ADMIN";
    const [resources, allClients, linkedOrganizations, availableOrganizations, permissions, defaults, availableResources] = await Promise.all([
      db.select(resourceWithScopeMappings).from(resourceServers).where(inArray(resourceServers.audience, row.resources)),
      db.select({ clientId: oidcClients.clientId, resources: oidcClients.resources }).from(oidcClients),
      db.select({ organizationId: organizations.organizationId }).from(oidcClientOrganizations)
        .innerJoin(organizations, eq(oidcClientOrganizations.organizationId, organizations.id))
        .where(eq(oidcClientOrganizations.clientId, clientId)),
      db.select({ organizationId: organizations.organizationId, firstParty: organizations.firstParty }).from(organizations),
      db.select({ permission: oidcPermissions.permission, description: oidcPermissions.description })
        .from(oidcPermissions).where(eq(oidcPermissions.clientId, clientId)),
      db.select({ permission: defaultPermissions.permission })
        .from(defaultPermissions).where(eq(defaultPermissions.applicationId, clientId)),
      db.select(resourceWithScopeMappings).from(resourceServers),
    ]);
    const claimsByAudience = new Map<string, number>();
    for (const client of allClients) {
      for (const audience of client.resources ?? []) {
        claimsByAudience.set(audience, (claimsByAudience.get(audience) ?? 0) + 1);
      }
    }
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
      permissionCatalogVersion: row.permissionCatalogVersion,
      role: membership?.role ?? null,
      capabilities: {
        update: (!own || isAdmin) && hasScopedPermission(actor, "Applications", "update", own),
        delete: (!own || isAdmin) && hasScopedPermission(actor, "Applications", "delete", own),
        manageOwners: isAdmin && hasPermission(actor, applicationPermissions.owners),
        manageResources: own && hasPermission(actor, applicationPermissions.resources),
        manageScopes: own && hasPermission(actor, applicationPermissions.resources),
        managePermissions: own && hasPermission(actor, applicationPermissions.permissions),
        manageRedirectUris: own && hasPermission(actor, applicationPermissions.redirects),
        manageCredentials: isAdmin && hasPermission(actor, applicationPermissions.credentials),
      },
      owners: metadata.owners.map((owner) => {
        const person = peopleById.get(owner.id);
        return { userId: owner.id, displayName: person?.displayName?.trim() || "Unknown user", image: person?.hasPicture ? `${issuer}/api/picture/${owner.id}` : null, disabled: person?.disabled ?? true, role: owner.role };
      }),
      resources: resources.filter((resource) => canAccessResource(actor, resource, "read")).map((resource) => ({
        resourceId: resource.audience,
        name: resource.name,
        availableScopes: resource.scopes,
        upstreamScopes: resource.upstreamScopes,
        grantedScopes: assignedScopes(metadata, resource.audience),
        claimCount: claimsByAudience.get(resource.audience) ?? 0,
        canUpdate: canAccessResource(actor, resource, "update"),
        canDelete: canAccessResource(actor, resource, "delete"),
      })),
      availableResources: availableResources.filter((resource) => canAccessResource(actor, resource, "read"))
        .map((resource) => ({
          resourceId: resource.audience,
          name: resource.name,
          availableScopes: resource.scopes,
          upstreamScopes: resource.upstreamScopes,
        })),
      permissions,
      defaultPermissions: defaults.map(({ permission }) => permission).sort(),
      redirectUris: metadata.redirectUris,
    };
  }

  async function updateApplication(clientId: string, actor: ApplicationActor, input: ApplicationSettingsInput) {
    await readApplication(clientId, actor);
    await readApplication(clientId, actor, "update");
    const linkedOrganizations = await organizationRows(unique(input.organizationIds));
    await db.transaction(async (tx) => {
      await tx.update(oidcClients).set({
        metadata: metadataPatch({ name: input.name }),
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
    requireScopedAccess(actor, "Applications", "delete");
    await editResourceAssignments(async (tx) => {
      await readApplication(clientId, actor, "delete", tx);
      await tx.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function rotateSecret(clientId: string, actor: ApplicationActor) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.credentials);
    requireAdmin(membership.role);
    if (metadata.redirectUris.some(isEphemeralLocalhostRedirectUri)) {
      throw new InternalApplicationError(409, "invalid_client_type", "Remove ephemeral localhost redirect URIs before making this client confidential");
    }
    const clientSecret = generateSecret();
    await db.update(oidcClients).set({ secretHash: await hashClientSecret(clientSecret), metadata: metadataPatch({ public: false }), updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
    return clientSecret;
  }

  async function removeSecret(clientId: string, actor: ApplicationActor) {
    const { membership } = await accessible(clientId, actor, applicationPermissions.credentials);
    requireAdmin(membership.role);
    await db.update(oidcClients).set({ secretHash: null, metadata: metadataPatch({ public: true }), updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    invalidateClient(clientId);
  }

  async function addOwner(clientId: string, actor: ApplicationActor, userId: string, role: ClientOwner["role"]) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    if (metadata.owners.some((owner) => owner.id === userId)) throw new InternalApplicationError(409, "conflict", "User is already a member");
    const [person] = await db.select({ id: users.id, disabled: users.disabled }).from(users).where(eq(users.id, userId)).limit(1);
    if (!person || person.disabled) throw new InternalApplicationError(400, "invalid_user", "User does not exist or is disabled");
    await saveMetadata(clientId, { owners: [...metadata.owners, { id: userId, role }] });
  }

  async function updateOwner(clientId: string, actor: ApplicationActor, userId: string, role: ClientOwner["role"]) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    const target = metadata.owners.find((owner) => owner.id === userId);
    if (!target) throw new InternalApplicationError(404, "not_found", "Application member not found");
    if (target.role === "role.ADMIN" && role !== "role.ADMIN" && metadata.owners.filter((owner) => owner.role === "role.ADMIN").length === 1) throw new InternalApplicationError(409, "last_admin", "The final application admin cannot be demoted");
    await saveMetadata(clientId, { owners: metadata.owners.map((owner) => owner.id === userId ? { ...owner, role } : owner) });
  }

  async function removeOwner(clientId: string, actor: ApplicationActor, userId: string) {
    const { metadata, membership } = await accessible(clientId, actor, applicationPermissions.owners);
    requireAdmin(membership.role);
    const target = metadata.owners.find((owner) => owner.id === userId);
    if (!target) throw new InternalApplicationError(404, "not_found", "Application member not found");
    if (target.role === "role.ADMIN" && metadata.owners.filter((owner) => owner.role === "role.ADMIN").length === 1) throw new InternalApplicationError(409, "last_admin", "The final application admin cannot be removed");
    await saveMetadata(clientId, { owners: metadata.owners.filter((owner) => owner.id !== userId) });
  }

  async function resourceRow(resourceId: string, database: Database | Transaction = db) {
    const [resource] = await database.select(resourceWithScopeMappings).from(resourceServers)
      .where(eq(resourceServers.audience, resourceId)).limit(1);
    return resource;
  }

  async function lockResourceForScopeUpdate(tx: Transaction, resourceId: string, actor: ApplicationActor) {
    const [resource] = await tx.select().from(resourceServers).where(eq(resourceServers.audience, resourceId)).for("update");
    requireResourceAccess(actor, resource, "update");
    return (await resourceRow(resourceId, tx))!;
  }

  function editResourceAssignments<T>(operation: (tx: Transaction) => Promise<T>) {
    return db.transaction(async (tx) => {
      // Assignment writes and definition checks span both tables.
      await tx.execute(sql`select pg_advisory_xact_lock(176436781, 1)`);
      return operation(tx);
    });
  }

  function attachedClients(tx: Transaction, resourceId: string) {
    return tx.select().from(oidcClients)
      .where(sql`${oidcClients.resources} @> ${JSON.stringify([resourceId])}::jsonb`);
  }

  async function assertScopesCoverAssignments(tx: Transaction, resource: ResourceWithScopes, nextScopes: string[]) {
    const nextSet = new Set(nextScopes);
    const removedScopes = new Set(resource.scopes.filter((scope) => !nextSet.has(scope)));
    if (!removedScopes.size) return;
    const clients = await attachedClients(tx, resource.audience);
    for (const client of clients) {
      const metadata = metadataOf(client);
      const currentAssignments = assignedScopes(metadata, resource.audience)
        .filter((scope) => scopesCover(resource.scopes, [scope]));
      if (currentAssignments.some((scope) => removedScopes.has(scope)) || !scopesCover(nextScopes, currentAssignments)) {
        throw new InternalApplicationError(409, "scope_in_use", "Remove the scope from the attached applications before deleting it from this resource");
      }
    }
  }

  function resourceView(resource: ResourceWithScopes & { upstreamScopes: Record<string, string | null> }, actor: ApplicationActor) {
    return {
      resourceId: resource.audience,
      name: resource.name,
      availableScopes: resource.scopes,
      upstreamScopes: resource.upstreamScopes,
      backchannelLogoutUris: resource.backchannelLogoutUris,
      backchannelLogoutUri: resource.backchannelLogoutUris[0] ?? null,
      capabilities: {
        update: canAccessResource(actor, resource, "update"),
        delete: canAccessResource(actor, resource, "delete"),
      },
    };
  }

  async function listResources(actor: ApplicationActor) {
    requireScopedAccess(actor, "Resources", "read");
    const resources = await db.select().from(resourceServers);
    return resources.filter((resource) => canAccessResource(actor, resource, "read"))
      .map(({ audience, name }) => ({ resourceId: audience, name }))
      .sort((a, b) => a.name.localeCompare(b.name) || a.resourceId.localeCompare(b.resourceId));
  }

  async function resourceDetail(resourceId: string, actor: ApplicationActor) {
    requireScopedAccess(actor, "Resources", "read");
    return resourceView(requireResourceAccess(actor, await resourceRow(resourceId), "read"), actor);
  }

  async function updateResourceScope(resourceId: string, actor: ApplicationActor, input: ResourceScopeChange) {
    requireScopedAccess(actor, "Resources", "update");
    return editResourceAssignments(async (tx) => {
      const resource = await lockResourceForScopeUpdate(tx, resourceId, actor);
      let nextScopes = resource.scopes;
      if (input.action === "add") nextScopes = unique([...nextScopes, input.scope]);
      if (input.action === "remove") nextScopes = nextScopes.filter((scope) => scope !== input.scope);
      if (input.action === "update" && !nextScopes.includes(input.scope)) {
        throw new InternalApplicationError(404, "scope_not_found", "Resource scope not found");
      }
      const upstreamScopes = input.action !== "remove" && input.upstreamScope !== undefined
        ? { [input.scope]: input.upstreamScope }
        : undefined;
      await assertScopesCoverAssignments(tx, resource, nextScopes);
      await replaceResourceScopes(tx, resourceId, nextScopes, upstreamScopes);
      await tx.update(resourceServers).set({ updatedAt: new Date() })
        .where(eq(resourceServers.audience, resourceId));
      return resourceView((await resourceRow(resourceId, tx))!, actor);
    });
  }

  function sameUris(left: string[], right: string[]) {
    if (left.length !== right.length) return false;
    const rightSet = new Set(right);
    return left.every((uri) => rightSet.has(uri));
  }

  async function saveLogoutUris(
    resourceId: string,
    uris: string[],
    authorize: (resource: ResourceRow | undefined) => ResourceRow,
    skipUnchanged = false,
  ) {
    const previous = authorize(await resourceRow(resourceId));
    const next = [...new Set(uris)];
    if (skipUnchanged && sameUris(previous.backchannelLogoutUris, next)) {
      return { backchannelLogoutUris: next };
    }
    await Promise.all(next.map(async (uri) => {
      const result = await backchannel.verifyDestination(resourceId, uri);
      if (result === "timeout") {
        throw new InternalApplicationError(504, "backchannel_timeout", "The resource did not complete webhook verification in time");
      }
      if (result !== "verified") {
        throw new InternalApplicationError(502, "backchannel_test_failed", `The webhook test failed for ${uri}. The endpoint must accept the test with HTTP 202`);
      }
    }));

    return db.transaction(async (tx) => {
      const [resource] = await tx.select().from(resourceServers).where(eq(resourceServers.audience, resourceId)).for("update");
      const current = authorize(resource);
      if (current.secretHash !== previous.secretHash || !sameUris(current.backchannelLogoutUris, previous.backchannelLogoutUris)) {
        throw new InternalApplicationError(409, "backchannel_changed", "The resource secret or webhooks changed during verification. Try again");
      }
      await tx.update(resourceServers).set({ backchannelLogoutUris: next, updatedAt: new Date() })
        .where(eq(resourceServers.audience, resourceId));
      return { backchannelLogoutUris: next };
    });
  }

  async function setResourceLogoutUris(resourceId: string, actor: ApplicationActor, uris: string[]) {
    requireScopedAccess(actor, "Resources", "update");
    return saveLogoutUris(resourceId, uris, (resource) => requireResourceAccess(actor, resource, "update"));
  }

  function reconcileConfiguredLogoutUris(resourceId: string, uris: string[]) {
    return saveLogoutUris(resourceId, uris, (resource) => {
      if (!resource) throw new InternalApplicationError(404, "resource_not_found", "Resource not found");
      return resource;
    }, true);
  }

  async function setResourceLogoutUri(resourceId: string, actor: ApplicationActor, uri: string | null) {
    return setResourceLogoutUris(resourceId, actor, uri === null ? [] : [uri]);
  }

  function reconcileConfiguredLogoutUri(resourceId: string, uri: string) {
    return reconcileConfiguredLogoutUris(resourceId, [uri]);
  }

  async function rotateResourceSecret(resourceId: string, actor: ApplicationActor) {
    requireScopedAccess(actor, "Resources", "update");
    return db.transaction(async (tx) => {
      const [resource] = await tx.select().from(resourceServers).where(eq(resourceServers.audience, resourceId)).for("update");
      requireResourceAccess(actor, resource, "update");
      const secret = generateSecret();
      await tx.update(resourceServers).set({ secretHash: await hashClientSecret(secret), updatedAt: new Date() })
        .where(eq(resourceServers.audience, resourceId));
      return { resourceSecret: secret };
    });
  }

  async function deleteResource(resourceId: string, actor: ApplicationActor) {
    requireScopedAccess(actor, "Resources", "delete");
    await editResourceAssignments(async (tx) => {
      requireResourceAccess(actor, await resourceRow(resourceId, tx), "delete");
      if ((await attachedClients(tx, resourceId)).length) {
        throw new InternalApplicationError(409, "resource_in_use", "Detach this resource from all applications before deleting it");
      }
      await tx.delete(resourceServers).where(eq(resourceServers.audience, resourceId));
    });
  }

  async function attachResource(clientId: string, actor: ApplicationActor, resourceId: string) {
    await editResourceAssignments(async (tx) => {
      const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources, tx);
      requireResourceAccess(actor, await resourceRow(resourceId, tx), "read");
      if (row.resources.includes(resourceId)) throw new InternalApplicationError(409, "conflict", "Resource is already attached");
      await tx.update(oidcClients).set({
        resources: [...row.resources, resourceId],
        metadata: metadataPatch({ resourceScopes: { ...metadata.resourceScopes, [resourceId]: [] } }),
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function createResource(clientId: string, actor: ApplicationActor, input: ResourceDefinitionInput) {
    await editResourceAssignments(async (tx) => {
      const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources, tx);
      const [created] = await tx.insert(resourceServers).values({
        audience: input.resourceId, name: input.name, createdBy: actor.id,
        secretHash: await hashNewResourceSecret(),
      }).onConflictDoNothing().returning({ audience: resourceServers.audience });
      if (!created) throw new InternalApplicationError(409, "conflict", "Resource already exists");
      await replaceResourceScopes(tx, input.resourceId, input.availableScopes, input.upstreamScopes);
      await tx.update(oidcClients).set({
        resources: [...row.resources, input.resourceId],
        metadata: metadataPatch({ resourceScopes: { ...metadata.resourceScopes, [input.resourceId]: [] } }),
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function updateResource(clientId: string, actor: ApplicationActor, input: ResourceDefinitionInput) {
    await editResourceAssignments(async (tx) => {
      const { row } = await accessible(clientId, actor, applicationPermissions.resources, tx);
      if (!row.resources.includes(input.resourceId)) throw new InternalApplicationError(404, "not_found", "Resource not found");
      const resource = await lockResourceForScopeUpdate(tx, input.resourceId, actor);
      if ((await attachedClients(tx, input.resourceId)).length > 1) {
        throw new InternalApplicationError(409, "resource_shared", "Shared resources cannot be edited from an application");
      }
      const scopes = unique(input.availableScopes);
      await assertScopesCoverAssignments(tx, resource, scopes);
      await replaceResourceScopes(tx, input.resourceId, scopes, input.upstreamScopes);
      await tx.update(resourceServers).set({ name: input.name, updatedAt: new Date() })
        .where(eq(resourceServers.audience, input.resourceId));
    });
  }

  async function removeResource(clientId: string, actor: ApplicationActor, resourceId: string, deleteDefinition: boolean) {
    await editResourceAssignments(async (tx) => {
      const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources, tx);
      if (!row.resources.includes(resourceId)) throw new InternalApplicationError(404, "not_found", "Resource not found");
      requireResourceAccess(actor, await resourceRow(resourceId, tx), deleteDefinition ? "delete" : "read");
      if (row.resources.length === 1) throw new InternalApplicationError(409, "last_resource", "An application must retain at least one resource");
      if (deleteDefinition && (await attachedClients(tx, resourceId)).length > 1) {
        throw new InternalApplicationError(409, "resource_shared", "Shared resources cannot be deleted");
      }
      const resourceScopes = { ...metadata.resourceScopes };
      delete resourceScopes[resourceId];
      await tx.update(oidcClients).set({
        resources: row.resources.filter((resource) => resource !== resourceId),
        metadata: metadataPatch({ resourceScopes, scopes: unique(Object.values(resourceScopes).flat()) }),
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
      if (deleteDefinition) await tx.delete(resourceServers).where(eq(resourceServers.audience, resourceId));
    });
    invalidateClient(clientId);
  }

  async function updateScopes(clientId: string, actor: ApplicationActor, input: Record<string, string[]>) {
    await editResourceAssignments(async (tx) => {
      const { row, metadata } = await accessible(clientId, actor, applicationPermissions.resources, tx);
      const resources = await tx.select(resourceWithScopes).from(resourceServers).where(inArray(resourceServers.audience, row.resources));
      const visible = resources.filter((resource) => canAccessResource(actor, resource, "read"));
      const visibleIds = new Set(visible.map((resource) => resource.audience));
      if (Object.keys(input).some((resource) => !visibleIds.has(resource))) {
        throw new InternalApplicationError(400, "invalid_scopes", "Scopes contain an unavailable resource");
      }
      for (const resource of visible) {
        const registered = new Set(resource.scopes);
        if (Object.hasOwn(input, resource.audience) && input[resource.audience]!.some((scope) => !registered.has(scope))) {
          throw new InternalApplicationError(400, "invalid_scopes", `Unsupported scope for ${resource.audience}`);
        }
      }
      const resourceScopes = Object.fromEntries(row.resources.map((resource) => [
        resource,
        visibleIds.has(resource)
          ? unique(Object.hasOwn(input, resource) ? input[resource]! : [])
          : assignedScopes(metadata, resource),
      ]));
      await tx.update(oidcClients).set({
        metadata: metadataPatch({ resourceScopes, scopes: unique(Object.values(resourceScopes).flat()) }),
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
    invalidateClient(clientId);
  }

  async function createPermission(clientId: string, actor: ApplicationActor, permission: string, description: string) {
    await accessible(clientId, actor, applicationPermissions.permissions);
    const [existing] = await db.select({ permission: oidcPermissions.permission }).from(oidcPermissions)
      .where(and(eq(oidcPermissions.clientId, clientId), eq(oidcPermissions.permission, permission))).limit(1);
    if (existing) throw new InternalApplicationError(409, "conflict", "Permission definition already exists");
    await db.transaction(async (tx) => {
      await tx.insert(oidcPermissions).values({ clientId, permission, description });
      await tx.update(oidcClients).set({
        permissionCatalogVersion: sql`${oidcClients.permissionCatalogVersion} + 1`,
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
  }

  async function updatePermission(clientId: string, actor: ApplicationActor, permission: string, description: string) {
    await accessible(clientId, actor, applicationPermissions.permissions);
    await db.transaction(async (tx) => {
      const updated = await tx.update(oidcPermissions).set({ description })
        .where(and(eq(oidcPermissions.clientId, clientId), eq(oidcPermissions.permission, permission)))
        .returning({ permission: oidcPermissions.permission });
      if (!updated.length) throw new InternalApplicationError(404, "not_found", "Permission definition not found");
      await tx.update(oidcClients).set({
        permissionCatalogVersion: sql`${oidcClients.permissionCatalogVersion} + 1`,
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
  }

  async function deletePermission(clientId: string, actor: ApplicationActor, permission: string) {
    await accessible(clientId, actor, applicationPermissions.permissions);
    await db.transaction(async (tx) => {
      const deleted = await tx.delete(oidcPermissions)
        .where(and(eq(oidcPermissions.clientId, clientId), eq(oidcPermissions.permission, permission)))
        .returning({ permission: oidcPermissions.permission });
      if (!deleted.length) throw new InternalApplicationError(404, "not_found", "Permission definition not found");
      await tx.update(oidcClients).set({
        permissionCatalogVersion: sql`${oidcClients.permissionCatalogVersion} + 1`,
        updatedAt: new Date(),
      }).where(eq(oidcClients.clientId, clientId));
    });
  }

  async function updateDefaultPermissions(clientId: string, actor: ApplicationActor, permissions: string[]) {
    await accessible(clientId, actor, applicationPermissions.permissions);
    if (new Set(permissions).size !== permissions.length) {
      throw new InternalApplicationError(400, "invalid_default_permissions", "Default permissions must be unique");
    }
    await db.transaction(async (tx) => {
      const definitions = await tx.select({ permission: oidcPermissions.permission })
        .from(oidcPermissions).where(eq(oidcPermissions.clientId, clientId));
      const defined = new Set(definitions.map(({ permission }) => permission));
      if (permissions.some((permission) => !defined.has(permission))) {
        throw new InternalApplicationError(400, "invalid_default_permissions", "Default permissions must be defined by this application");
      }
      await tx.delete(defaultPermissions).where(eq(defaultPermissions.applicationId, clientId));
      if (permissions.length) {
        await tx.insert(defaultPermissions).values(permissions.map((permission) => ({
          applicationId: clientId,
          permission,
        })));
      }
      await tx.update(oidcClients).set({ updatedAt: new Date() }).where(eq(oidcClients.clientId, clientId));
    });
  }

  async function updateRedirectUris(clientId: string, actor: ApplicationActor, redirectUris: string[]) {
    const { metadata } = await accessible(clientId, actor, applicationPermissions.redirects);
    const values = unique(redirectUris);
    if (!values.length || values.length !== redirectUris.length || values.some((uri) => !validRedirectUri(uri, metadata.public))) throw new InternalApplicationError(400, "invalid_redirect_uris", "Redirect URIs must be unique and valid for this client type");
    await saveMetadata(clientId, { redirectUris: values });
  }

  return {
    list, listOrganizations, detail, createApplication, updateApplication, deleteApplication,
    rotateSecret, removeSecret, addOwner, updateOwner, removeOwner, attachResource, createResource,
    updateResource, removeResource, updateScopes, createPermission, updatePermission,
    deletePermission, updateDefaultPermissions, updateRedirectUris, listResources, resourceDetail,
    updateResourceScope, setResourceLogoutUri, setResourceLogoutUris, rotateResourceSecret, deleteResource,
    validateBackchannel: backchannel.validate, reconcileConfiguredLogoutUri, reconcileConfiguredLogoutUris,
  };
}

export type InternalApplicationService = ReturnType<typeof createInternalApplicationService>;
