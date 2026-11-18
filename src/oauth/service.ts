import { and, desc, eq, gt, inArray, isNull, sql } from "drizzle-orm";
import { decodeJwt } from "jose";
import {
  EPHEMERAL_LOCALHOST_REDIRECT_PREFIX,
  backchannelLogoutUriSchema,
  isEphemeralLocalhostRedirectUri,
  type AppConfig,
} from "../config.js";
import type { Database } from "../database/client.js";
import { resourceScopeNames } from "../database/resource-scopes.js";
import {
  secretMatches,
  type ClientOwner,
  type StoredClientMetadata,
} from "../database/seed.js";
import { createClientCache, type CachedClient, type ClientCache } from "./clientCache.js";
import {
  authorizationCodes,
  authorizationConsents,
  authorizationRequests,
  authorizationSessions,
  oidcClientOrganizations,
  oidcClients,
  organizations,
  refreshTokens,
  resourceServers,
  users,
} from "../database/schema.js";
import type { IdentityService } from "../identity.js";
import { createAccessTokenRevocationDelivery, recordAccessTokenRevocation } from "./access-token-revocations.js";
import { hashToken, isValidS256PkceRequest, randomToken, verifyS256Pkce } from "./crypto.js";
import { OAuthError } from "./errors.js";
import type { KeyService } from "./keys.js";
import { scopesCover } from "./scopes.js";

// function c(x: string | undefined) {
//   if (!x) return "..."
//   return x.substring(0, 20) + (x.length > 20 ? "..." : "")
// }

// These OIDC scopes describe the authenticated user or request refresh-token
// access. They are available to every registered client, rather than being an
// API capability granted by a particular resource server.
const publicScopes = new Set(["openid", "profile", "email", "offline_access"]);
const identityScopes = publicScopes;
const maxAccessTokenLifetimeWithoutBackchannelSeconds = 10 * 60;

async function requireResource(database: Pick<Database, "select">, audience: string) {
  const [resource] = await database.select({
    scopes: resourceScopeNames,
    backchannelLogoutUris: resourceServers.backchannelLogoutUris,
  }).from(resourceServers).where(eq(resourceServers.audience, audience)).limit(1);
  if (!resource) {
    throw new OAuthError(
      "invalid_target",
      `Resource server "${audience}" is not registered; add it with "bun run clients" or OIDC_RESOURCES_JSON`,
      400,
      14407,
    );
  }
  return resource;
}

export interface OAuthClient {
  clientId: string;
  secretHash: string | null;
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  organizations: (typeof organizations.$inferSelect)[];
  metadata: StoredClientMetadata;
}

export function assertClientAllowsEmail(
  client: Pick<OAuthClient, "filterMode" | "filterContent"> & { filterContentSet?: Set<string> },
  email: string,
) {
  const normalizedEmail = email.trim().toLowerCase();
  const matchesFilter = client.filterContentSet?.has(normalizedEmail)
    ?? client.filterContent.includes(normalizedEmail);
  if (
    (client.filterMode === "whitelist" && !matchesFilter) ||
    (client.filterMode === "blacklist" && matchesFilter)
  ) {
    throw new OAuthError("access_denied", "This account is not allowed to sign in to this application.", 403);
  }
}

function parseMetadata(value: Record<string, unknown>): StoredClientMetadata {
  const { permissions: _legacyPermissions, ...metadata } = value;
  const owners = Array.isArray(value.owners)
    ? value.owners.map((owner): ClientOwner | undefined => {
        if (!owner || typeof owner !== "object" || !("id" in owner) || !("role" in owner)) {
          return undefined;
        }
        if (typeof owner.id !== "string" || typeof owner.role !== "string") return undefined;
        const normalizedRole = owner.role.toLowerCase();
        if (normalizedRole === "role.admin") return { id: owner.id, role: "role.ADMIN" };
        if (normalizedRole === "role.general") return { id: owner.id, role: "role.GENERAL" };
        return undefined;
      })
    : [];
  const resourceScopes = value.resourceScopes && typeof value.resourceScopes === "object"
    ? Object.fromEntries(Object.entries(value.resourceScopes).map(([resource, scopes]) => [
        resource,
        Array.isArray(scopes) ? scopes.filter((scope): scope is string => typeof scope === "string") : [],
      ]))
    : {};
  if (
    typeof value.name !== "string" ||
    owners.length === 0 ||
    owners.some((owner) => !owner) ||
    !Array.isArray(value.redirectUris) ||
    typeof value.public !== "boolean" ||
    !Array.isArray(value.scopes)
  ) {
    throw new Error("Stored client metadata is invalid");
  }
  return {
    ...metadata,
    owners: owners as ClientOwner[],
    resourceScopes,
  } as StoredClientMetadata;
}

function redirectUriMatches(
  client: Pick<OAuthClient, "metadata"> & { redirectUriSet: Set<string> },
  redirectUri: string | undefined,
): boolean {
  if (!redirectUri || isEphemeralLocalhostRedirectUri(redirectUri)) return false;
  if (client.redirectUriSet.has(redirectUri)) return true;
  if (!client.metadata.public) return false;

  const match = /^http:\/\/localhost:(\d+)(\/[^?#]*)$/i.exec(redirectUri);
  if (!match) return false;
  const port = Number(match[1]);
  if (!Number.isInteger(port) || port < 1 || port > 65_535) return false;

  const path = match[2]!;
  return client.metadata.redirectUris.some((registeredUri) =>
    isEphemeralLocalhostRedirectUri(registeredUri) &&
    registeredUri.slice(EPHEMERAL_LOCALHOST_REDIRECT_PREFIX.length) === path
  );
}

export function createOAuthService(
  config: AppConfig,
  db: Database,
  keys: KeyService,
  identity: IdentityService,
) {
  const revocationDelivery = createAccessTokenRevocationDelivery(db, keys);
  const clientByIdStmt = db
    .select()
    .from(oidcClients)
    .where(eq(oidcClients.clientId, sql.placeholder("id")))
    .limit(1)
    .prepare("client_by_id");

  async function clientById(clientId: string): Promise<OAuthClient | undefined> {
    const [row] = await clientByIdStmt.execute({ id: clientId });
    if (!row) return undefined;
    const linkedOrganizations = await db
      .select({
        id: organizations.id,
        organizationId: organizations.organizationId,
        firstParty: organizations.firstParty,
        createdAt: organizations.createdAt,
        updatedAt: organizations.updatedAt,
      })
      .from(oidcClientOrganizations)
      .innerJoin(organizations, eq(oidcClientOrganizations.organizationId, organizations.id))
      .where(eq(oidcClientOrganizations.clientId, clientId));
    return { ...row, organizations: linkedOrganizations, metadata: parseMetadata(row.metadata) };
  }

  const clientCache: ClientCache = createClientCache(clientById, { ttlMs: 60_000 });

  function accessTokenLifetimeFor(backchannelLogoutUris: string[]) {
    const hasBackchannel = backchannelLogoutUris.some((uri) => backchannelLogoutUriSchema.safeParse(uri).success);
    return hasBackchannel
      ? config.accessTokenLifetimeSeconds
      : Math.min(config.accessTokenLifetimeSeconds, maxAccessTokenLifetimeWithoutBackchannelSeconds);
  }

  function requireClient(
    client: CachedClient | undefined,
    clientId: string,
    status: 400 | 401 | 404,
  ): CachedClient {
    if (!client) {
      throw new OAuthError("invalid_client", `Client "${clientId}" is not registered.`, status, 14001);
    }
    if (client.metadata.disabled) {
      throw new OAuthError("invalid_client", `Client "${clientId}" is disabled.`, status, 14002);
    }
    return client;
  }

  async function authenticateClient(clientId: string, secret?: string) {
    const client = requireClient(await clientCache.get(clientId), clientId, 401);
    if (client.metadata.public) {
      if (secret) throw new OAuthError("invalid_client", "Public clients must not send a secret", 401, 14003);
    } else if (!secret || !(await secretMatches(secret, client.secretHash))) {
      throw new OAuthError("invalid_client", "Client authentication failed", 401, 14004);
    }
    return client;
  }

  async function startAuthorization(input: {
    initialUri: string;
    clientId?: string;
    redirectUri?: string;
    responseType?: string;
    scope?: string;
    resources: string[];
    state?: string;
    nonce?: string;
    codeChallenge?: string;
    codeChallengeMethod?: string;
    session?: { userId: string; authenticatedAt: Date };
  }) {
    if (!input.clientId) throw new OAuthError("invalid_request", "client_id is required");
    const client = requireClient(await clientCache.get(input.clientId), input.clientId, 400);
    const redirectUri = input.redirectUri;
    if (!redirectUri || !redirectUriMatches(client, redirectUri)) {
      throw new OAuthError("invalid_request", `Redirect URI "${input.redirectUri}" is not registered for client "${client.metadata.name}"`, 400, 14100);
    }
    if (input.responseType == "token") {
      throw new OAuthError("unsupported_response_type", "response_type=token is deprecated for present OAuth2.1 client " + client.metadata.name + ". Adjust backward compatibilty in your developer portal.", 400, 14429);
    }
    if (input.responseType !== "code") {
      throw new OAuthError("unsupported_response_type", "Only response_type=code is supported", 400, 14429);
    }
    if (!input.state) throw new OAuthError("invalid_request", "state is required");
    if (!input.nonce) throw new OAuthError("invalid_request", "nonce is required");
    if (!isValidS256PkceRequest(input.codeChallenge, input.codeChallengeMethod)) {
      throw new OAuthError("invalid_request", "S256 PKCE is required");
    }
    const scopes = (input.scope ?? "").split(" ").filter(Boolean);
    if (!scopes.includes("openid")) {
      throw new OAuthError("invalid_scope", "The openid scope is required");
    }
    const resourceScopes = scopes.filter((scope) => !publicScopes.has(scope));
    if (input.resources.length > 1) {
      throw new OAuthError("invalid_target", "Exactly one resource may be requested");
    }
    const resource = input.resources[0] ?? (client.resources.length === 1 ? client.resources[0] : undefined);
    if (!resource || !client.resources.includes(resource)) {
      throw new OAuthError("invalid_target", "The resource \"" + resource +"\" is not registered for this client", 400, 14501);
    }
    const allowedScopes = client.metadata.resourceScopes?.[resource] ?? client.metadata.scopes;
    if (!scopesCover(allowedScopes, resourceScopes)) {
      throw new OAuthError("invalid_scope", "The client is not allowed to request one or more scopes for this resource", 400, 14401);
    }
    const resourceServer = await requireResource(db, resource);
    const customScopes = scopes.filter((scope) => !identityScopes.has(scope));
    if (!scopesCover(resourceServer.scopes, customScopes)) {
      throw new OAuthError("invalid_scope", "A requested scope is not supported by the resource", 400, 14401);
    }

    const sessionUser = input.session ? await identity.findUser(input.session.userId) : undefined;
    if (sessionUser) assertClientAllowsEmail(client, sessionUser.email);
    const sessionOrganization = sessionUser ? await identity.organizationForUser(sessionUser.id) : undefined;
    const allowedSession = input.session && sessionOrganization && client.organizations.some(
      (organization) => organization.id === sessionOrganization.id,
    )
      ? input.session
      : undefined;
    const id = crypto.randomUUID();
    const interactionToken = randomToken(32);
    await db.insert(authorizationRequests).values({
      id,
      initialUri: input.initialUri,
      interactionHash: hashToken(interactionToken),
      clientId: client.clientId,
      redirectUri,
      scopes,
      resource,
      state: input.state,
      nonce: input.nonce,
      codeChallenge: input.codeChallenge!,
      userId: allowedSession?.userId,
      authenticatedAt: allowedSession?.authenticatedAt,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    return { id, interactionToken };
  }

  async function interaction(requestId: string, interactionToken: string | undefined) {
    if (!interactionToken) throw new OAuthError("invalid_request", "Interaction cookie is missing");
    const [request] = await db
      .select()
      .from(authorizationRequests)
      .where(
        and(
          eq(authorizationRequests.id, requestId),
          eq(authorizationRequests.interactionHash, hashToken(interactionToken)),
          eq(authorizationRequests.status, "pending"),
          gt(authorizationRequests.expiresAt, new Date()),
        ),
      )
      .limit(1);
    if (!request) throw new OAuthError("invalid_request", "Interaction is invalid or expired", 404, 2400);
    const client = requireClient(await clientCache.get(request.clientId), request.clientId, 400);
    return { request, client };
  }

  async function getAuthorization(bridgeToken: string) {
    const [request] = await db
      .select()
      .from(authorizationRequests)
      .where(
        and(
          eq(authorizationRequests.interactionHash, hashToken(bridgeToken)),
          eq(authorizationRequests.status, "pending"),
          gt(authorizationRequests.expiresAt, new Date()),
        ),
      )
      .limit(1);
    if (!request) throw new OAuthError("invalid_request", "Authorization request is invalid or expired", 400, 2400);
    return request;
  }

  async function getClientInformation(clientId: string) {
    const client = requireClient(await clientCache.get(clientId), clientId, 404);
    const ownerIds = client.metadata.owners.map((owner) => owner.id);
    const people = await identity.findUsersByIds(ownerIds);
    const peopleById = new Map(people.map((person) => [person.id, person]));
    return {
      id: client.clientId,
      name: client.metadata.name,
      owners: ownerIds.flatMap((ownerId) => {
        const person = peopleById.get(ownerId);
        if (!person) return [];
        return [{
          id: person.id,
          name: person.displayName?.trim() || person.email,
          email: person.email,
          picture: person.picture && person.pictureContentType
            ? `/api/picture/${encodeURIComponent(person.id)}`
            : null,
        }];
      }),
    };
  }

  async function requiresConsent(request: typeof authorizationRequests.$inferSelect, client: OAuthClient) {
    if (!client.requireConsent) return false;
    if (!request.userId) return true;
    const [consent] = await db
      .select()
      .from(authorizationConsents)
      .where(
        and(
          eq(authorizationConsents.userId, request.userId),
          eq(authorizationConsents.clientId, request.clientId),
        ),
      )
      .limit(1);
    return !consent || !scopesCover(consent.scopes, request.scopes) || !consent.resources.includes(request.resource);
  }

  async function attachUser(requestId: string, userId: string, authenticatedAt: Date) {
    const rows = await db
      .update(authorizationRequests)
      .set({ userId, authenticatedAt })
      .where(
        and(
          eq(authorizationRequests.id, requestId),
          eq(authorizationRequests.status, "pending"),
          gt(authorizationRequests.expiresAt, new Date()),
        ),
      )
      .returning({ id: authorizationRequests.id });
    if (!rows.length) throw new OAuthError("invalid_request", "Authorization request expired");
  }

  async function clearInteractionUser(requestId: string) {
    const rows = await db
      .update(authorizationRequests)
      .set({ userId: null, authenticatedAt: null })
      .where(
        and(
          eq(authorizationRequests.id, requestId),
          eq(authorizationRequests.status, "pending"),
          gt(authorizationRequests.expiresAt, new Date()),
        ),
      )
      .returning({ id: authorizationRequests.id });
    if (!rows.length) throw new OAuthError("invalid_request", "Authorization request expired");
  }

  async function grantConsent(request: typeof authorizationRequests.$inferSelect) {
    if (!request.userId) throw new OAuthError("invalid_request", "User is not authenticated");
    const [existing] = await db
      .select()
      .from(authorizationConsents)
      .where(
        and(
          eq(authorizationConsents.userId, request.userId),
          eq(authorizationConsents.clientId, request.clientId),
        ),
      )
      .limit(1);
    const scopes = [...new Set([...(existing?.scopes ?? []), ...request.scopes])];
    const resources = [...new Set([...(existing?.resources ?? []), request.resource])];
    await db
      .insert(authorizationConsents)
      .values({ userId: request.userId, clientId: request.clientId, scopes, resources })
      .onConflictDoUpdate({
        target: [authorizationConsents.userId, authorizationConsents.clientId],
        set: { scopes, resources, updatedAt: new Date() },
      });
  }

  async function completeAuthorization(requestId: string) {
    const code = randomToken(48);
    const codeHash = hashToken(code);
    const request = await db.transaction(async (tx) => {
      const [claimed] = await tx
        .update(authorizationRequests)
        .set({ status: "completed" })
        .where(
          and(
            eq(authorizationRequests.id, requestId),
            eq(authorizationRequests.status, "pending"),
            gt(authorizationRequests.expiresAt, new Date()),
          ),
        )
        .returning();
      if (!claimed?.userId || !claimed.authenticatedAt) {
        throw new OAuthError("invalid_request", "Authorization request is not ready");
      }
      await requireResource(tx, claimed.resource);
      await tx.insert(authorizationCodes).values({
        codeHash,
        requestId: claimed.id,
        clientId: claimed.clientId,
        redirectUri: claimed.redirectUri,
        userId: claimed.userId,
        scopes: claimed.scopes,
        resource: claimed.resource,
        nonce: claimed.nonce,
        codeChallenge: claimed.codeChallenge,
        authenticatedAt: claimed.authenticatedAt,
        expiresAt: new Date(Date.now() + 60 * 1000),
      });
      return claimed;
    });
    const redirect = new URL(request.redirectUri);
    redirect.searchParams.set("code", code);
    redirect.searchParams.set("state", request.state);
    return redirect.toString();
  }

  function denialRedirect(request: typeof authorizationRequests.$inferSelect) {
    const redirect = new URL(request.redirectUri);
    redirect.searchParams.set("error", "access_denied");
    redirect.searchParams.set("error_description", "The user denied access");
    redirect.searchParams.set("state", request.state);
    return redirect.toString();
  }

  async function denyAuthorization(request: typeof authorizationRequests.$inferSelect) {
    await db
      .update(authorizationRequests)
      .set({ status: "denied" })
      .where(
        and(
          eq(authorizationRequests.id, request.id),
          eq(authorizationRequests.status, "pending"),
        ),
      );
    return denialRedirect(request);
  }

  async function issueTokenSet(database: Pick<Database, "select">, user: typeof users.$inferSelect, input: {
    clientId: string;
    scopes: string[];
    resource: string;
    nonce?: string;
    authenticatedAt?: Date;
    grantType: "authorization_code" | "refresh_token";
  }, lifetimeSeconds: number) {
    const permissions = await identity.permissionsFor(user.id, input.clientId, database);
    const accessTokenJti = randomToken();
    const accessToken = await keys.issueAccessToken(
      { ...input, userId: user.id, jti: accessTokenJti, lifetimeSeconds },
      { user, permissions },
    );
    const response: Record<string, unknown> = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: lifetimeSeconds,
      scope: input.scopes.join(" "),
    };
    if (input.nonce && input.authenticatedAt) {
      const account = await identity.findAccount(user.id, database);
      if (!account) throw new OAuthError("invalid_grant", "User is missing or disabled");
      response.id_token = await keys.issueIdToken(
        { ...input, userId: user.id, accessToken, nonce: input.nonce, authenticatedAt: input.authenticatedAt },
        { account, permissions },
      );
    }
    const accessTokenExpiresAt = new Date(decodeJwt<{ exp: number }>(accessToken).exp * 1000);
    return { response, accessTokenJti, accessTokenExpiresAt };
  }

  async function issueRefreshToken(database: Pick<Database, "insert">, sessionId: string) {
    const token = randomToken(64);
    await database.insert(refreshTokens).values({ tokenHash: hashToken(token), sessionId });
    return token;
  }

  async function exchangeAuthorizationCode(input: {
    code: string;
    clientId: string;
    clientSecret?: string;
    redirectUri?: string;
    codeVerifier?: string;
  }) {
    await authenticateClient(input.clientId, input.clientSecret);
    const [authorizationCode] = await db
      .select()
      .from(authorizationCodes)
      .where(
        and(
          eq(authorizationCodes.codeHash, hashToken(input.code)),
          gt(authorizationCodes.expiresAt, new Date()),
        ),
      )
      .limit(1);
    if (
      !authorizationCode ||
      authorizationCode.clientId !== input.clientId ||
      !input.codeVerifier ||
      (input.redirectUri !== undefined && authorizationCode.redirectUri !== input.redirectUri) ||
      !verifyS256Pkce(input.codeVerifier, authorizationCode.codeChallenge)
    ) {
      throw new OAuthError("invalid_grant", "Authorization code exchange failed");
    }
    if (authorizationCode.consumedAt) {
      throw new OAuthError("invalid_grant", "Authorization code was already used");
    }
    return db.transaction(async (tx) => {
      const [consumed] = await tx
        .update(authorizationCodes)
        .set({ consumedAt: new Date() })
        .where(and(
          eq(authorizationCodes.codeHash, authorizationCode.codeHash),
          eq(authorizationCodes.clientId, input.clientId),
          isNull(authorizationCodes.consumedAt),
          gt(authorizationCodes.expiresAt, new Date()),
        ))
        .returning();
      if (!consumed) throw new OAuthError("invalid_grant", "Authorization code is invalid or was already used");

      const resource = await requireResource(tx, consumed.resource);
      const [user] = await tx.select().from(users).where(eq(users.id, consumed.userId)).for("share");
      if (!user || user.disabled) throw new OAuthError("invalid_grant", "User is missing or disabled");
      await identity.registerApplicationLogin?.(user.id, consumed.clientId, tx);
      const { response, accessTokenJti, accessTokenExpiresAt } = await issueTokenSet(
        tx, user, { ...consumed, grantType: "authorization_code" }, accessTokenLifetimeFor(resource.backchannelLogoutUris),
      );
      const sessionId = consumed.requestId;
      const canRefresh = consumed.scopes.includes("offline_access");
      await tx.insert(authorizationSessions).values({
        id: sessionId,
        userId: user.id,
        clientId: consumed.clientId,
        scopes: consumed.scopes,
        resource: consumed.resource,
        authenticatedAt: consumed.authenticatedAt,
        accessTokenJti,
        accessTokenExpiresAt,
        refreshExpiresAt: canRefresh ? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000) : null,
      });
      if (canRefresh) response.refresh_token = await issueRefreshToken(tx, sessionId);
      return response;
    });
  }

  async function exchangeRefreshToken(input: {
    refreshToken: string;
    clientId: string;
    clientSecret?: string;
  }) {
    await authenticateClient(input.clientId, input.clientSecret);
    const tokenHash = hashToken(input.refreshToken);
    const result = await db.transaction(async (tx) => {
      // Serialize token rotation and revocation on the session row.
      const [session] = await tx.select().from(authorizationSessions).where(and(
        eq(authorizationSessions.clientId, input.clientId),
        inArray(authorizationSessions.id, tx.select({ id: refreshTokens.sessionId })
          .from(refreshTokens).where(eq(refreshTokens.tokenHash, tokenHash))),
      )).for("update");
      if (!session?.accessTokenJti || session.revokedAt || !session.refreshExpiresAt || session.refreshExpiresAt <= new Date()) {
        return { error: "Refresh token is invalid or expired" };
      }

      const [stored] = await tx.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, tokenHash));
      if (!stored) return { error: "Refresh token is invalid" };
      if (stored.consumedAt) {
        await tx.update(authorizationSessions).set({ revokedAt: new Date() }).where(eq(authorizationSessions.id, session.id));
        return { error: "Refresh token reuse detected" };
      }

      const resource = await requireResource(tx, session.resource);
      const user = await identity.findUser(session.userId, tx);
      if (!user || user.disabled) {
        await tx.update(authorizationSessions).set({ revokedAt: new Date() }).where(eq(authorizationSessions.id, session.id));
        return { error: "User is missing or disabled" };
      }
      const { response, accessTokenJti, accessTokenExpiresAt } = await issueTokenSet(tx, user, {
        clientId: session.clientId,
        scopes: session.scopes,
        resource: session.resource,
        grantType: "refresh_token",
      }, accessTokenLifetimeFor(resource.backchannelLogoutUris));
      await tx.update(refreshTokens).set({ consumedAt: new Date() }).where(eq(refreshTokens.tokenHash, tokenHash));
      response.refresh_token = await issueRefreshToken(tx, session.id);
      await tx.update(authorizationSessions).set({ accessTokenJti, accessTokenExpiresAt }).where(eq(authorizationSessions.id, session.id));
      await recordAccessTokenRevocation(tx, {
        jti: session.accessTokenJti, audience: session.resource, expiresAt: session.accessTokenExpiresAt,
      }, config.accessTokenRevocationGraceSeconds);
      return { response, revokedJti: session.accessTokenJti };
    });
    if (result.error !== undefined) throw new OAuthError("invalid_grant", result.error);
    await revocationDelivery.deliver(result.revokedJti);
    return result.response;
  }

  async function exchangeClientCredentials(input: {
    clientId: string;
    clientSecret?: string;
    scope?: string;
    resource?: string;
  }) {
    const client = await authenticateClient(input.clientId, input.clientSecret);
    if (client.metadata.public) {
      throw new OAuthError("unauthorized_client", "Public clients cannot use the client_credentials grant");
    }

    const resource = input.resource ?? (client.resources.length === 1 ? client.resources[0] : undefined);
    if (!resource || !client.resources.includes(resource)) {
      throw new OAuthError("invalid_target", `The resource "${resource}" is not registered for this client`, 400, 14501);
    }
    const allowedScopes = client.metadata.resourceScopes?.[resource] ?? client.metadata.scopes;
    const scopes = input.scope === undefined
      ? allowedScopes
      : [...new Set(input.scope.split(" ").filter(Boolean))];
    if (!scopesCover(allowedScopes, scopes)) {
      throw new OAuthError("invalid_scope", "The client is not allowed to request one or more scopes for this resource", 400, 14401);
    }
    const resourceServer = await requireResource(db, resource);
    if (!scopesCover(resourceServer.scopes, scopes)) {
      throw new OAuthError("invalid_scope", "A requested scope is not supported by the resource", 400, 14401);
    }

    const lifetimeSeconds = accessTokenLifetimeFor(resourceServer.backchannelLogoutUris);
    return {
      access_token: await keys.issueApplicationAccessToken({
        clientId: client.clientId,
        scopes,
        resource,
        lifetimeSeconds,
      }),
      token_type: "Bearer",
      expires_in: lifetimeSeconds,
      scope: scopes.join(" "),
    };
  }

  async function revoke(token: string, clientId: string, clientSecret?: string) {
    await authenticateClient(clientId, clientSecret);
    const access = await keys.readAccessToken(token).catch(() => undefined);
    if (access) {
      if (access.client_id !== clientId || typeof access.aud !== "string") return;
      await recordAccessTokenRevocation(db, {
        jti: access.jti, audience: access.aud, expiresAt: new Date(access.exp * 1000),
      }, config.accessTokenRevocationGraceSeconds);
      await revocationDelivery.deliver(access.jti);
      return;
    }

    const jti = await db.transaction(async (tx) => {
      const [session] = await tx.update(authorizationSessions).set({ revokedAt: new Date() }).where(and(
        eq(authorizationSessions.clientId, clientId),
        isNull(authorizationSessions.revokedAt),
        inArray(authorizationSessions.id, tx.select({ id: refreshTokens.sessionId })
          .from(refreshTokens).where(eq(refreshTokens.tokenHash, hashToken(token)))),
      )).returning();
      if (!session?.accessTokenJti) return undefined;

      await recordAccessTokenRevocation(tx, {
        jti: session.accessTokenJti, audience: session.resource, expiresAt: session.accessTokenExpiresAt,
      }, config.accessTokenRevocationGraceSeconds);
      return session.accessTokenJti;
    });
    if (jti) await revocationDelivery.deliver(jti);
  }

  async function listAuthorizationSessions(userId: string, actorJti: string) {
    const expiresAt = sql<Date>`greatest(
      ${authorizationSessions.refreshExpiresAt},
      coalesce(${authorizationSessions.accessTokenExpiresAt},
        ${authorizationSessions.createdAt} + ${config.accessTokenLifetimeSeconds}::double precision * interval '1 second')
    )`;
    return db.select({
      id: authorizationSessions.id,
      createdAt: authorizationSessions.createdAt,
      expiresAt: expiresAt.mapWith(authorizationSessions.createdAt),
      resource: authorizationSessions.resource,
      current: sql<boolean>`coalesce(${authorizationSessions.accessTokenJti} = ${actorJti}, false)`,
    }).from(authorizationSessions).where(and(
      eq(authorizationSessions.userId, userId),
      isNull(authorizationSessions.revokedAt),
      gt(expiresAt, new Date()),
    )).orderBy(desc(authorizationSessions.createdAt), desc(authorizationSessions.id));
  }

  async function endAuthorizationSession(userId: string, sessionId: string, actorJti: string) {
    const ended = await db.transaction(async (tx) => {
      const [session] = await tx.update(authorizationSessions).set({ revokedAt: new Date() }).where(and(
        eq(authorizationSessions.userId, userId),
        eq(authorizationSessions.id, sessionId),
        isNull(authorizationSessions.revokedAt),
      )).returning({
        jti: authorizationSessions.accessTokenJti,
        resource: authorizationSessions.resource,
        expiresAt: authorizationSessions.accessTokenExpiresAt,
      });
      if (session?.jti) {
        await recordAccessTokenRevocation(tx, {
          jti: session.jti, audience: session.resource, expiresAt: session.expiresAt,
        }, 0);
      }
      return session;
    });
    if (ended?.jti) await revocationDelivery.deliver(ended.jti);
    return ended ? { currentSessionEnded: ended.jti === actorJti } : null;
  }

  async function userInfo(accessToken: string) {
    let payload: Awaited<ReturnType<KeyService["verifyAccessToken"]>>;
    try {
      payload = await keys.verifyAccessToken(accessToken);
    } catch {
      throw new OAuthError("invalid_token", "Access token is invalid", 401);
    }
    if (payload.gty === "client_credentials") {
      throw new OAuthError("invalid_token", "UserInfo requires a user access token", 401);
    }
    const account = await identity.findAccount(payload.sub);
    if (!account) throw new OAuthError("invalid_token", "User no longer exists", 401);
    return account.claims("userinfo", payload.scope);
  }

  return {
    clientById,
    authenticateClient,
    startAuthorization,
    interaction,
    getAuthorization,
    getClientInformation,
    requiresConsent,
    attachUser,
    clearInteractionUser,
    grantConsent,
    completeAuthorization,
    denialRedirect,
    denyAuthorization,
    exchangeAuthorizationCode,
    exchangeRefreshToken,
    exchangeClientCredentials,
    listAuthorizationSessions,
    endAuthorizationSession,
    revoke,
    flushAccessTokenRevocations: revocationDelivery.flush,
    userInfo,
    invalidateClient: (clientId: string) => clientCache.invalidate(clientId),
  };
}

export type OAuthService = ReturnType<typeof createOAuthService>;
export const oauthServiceInternals = { parseMetadata, redirectUriMatches };
