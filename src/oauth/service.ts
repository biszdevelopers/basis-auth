import { and, eq, gt, isNull, sql } from "drizzle-orm";
import { permissionDefinitionsSchema, type AppConfig } from "../config.js";
import type { Database } from "../database/client.js";
import {
  secretMatches,
  type ClientOwner,
  type StoredClientMetadata,
} from "../database/seed.js";
import { createClientCache, type ClientCache } from "./clientCache.js";
import {
  authorizationCodes,
  authorizationConsents,
  authorizationRequests,
  oidcClients,
  refreshTokens,
  resourceServers,
} from "../database/schema.js";
import type { IdentityService } from "../identity.js";
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

export interface OAuthClient {
  clientId: string;
  secretHash: string | null;
  resources: string[];
  requireConsent: boolean;
  filterMode: "whitelist" | "blacklist" | null;
  filterContent: string[];
  metadata: StoredClientMetadata;
}

function parseMetadata(value: Record<string, unknown>): StoredClientMetadata {
  const permissions = value.permissions === undefined
    ? {}
    : permissionDefinitionsSchema.parse(value.permissions);
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
    ...value,
    owners: owners as ClientOwner[],
    // Existing database rows predate permission definitions. They remain
    // usable until their next seed or TUI edit writes an explicit empty list.
    permissions,
  } as StoredClientMetadata;
}

export function createOAuthService(
  config: AppConfig,
  db: Database,
  keys: KeyService,
  identity: IdentityService,
) {
  const clientByIdStmt = db
    .select()
    .from(oidcClients)
    .where(eq(oidcClients.clientId, sql.placeholder("id")))
    .limit(1)
    .prepare("client_by_id");

  async function clientById(clientId: string): Promise<OAuthClient | undefined> {
    const [row] = await clientByIdStmt.execute({ id: clientId });
    return row ? { ...row, metadata: parseMetadata(row.metadata) } : undefined;
  }

  const clientCache: ClientCache = createClientCache(clientById, { ttlMs: 60_000 });

  async function authenticateClient(clientId: string, secret?: string) {
    const client = await clientCache.get(clientId);
    if (!client) throw new OAuthError("invalid_client", `Client "${clientId}" is not registered or has been disabled.`, 401, 14001);
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
    const client = await clientCache.get(input.clientId);
    if (!client) throw new OAuthError("invalid_request", `Client "${input.clientId}" is not registered or has been disabled.`, 400, 14001);
    if (!input.redirectUri || !client.redirectUriSet.has(input.redirectUri)) {
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
    if (!scopesCover(client.metadata.scopes, resourceScopes)) {
      throw new OAuthError("invalid_scope", "The client is not allowed to request one or more scopes", 400, 14401);
    }
    if (input.resources.length > 1) {
      throw new OAuthError("invalid_target", "Exactly one resource may be requested");
    }
    const resource = input.resources[0] ?? (client.resources.length === 1 ? client.resources[0] : undefined);
    if (!resource || !client.resources.includes(resource)) {
      throw new OAuthError("invalid_target", "The resource \"" + resource +"\" is not registered for this client", 400, 14501);
    }
    const [resourceServer] = await db
      .select()
      .from(resourceServers)
      .where(eq(resourceServers.audience, resource))
      .limit(1);
    if (!resourceServer) {
      throw new OAuthError(
        "invalid_target",
        `Resource server "${resource}" is not registered; add it with "bun run clients" or OIDC_RESOURCES_JSON`,
        400,
        14407,
      );
    }
    const customScopes = scopes.filter((scope) => !identityScopes.has(scope));
    if (!scopesCover(resourceServer.scopes, customScopes)) {
      throw new OAuthError("invalid_scope", "A requested scope is not supported by the resource", 400, 14401);
    }

    const id = crypto.randomUUID();
    const interactionToken = randomToken(32);
    await db.insert(authorizationRequests).values({
      id,
      initialUri: input.initialUri,
      interactionHash: hashToken(interactionToken),
      clientId: client.clientId,
      redirectUri: input.redirectUri,
      scopes,
      resource,
      state: input.state,
      nonce: input.nonce,
      codeChallenge: input.codeChallenge!,
      userId: input.session?.userId,
      authenticatedAt: input.session?.authenticatedAt,
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
    const client = await clientCache.get(request.clientId);
    if (!client) throw new OAuthError("invalid_request", "Client no longer exists", 400, 14001);
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

  async function getClient(clientId: string) {
    const client = await clientCache.get(clientId);
    if (!client) throw new OAuthError("invalid_request", `Client "${clientId}" is not registered or has been disabled.`, 400, 14001);
    return {
      id: client.clientId,
      name: client.metadata.name,
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

  async function issueTokenSet(input: {
    userId: string;
    clientId: string;
    scopes: string[];
    resource: string;
    nonce?: string;
    authenticatedAt?: Date;
    familyId?: string;
    refreshExpiresAt?: Date;
  }) {
    const user = await identity.findUser(input.userId);
    if (!user || user.disabled) {
      if (input.familyId) {
        await db
          .update(refreshTokens)
          .set({ revokedAt: new Date() })
          .where(eq(refreshTokens.familyId, input.familyId));
      }
      throw new OAuthError("invalid_grant", "User is missing or disabled");
    }
    const permissions = await identity.permissionsFor(input.userId);
    const accessToken = await keys.issueAccessToken(input, { user, permissions });
    const response: Record<string, unknown> = {
      access_token: accessToken,
      token_type: "Bearer",
      expires_in: 600,
      scope: input.scopes.join(" "),
    };
    if (input.nonce && input.authenticatedAt) {
      const account = await identity.findAccount(input.userId);
      response.id_token = await keys.issueIdToken(
        { ...input, accessToken, nonce: input.nonce, authenticatedAt: input.authenticatedAt },
        { account, permissions },
      );
    }
    if (input.scopes.includes("offline_access")) {
      const refreshToken = randomToken(64);
      await db.insert(refreshTokens).values({
        tokenHash: hashToken(refreshToken),
        familyId: input.familyId ?? crypto.randomUUID(),
        clientId: input.clientId,
        userId: input.userId,
        scopes: input.scopes,
        resource: input.resource,
        expiresAt: input.refreshExpiresAt ?? new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
      });
      response.refresh_token = refreshToken;
    }
    return response;
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
    const consumed = await db
      .update(authorizationCodes)
      .set({ consumedAt: new Date() })
      .where(
        and(
          eq(authorizationCodes.codeHash, authorizationCode.codeHash),
          isNull(authorizationCodes.consumedAt),
        ),
      )
      .returning({ codeHash: authorizationCodes.codeHash });
    if (!consumed.length) throw new OAuthError("invalid_grant", "Authorization code was already used");
    return issueTokenSet({
      userId: authorizationCode.userId,
      clientId: authorizationCode.clientId,
      scopes: authorizationCode.scopes,
      resource: authorizationCode.resource,
      nonce: authorizationCode.nonce,
      authenticatedAt: authorizationCode.authenticatedAt,
    });
  }

  async function exchangeRefreshToken(input: {
    refreshToken: string;
    clientId: string;
    clientSecret?: string;
  }) {
    await authenticateClient(input.clientId, input.clientSecret);
    const tokenHash = hashToken(input.refreshToken);
    const [stored] = await db.select().from(refreshTokens).where(eq(refreshTokens.tokenHash, tokenHash)).limit(1);
    if (!stored || stored.clientId !== input.clientId) {
      throw new OAuthError("invalid_grant", "Refresh token is invalid");
    }
    if (stored.consumedAt || stored.revokedAt || stored.expiresAt <= new Date()) {
      await db
        .update(refreshTokens)
        .set({ revokedAt: new Date() })
        .where(eq(refreshTokens.familyId, stored.familyId));
      throw new OAuthError("invalid_grant", "Refresh token reuse detected");
    }
    const consumed = await db
      .update(refreshTokens)
      .set({ consumedAt: new Date() })
      .where(
        and(
          eq(refreshTokens.tokenHash, tokenHash),
          isNull(refreshTokens.consumedAt),
          isNull(refreshTokens.revokedAt),
          gt(refreshTokens.expiresAt, new Date()),
        ),
      )
      .returning({ tokenHash: refreshTokens.tokenHash });
    if (!consumed.length) {
      await db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.familyId, stored.familyId));
      throw new OAuthError("invalid_grant", "Refresh token reuse detected");
    }
    return issueTokenSet({
      userId: stored.userId,
      clientId: stored.clientId,
      scopes: stored.scopes,
      resource: stored.resource,
      familyId: stored.familyId,
      refreshExpiresAt: stored.expiresAt,
    });
  }

  async function revoke(token: string, clientId: string, clientSecret?: string) {
    await authenticateClient(clientId, clientSecret);
    const [stored] = await db
      .select()
      .from(refreshTokens)
      .where(eq(refreshTokens.tokenHash, hashToken(token)))
      .limit(1);
    if (stored?.clientId === clientId) {
      await db.update(refreshTokens).set({ revokedAt: new Date() }).where(eq(refreshTokens.familyId, stored.familyId));
    }
  }

  async function userInfo(accessToken: string) {
    let payload: Awaited<ReturnType<KeyService["verifyAccessToken"]>>;
    try {
      payload = await keys.verifyAccessToken(accessToken);
    } catch {
      throw new OAuthError("invalid_token", "Access token is invalid", 401);
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
    getClient,
    requiresConsent,
    attachUser,
    clearInteractionUser,
    grantConsent,
    completeAuthorization,
    denialRedirect,
    denyAuthorization,
    exchangeAuthorizationCode,
    exchangeRefreshToken,
    revoke,
    userInfo,
  };
}

export type OAuthService = ReturnType<typeof createOAuthService>;
export const oauthServiceInternals = { parseMetadata };
