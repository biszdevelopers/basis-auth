import { beforeAll, afterAll, describe, expect, it, vi } from "vitest";
import { createHmac } from "node:crypto";
import { eq } from "drizzle-orm";
import { loadConfig, type AppConfig } from "../config.js";
import { createDatabase, type Database } from "../database/client.js";
import { migrateDatabase } from "../database/migrate.js";
import { seedConfiguration } from "../database/seed.js";
import { createEmailDomainService } from "../database/emailDomains.js";
import {
  defaultPermissions,
  emailDomainSuffixes,
  oidcClientOrganizations,
  oidcClients,
  oidcPermissions,
  organizations,
  resourceServers,
  userApplications,
  userPermissions,
  users,
} from "../database/schema.js";
import { createIdentityService, type IdentityService } from "../identity.js";
import { createInternalApplicationService } from "../internal/applications.js";
import { createInternalApp } from "../internal/app.js";
import { createBackchannelVerifier } from "../internal/backchannel.js";
import { createInternalUserService } from "../internal/users.js";
import { createResourceVerifier } from "../internal/resource-auth.js";
import { portalScopedDefaults } from "../internal/portal-permissions.js";
import { createKeyService, type KeyService } from "./keys.js";
import { createLogoutService } from "./logout.js";
import { createOAuthService, type OAuthService } from "./service.js";
import { applyClientEdit, getClientDetail, listClients } from "../../scripts/clients.js";

const runIntegration =
  process.env.RUN_POSTGRES_TESTS === "1" && Boolean(process.env.DATABASE_URL);

describe.skipIf(!runIntegration)("OAuth flow with PostgreSQL", () => {
  let db: Database;
  let close: () => Promise<void>;
  let config: AppConfig;
  let identity: IdentityService;
  let keys: KeyService;
  let oauth: OAuthService;
  let emailDomains: ReturnType<typeof createEmailDomainService>;

  const databaseUrl = process.env.DATABASE_URL!;

  beforeAll(async () => {
    config = await loadConfig({
      NODE_ENV: "test",
      DATABASE_URL: databaseUrl,
      MANAGEMENT_PORTAL_CLIENT_ID: "portal",
      MANAGEMENT_PORTAL_AUDIENCE: "devconnect://noesis",
      OIDC_ISSUER: "https://auth.example.test",
      OIDC_COOKIE_KEYS: "a".repeat(32),
      OIDC_RESOURCES_JSON: JSON.stringify([
        { audience: "urn:basis:api:projects", scopes: ["nethack.access"] },
      ]),
      OIDC_CLIENTS_JSON: JSON.stringify([
        {
          clientId: "portal",
          clientSecret: "portal-secret-long-enough",
          redirectUris: ["https://portal.example.test/callback"],
          public: false,
          scopes: ["nethack.access"],
          permissions: {
            "nethack.Projects.read": "View all projects",
            "integration.live-default": "A default added after first login",
          },
          defaultPermissions: ["nethack.Projects.read"],
          resources: ["urn:basis:api:projects"],
          requireConsent: false,
          organizationIds: ["cbc6e1e2-a6bb-4002-bbdc-6da892a051a7"],
        },
        {
          clientId: "other-app",
          clientSecret: "other-app-secret-long-enough",
          redirectUris: ["https://other.example.test/callback"],
          public: false,
          scopes: ["nethack.access"],
          permissions: { "other.Application.read": "Read the other app" },
          defaultPermissions: ["other.Application.read"],
          resources: ["urn:basis:api:projects"],
          requireConsent: false,
          organizationIds: ["cbc6e1e2-a6bb-4002-bbdc-6da892a051a7"],
        },
      ]),
    });
    await migrateDatabase(databaseUrl);
    const database = createDatabase(databaseUrl);
    db = database.db;
    close = () => database.pool.end();
    await seedConfiguration(db, config.clients, config.resources, { clientId: config.managementPortalClientId });
    emailDomains = createEmailDomainService(db);
    identity = createIdentityService(db, emailDomains, []);
    keys = await createKeyService(config, identity);
    oauth = createOAuthService(config, db, keys, identity);
  }, 120_000);

  afterAll(async () => {
    await close?.();
  });

  it("verifies a configured webhook before saving it and preserves it unless explicitly cleared", async () => {
    const resource = { audience: "urn:basis:api:logout-test", scopes: [] };
    const uri = "https://projects.example.test/logout";
    const loadResource = () => db.select().from(resourceServers).where(eq(resourceServers.audience, resource.audience));
    const verifyDestination = vi.fn().mockResolvedValueOnce("rejected").mockResolvedValueOnce("verified");
    const applications = createInternalApplicationService(db, config.issuer, oauth.invalidateClient, {
      verifyDestination, validate: vi.fn(),
    });

    await seedConfiguration(db, [], [{ ...resource, backchannelLogoutUri: uri }]);
    await expect(loadResource()).resolves.toEqual([expect.objectContaining({ backchannelLogoutUri: null })]);
    await expect(applications.reconcileConfiguredLogoutUri(resource.audience, uri)).rejects.toMatchObject({ status: 502 });
    await expect(loadResource()).resolves.toEqual([expect.objectContaining({ backchannelLogoutUri: null })]);
    await applications.reconcileConfiguredLogoutUri(resource.audience, uri);
    await applications.reconcileConfiguredLogoutUri(resource.audience, uri);
    expect(verifyDestination).toHaveBeenCalledTimes(2);
    await seedConfiguration(db, [], [resource]);
    await expect(loadResource()).resolves.toEqual([expect.objectContaining({ backchannelLogoutUri: uri })]);
    await seedConfiguration(db, [], [{ ...resource, backchannelLogoutUri: null }]);
    await expect(loadResource()).resolves.toEqual([expect.objectContaining({ backchannelLogoutUri: null })]);
  });

  it("checks resource ownership, active scope assignments, and the stored logout destination", async () => {
    const ownerId = crypto.randomUUID();
    const otherId = crypto.randomUUID();
    const ids = [ownerId, otherId];
    await db.insert(users).values(ids.map((id) => ({
      id, provider: "resource-integration", upstreamIssuer: "test", upstreamSubject: id, email: `${id}@example.test`,
    })));
    const backchannel = createBackchannelVerifier(db, 1000);
    const applications = createInternalApplicationService(db, config.issuer, oauth.invalidateClient, backchannel);
    const owner = {
      id: ownerId,
      permissions: [
        "BiszPortal.Applications.create",
        "BiszPortal.Applications.read.me",
        "BiszPortal.Applications.delete.me",
        "BiszPortal.ApplicationResources.manage",
        "BiszPortal.Resources.read.me",
        "BiszPortal.Resources.update.me",
        "BiszPortal.Resources.delete.me",
      ],
    };
    const settings = {
      name: "Resource test application",
      public: true,
      redirectUris: ["https://example.test/callback"],
      organizationIds: ["cbc6e1e2-a6bb-4002-bbdc-6da892a051a7"],
      requireConsent: false,
      filterMode: null,
      filterContent: [],
    };
    const { clientId } = await applications.createApplication(owner, settings);
    const resourceId = `urn:basis:api:${clientId}`;
    const othersOnly = {
      id: otherId,
      permissions: ["BiszPortal.Applications.read.others", "BiszPortal.Resources.read.others"],
    };
    const ownResource = { id: ownerId, permissions: othersOnly.permissions };
    const resourceWildcard = { id: otherId, permissions: ["BiszPortal.Resources.all"] };
    const logoutUri = "http://localhost:4321/logout";

    try {
      await expect(applications.list(othersOnly)).resolves.toContainEqual(expect.objectContaining({ clientId }));
      await expect(applications.detail(clientId, ownResource)).rejects.toMatchObject({ status: 404 });
      await expect(applications.detail(clientId, othersOnly)).resolves.toMatchObject({ role: null });
      await expect(applications.resourceDetail(resourceId, ownResource)).rejects.toMatchObject({ status: 404 });
      await expect(applications.listResources(owner)).resolves.toEqual([{ name: `${settings.name} API`, resourceId }]);
      await expect(applications.resourceDetail(resourceId, othersOnly)).resolves.toMatchObject({
        capabilities: { update: false, delete: false },
      });
      await expect(applications.setResourceLogoutUri(resourceId, othersOnly, logoutUri))
        .rejects.toMatchObject({ status: 403 });
      await expect(applications.listResources({ id: ownerId, permissions: [] })).rejects.toMatchObject({ status: 403 });

      const verifyResource = createResourceVerifier(db);
      await expect(verifyResource(resourceId, "sk-1")).resolves.toBe(false);
      const { resourceSecret: oldSecret } = await applications.rotateResourceSecret(resourceId, owner);
      await expect(verifyResource(resourceId, oldSecret)).resolves.toBe(true);
      await expect(applications.rotateResourceSecret(resourceId, othersOnly)).rejects.toMatchObject({ status: 403 });
      const { resourceSecret: newSecret } = await applications.rotateResourceSecret(resourceId, owner);
      expect(newSecret).toMatch(/^sk-[A-Za-z0-9_-]{43}$/);
      const [stored] = await db.select({ secretHash: resourceServers.secretHash }).from(resourceServers)
        .where(eq(resourceServers.audience, resourceId));
      expect(stored?.secretHash).toMatch(/^scrypt:/);
      await expect(verifyResource(resourceId, oldSecret)).resolves.toBe(false);
      await expect(verifyResource(resourceId, newSecret)).resolves.toBe(true);
      await expect(applications.resourceDetail(resourceId, owner)).resolves.not.toHaveProperty("resourceSecret");

      await applications.updateResourceScope(resourceId, owner, { action: "add", scope: "test.read" });
      await applications.updateResourceScope(resourceId, owner, { action: "add", scope: "test.all" });
      await applications.updateScopes(clientId, owner, { [resourceId]: ["test.read"] });
      await expect(applications.updateResourceScope(resourceId, owner, { action: "remove", scope: "test.read" }))
        .rejects.toMatchObject({ status: 409, code: "scope_in_use" });
      await expect(applications.deleteResource(resourceId, owner)).rejects.toMatchObject({ status: 409, code: "resource_in_use" });
      await applications.updateScopes(clientId, owner, { [resourceId]: [] });
      await expect(applications.updateResourceScope(resourceId, owner, { action: "remove", scope: "test.read" }))
        .resolves.toMatchObject({ availableScopes: ["test.all"] });

      const internalApp = createInternalApp({ verifyResource }, createInternalUserService(db, emailDomains), {
        applications, keys, clientId: "portal", audience: config.managementPortalAudience, scope: config.managementPortalScope,
      });
      const fetch = vi.fn<typeof globalThis.fetch>();
      vi.stubGlobal("fetch", fetch);
      const validate = (nonce: string, hash: string, secret = newSecret) =>
        internalApp.request("/internal/backchannel/validate", {
          method: "POST",
          headers: { authorization: `Bearer ${secret}`, "x-basis-resource": encodeURIComponent(resourceId) },
          body: new URLSearchParams({ nonce, challenge_hash: hash }),
        });
      const proof = () => {
        const params = fetch.mock.lastCall?.[1]?.body as URLSearchParams;
        return {
          nonce: params.get("nonce")!,
          hash: createHmac("sha256", newSecret).update(params.get("challenge")!).digest("hex"),
        };
      };
      fetch.mockResolvedValueOnce(new Response(null, { status: 202 }));
      const saving = applications.setResourceLogoutUri(resourceId, resourceWildcard, logoutUri);
      await vi.waitFor(() => expect(fetch).toHaveBeenCalledTimes(1));
      expect(fetch).toHaveBeenCalledWith(logoutUri, expect.objectContaining({
        method: "POST", redirect: "error",
      }));
      expect((fetch.mock.lastCall?.[1]?.body as URLSearchParams).get("action")).toBe("test");
      await expect(applications.resourceDetail(resourceId, owner)).resolves.toMatchObject({ backchannelLogoutUri: null });
      const { nonce, hash } = proof();
      expect((await validate(nonce, hash, oldSecret)).status).toBe(401);
      expect((await validate(nonce, "0".repeat(64))).status).toBe(400);
      expect(await backchannel.validate("wrong-audience", newSecret, nonce, hash)).toBe("invalid");
      const validation = await validate(nonce, hash);
      expect(validation.status).toBe(200);
      expect(await validation.json()).toEqual({ status: "successful" });
      await expect(saving).resolves.toEqual({ backchannelLogoutUri: logoutUri });
      expect((await validate(nonce, hash)).status).toBe(400);

      const changedUri = "https://resource.example.test/replacement";
      fetch.mockResolvedValueOnce(new Response(null, { status: 200 }));
      await expect(applications.setResourceLogoutUri(resourceId, owner, changedUri))
        .rejects.toMatchObject({ status: 502, code: "backchannel_test_failed" });
      fetch.mockResolvedValueOnce(new Response(null, { status: 202 }));
      await expect(applications.setResourceLogoutUri(resourceId, owner, changedUri))
        .rejects.toMatchObject({ status: 504, code: "backchannel_timeout" });
      const expired = proof();
      const timeout = await validate(expired.nonce, expired.hash);
      expect(timeout.status).toBe(408);
      expect(await timeout.json()).toEqual({ error: "timeout" });

      fetch.mockResolvedValueOnce(new Response(null, { status: 204 }));
      const logout = createLogoutService(db, { issueLogoutToken: vi.fn().mockResolvedValue("signed-token") });
      await expect(logout(ownerId, resourceId)).resolves.toBe("delivered");
      expect(fetch).toHaveBeenLastCalledWith(logoutUri, expect.objectContaining({
        method: "POST", body: new URLSearchParams({ logout_token: "signed-token" }),
      }));
      await applications.setResourceLogoutUri(resourceId, owner, null);
      await expect(logout(ownerId, resourceId)).resolves.toBe("logout_not_configured");

      await applications.deleteApplication(clientId, owner);
      await applications.deleteResource(resourceId, owner);
      await expect(applications.resourceDetail(resourceId, owner)).rejects.toMatchObject({ status: 404 });
    } finally {
      vi.unstubAllGlobals();
      await db.delete(oidcClients).where(eq(oidcClients.clientId, clientId));
      await db.delete(resourceServers).where(eq(resourceServers.audience, resourceId));
      for (const id of ids) await db.delete(users).where(eq(users.id, id));
    }
  });

  it("stores permission definitions separately from client metadata", async () => {
    const [client] = await db.select({ metadata: oidcClients.metadata }).from(oidcClients).limit(1);

    expect(client?.metadata).toMatchObject({
      owners: [
        {
          id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5",
          role: "role.ADMIN",
        },
      ],
    });
    expect(client?.metadata).not.toHaveProperty("permissions");
    await expect(db.select().from(oidcPermissions)).resolves.toEqual(expect.arrayContaining([
      expect.objectContaining({ clientId: "portal", permission: "nethack.Projects.read" }),
    ]));
  });

  it("stores application-specific defaults and starts without historical affiliations", async () => {
    const defaults = await db.select().from(defaultPermissions);
    expect(defaults).toEqual(expect.arrayContaining([
      expect.objectContaining({ applicationId: "portal", permission: "nethack.Projects.read" }),
    ]));
    await expect(db.select().from(userApplications)).resolves.toEqual([]);
  });

  it("manages default permissions atomically", async () => {
    const applications = createInternalApplicationService(
      db,
      config.issuer,
      () => undefined,
    );
    const actor = {
      id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5",
      permissions: ["BiszPortal.ApplicationPermissions.manage", "BiszPortal.Applications.read.me"],
    };
    const selected = ["nethack.Projects.read", "integration.live-default"];

    await applications.updateDefaultPermissions("portal", actor, selected);
    await expect(applications.detail("portal", actor)).resolves.toMatchObject({
      defaultPermissions: [...selected].sort(),
    });

    await applications.updateDefaultPermissions("portal", actor, []);
    await expect(
      db.select().from(defaultPermissions).where(eq(defaultPermissions.applicationId, "portal")),
    ).resolves.toEqual([]);
    await expect(
      applications.updateDefaultPermissions("portal", actor, ["undefined.permission"]),
    ).rejects.toMatchObject({ status: 400, code: "invalid_default_permissions" });
    await expect(
      applications.updateDefaultPermissions("portal", actor, ["nethack.Projects.read", "nethack.Projects.read"]),
    ).rejects.toMatchObject({ status: 400, code: "invalid_default_permissions" });

    await applications.updateDefaultPermissions("portal", actor, ["nethack.Projects.read", ...portalScopedDefaults]);
  });

  it("seeds domains and clears user links when a suffix is deleted", async () => {
    const policies = await db.select().from(organizations);
    const suffixes = await db.select().from(emailDomainSuffixes);
    expect(policies).toEqual(expect.arrayContaining([
      expect.objectContaining({
        organizationId: "cbc6e1e2-a6bb-4002-bbdc-6da892a051a7",
        firstParty: true,
      }),
    ]));
    expect(suffixes.map((row) => row.suffix)).toEqual(expect.arrayContaining([
      "basis-global.com",
      "basischina.com",
    ]));

    const marker = crypto.randomUUID();
    const policy = await emailDomains.createPolicy({ organizationId: crypto.randomUUID(), firstParty: false });
    const suffix = await emailDomains.createSuffix({
      suffix: `${marker}.example.com`,
      organizationId: policy.id,
    });
    await expect(emailDomains.getSuffix(suffix.id)).resolves.toMatchObject({ suffix: `${marker}.example.com` });
    await emailDomains.updateSuffix(suffix.id, { suffix: `${marker}.example.org` });
    const user = await identity.upsertFromMicrosoft({
      provider: "integration-microsoft",
      issuer: "https://login.microsoftonline.com/organizations/v2.0",
      subject: marker,
      email: `person@${marker}.example.org`,
    });
    expect(user.emailSuffixId).toBe(suffix.id);

    await emailDomains.deleteSuffix(suffix.id);
    const [updated] = await db.select({ emailSuffixId: users.emailSuffixId }).from(users).where(eq(users.id, user.id));
    expect(updated?.emailSuffixId).toBeNull();
    await emailDomains.deletePolicy(policy.id);
  });

  it("issues audience-bound tokens, rejects code replay, and detects refresh reuse", async () => {
    const resourceAudience = "urn:basis:api:projects";
    const logoutUri = "https://projects.example.test/logout";
    const setLogoutUri = (backchannelLogoutUri: string | null) =>
      db.update(resourceServers).set({ backchannelLogoutUri })
        .where(eq(resourceServers.audience, resourceAudience));
    await setLogoutUri(logoutUri);
    const user = await identity.upsertFromMicrosoft({
      provider: "basischina-microsoft",
      issuer: "https://login.microsoftonline.com/tenant/v2.0",
      subject: "microsoft-subject",
      email: "user@basis-global.com",
      displayName: "Example User",
    });
    const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    const started = await oauth.startAuthorization({
      initialUri: "/oauth/authorize",
      clientId: "portal",
      redirectUri: "https://portal.example.test/callback",
      responseType: "code",
      scope: "openid profile email offline_access nethack.access",
      resources: ["urn:basis:api:projects"],
      state: "state",
      nonce: "nonce",
      codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      codeChallengeMethod: "S256",
      session: { userId: user.id, authenticatedAt: new Date() },
    });
    await setLogoutUri(null);
    await expect(oauth.completeAuthorization(started.id))
      .rejects.toMatchObject({ error: "invalid_resource", code: 14408 });
    await setLogoutUri(logoutUri);
    const redirect = new URL(await oauth.completeAuthorization(started.id));
    const code = redirect.searchParams.get("code")!;
    const exchangeRequest = {
      code,
      clientId: "portal",
      clientSecret: "portal-secret-long-enough",
      redirectUri: "https://portal.example.test/callback",
      codeVerifier: verifier,
    };
    await setLogoutUri(null);
    await expect(oauth.exchangeAuthorizationCode(exchangeRequest))
      .rejects.toMatchObject({ error: "invalid_resource", code: 14408 });
    await setLogoutUri(logoutUri);
    const tokens = await oauth.exchangeAuthorizationCode(exchangeRequest);
    const access = await keys.verifyAccessToken(String(tokens.access_token));
    const expectedPortalPermissions = ["nethack.Projects.read", ...portalScopedDefaults].sort();
    expect(access).toMatchObject({
      sub: user.id,
      aud: "urn:basis:api:projects",
      client_id: "portal",
      permissions: expectedPortalPermissions,
      gty: "authorization_code",
    });
    const defaultRows = await db.select().from(userPermissions).where(eq(userPermissions.userId, user.id));
    expect(defaultRows).toEqual(expect.arrayContaining([
      expect.objectContaining({ applicationId: "portal", permission: "nethack.Projects.read" }),
    ]));

    await db.insert(defaultPermissions).values({
      applicationId: "portal",
      permission: "integration.live-default",
    }).onConflictDoNothing();
    const repeatPortalLogin = await oauth.startAuthorization({
      initialUri: "/oauth/authorize",
      clientId: "portal",
      redirectUri: "https://portal.example.test/callback",
      responseType: "code",
      scope: "openid profile email offline_access nethack.access",
      resources: ["urn:basis:api:projects"],
      state: "state-again",
      nonce: "nonce-again",
      codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      codeChallengeMethod: "S256",
      session: { userId: user.id, authenticatedAt: new Date() },
    });
    const repeatCode = new URL(await oauth.completeAuthorization(repeatPortalLogin.id)).searchParams.get("code")!;
    const repeated = await oauth.exchangeAuthorizationCode({
      code: repeatCode,
      clientId: "portal",
      clientSecret: "portal-secret-long-enough",
      redirectUri: "https://portal.example.test/callback",
      codeVerifier: verifier,
    });
    await expect(keys.verifyAccessToken(String(repeated.access_token))).resolves.toMatchObject({
      client_id: "portal",
      permissions: expectedPortalPermissions,
    });

    const otherLogin = await oauth.startAuthorization({
      initialUri: "/oauth/authorize",
      clientId: "other-app",
      redirectUri: "https://other.example.test/callback",
      responseType: "code",
      scope: "openid profile email offline_access nethack.access",
      resources: ["urn:basis:api:projects"],
      state: "other-state",
      nonce: "other-nonce",
      codeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
      codeChallengeMethod: "S256",
      session: { userId: user.id, authenticatedAt: new Date() },
    });
    const otherCode = new URL(await oauth.completeAuthorization(otherLogin.id)).searchParams.get("code")!;
    const otherTokens = await oauth.exchangeAuthorizationCode({
      code: otherCode,
      clientId: "other-app",
      clientSecret: "other-app-secret-long-enough",
      redirectUri: "https://other.example.test/callback",
      codeVerifier: verifier,
    });
    await expect(keys.verifyAccessToken(String(otherTokens.access_token))).resolves.toMatchObject({
      client_id: "other-app",
      permissions: ["other.Application.read"],
    });
    await expect(
      oauth.exchangeAuthorizationCode({
        code,
        clientId: "portal",
        clientSecret: "portal-secret-long-enough",
        redirectUri: "https://portal.example.test/callback",
        codeVerifier: verifier,
      }),
    ).rejects.toMatchObject({ error: "invalid_grant" });

    const firstRefresh = String(tokens.refresh_token);
    const rotated = await oauth.exchangeRefreshToken({
      refreshToken: firstRefresh,
      clientId: "portal",
      clientSecret: "portal-secret-long-enough",
    });
    await expect(keys.verifyAccessToken(String(rotated.access_token))).resolves.toMatchObject({
      sub: user.id,
      client_id: "portal",
      gty: "refresh_token",
      permissions: expectedPortalPermissions,
    });
    await db
      .delete(defaultPermissions)
      .where(eq(defaultPermissions.applicationId, "portal"));
    await expect(
      oauth.exchangeRefreshToken({
        refreshToken: firstRefresh,
        clientId: "portal",
        clientSecret: "portal-secret-long-enough",
      }),
    ).rejects.toMatchObject({ error: "invalid_grant" });
    await expect(
      oauth.exchangeRefreshToken({
        refreshToken: String(rotated.refresh_token),
        clientId: "portal",
        clientSecret: "portal-secret-long-enough",
      }),
    ).rejects.toMatchObject({ error: "invalid_grant" });
  });

  it("moves client configuration and authorization state to a new client ID", async () => {
    const current = await getClientDetail(db, "other-app");
    const nextClientId = `renamed-${crypto.randomUUID()}`;
    const [user] = await db.select({ id: users.id }).from(users).limit(1);
    expect(user).toBeDefined();

    await db.insert(userPermissions).values({
      userId: user!.id,
      applicationId: "other-app",
      permission: "other.Application.read",
    }).onConflictDoNothing();
    await db.insert(userApplications).values({
      userId: user!.id,
      applicationId: "other-app",
    }).onConflictDoNothing();

    await applyClientEdit(db, "other-app", {
      ...current,
      clientId: nextClientId,
      newSecret: undefined,
      resourceScopes: new Map(current.resources.map((resource) => [resource, current.scopes])),
    });

    await expect(
      db.select().from(oidcClients).where(eq(oidcClients.clientId, "other-app")),
    ).resolves.toEqual([]);
    await expect(getClientDetail(db, nextClientId)).resolves.toMatchObject({
      clientId: nextClientId,
      name: current.name,
      public: current.public,
      redirectUris: current.redirectUris,
      resources: current.resources,
      organizationIds: current.organizationIds,
    });
    await expect(
      db.select().from(oidcPermissions).where(eq(oidcPermissions.clientId, nextClientId)),
    ).resolves.toEqual(expect.arrayContaining([
      expect.objectContaining({ permission: "other.Application.read" }),
    ]));
    await expect(
      db.select().from(defaultPermissions).where(eq(defaultPermissions.applicationId, nextClientId)),
    ).resolves.toEqual(expect.arrayContaining([
      expect.objectContaining({ permission: "other.Application.read" }),
    ]));
    await expect(
      db.select().from(userPermissions).where(eq(userPermissions.applicationId, nextClientId)),
    ).resolves.toEqual(expect.arrayContaining([expect.objectContaining({ userId: user!.id })]));
    await expect(
      db.select().from(userApplications).where(eq(userApplications.applicationId, nextClientId)),
    ).resolves.toEqual(expect.arrayContaining([expect.objectContaining({ userId: user!.id })]));
    await expect(
      db.select().from(oidcClientOrganizations).where(eq(oidcClientOrganizations.clientId, nextClientId)),
    ).resolves.toHaveLength(1);

    const listed = await listClients(db);
    expect(listed.some((client) => client.clientId === "other-app")).toBe(false);
    expect(listed.find((client) => client.clientId === nextClientId)).toMatchObject({
      hasSecret: true,
      updatedAt: expect.any(String),
    });
  });
});
