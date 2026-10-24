import { beforeAll, afterAll, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { loadConfig, type AppConfig } from "../config.js";
import { createDatabase, type Database } from "../database/client.js";
import { migrateDatabase } from "../database/migrate.js";
import { seedConfiguration } from "../database/seed.js";
import { createEmailDomainService } from "../database/emailDomains.js";
import {
  defaultPermissions,
  emailDomainSuffixes,
  oidcClients,
  oidcPermissions,
  organizations,
  userApplications,
  userPermissions,
  users,
} from "../database/schema.js";
import { createIdentityService, type IdentityService } from "../identity.js";
import { createKeyService, type KeyService } from "./keys.js";
import { createOAuthService, type OAuthService } from "./service.js";

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
    await seedConfiguration(db, config.clients, config.resources);
    emailDomains = createEmailDomainService(db);
    identity = createIdentityService(db, emailDomains, []);
    keys = await createKeyService(config, identity);
    oauth = createOAuthService(config, db, keys, identity);
  }, 120_000);

  afterAll(async () => {
    await close?.();
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
    const user = await identity.upsertFromMicrosoft({
      provider: "basischina-microsoft",
      issuer: "https://login.microsoftonline.com/tenant/v2.0",
      subject: "microsoft-subject",
      email: "user@example.edu",
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
    const redirect = new URL(await oauth.completeAuthorization(started.id));
    const code = redirect.searchParams.get("code")!;
    const tokens = await oauth.exchangeAuthorizationCode({
      code,
      clientId: "portal",
      clientSecret: "portal-secret-long-enough",
      redirectUri: "https://portal.example.test/callback",
      codeVerifier: verifier,
    });
    const access = await keys.verifyAccessToken(String(tokens.access_token));
    expect(access).toMatchObject({
      sub: user.id,
      aud: "urn:basis:api:projects",
      client_id: "portal",
      permissions: ["nethack.Projects.read"],
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
      permissions: ["nethack.Projects.read"],
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
      permissions: ["nethack.Projects.read"],
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
});
