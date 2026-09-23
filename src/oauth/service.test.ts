import { describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../config.js";
import type { IdentityService } from "../identity.js";
import type { KeyService } from "./keys.js";
import { createOAuthService, oauthServiceInternals } from "./service.js";
import { resourceServers } from "../database/schema.js";

const metadata = {
  name: "Portal",
  redirectUris: ["https://portal.example.test/callback"],
  public: false,
  scopes: ["openid"],
};

describe("stored client metadata", () => {
  it("retains descriptive permission definitions", () => {
    const parsed = oauthServiceInternals.parseMetadata({
      ...metadata,
      owners: [{ id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role: "role.ADMIN" }],
      permissions: { "nethack.Projects.submit": "Submit a project" },
    });

    expect(parsed.permissions).toEqual({ "nethack.Projects.submit": "Submit a project" });
  });

  it.each([
    ["RoLe.AdMiN", "role.ADMIN"],
    ["ROLE.GENERAL", "role.GENERAL"],
  ])("accepts the case-insensitive owner role %s", (role, expected) => {
    const parsed = oauthServiceInternals.parseMetadata({
      ...metadata,
      owners: [{ id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role }],
    });

    expect(parsed.owners).toEqual([
      { id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role: expected },
    ]);
  });

  it("rejects unsupported owner roles", () => {
    expect(() =>
      oauthServiceInternals.parseMetadata({
        ...metadata,
        owners: [{ id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role: "role.OWNER" }],
      }),
    ).toThrow("Stored client metadata is invalid");
  });
});

describe("client lookup", () => {
  const clientRow = {
    clientId: "client-1",
    secretHash: "stored-secret-hash",
    resources: ["urn:basis:api:test"],
    requireConsent: false,
    filterMode: null,
    filterContent: ["allowed@example.test"],
    metadata: {
      name: "Portal",
      owners: [{ id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role: "role.ADMIN" }],
      redirectUris: ["https://portal.example.test/callback"],
      public: false,
      scopes: ["openid"],
    },
  };
  const execute = vi.fn(async () => [clientRow]);
  const db = {
    select: () => ({
      from: () => ({
        where: () => ({
          limit: () => ({
            prepare: () => ({ execute }),
          }),
        }),
      }),
    }),
  } as unknown as Parameters<typeof createOAuthService>[1];

  const config = {
    issuer: "https://auth.example.test",
    cookieKeys: ["a".repeat(32)],
  } as AppConfig;
  const service = createOAuthService(
    config,
    db,
    {} as KeyService,
    {} as IdentityService,
  );

  it("returns only the id and name to the frontend", async () => {
    await expect(service.getClient("client-1")).resolves.toEqual({ id: "client-1", name: "Portal" });
  });

  it("serves repeated lookups from the in-memory cache", async () => {
    await service.getClient("client-1");
    await service.getClient("client-1");
    expect(execute).toHaveBeenCalledTimes(1);
  });

  it("throws when the client does not exist", async () => {
    const missing = vi.fn(async () => []);
    const missingDb = {
      select: () => ({ from: () => ({ where: () => ({ limit: () => ({ prepare: () => ({ execute: missing }) }) }) }) }),
    } as unknown as Parameters<typeof createOAuthService>[1];
    const missingService = createOAuthService(config, missingDb, {} as KeyService, {} as IdentityService);
    await expect(missingService.getClient("missing")).rejects.toThrow("not registered or has been disabled");
  });
});

describe("authorization resource check", () => {
  const clientRow = {
    clientId: "client-1",
    secretHash: "stored-secret-hash",
    resources: ["urn:basis:api:missing"],
    requireConsent: false,
    filterMode: null,
    filterContent: [],
    metadata: {
      name: "Portal",
      owners: [{ id: "c6ba1588-03bb-4c61-a4e1-3c7c82e919b5", role: "role.ADMIN" }],
      redirectUris: ["https://portal.example.test/callback"],
      public: false,
      scopes: ["openid"],
    },
  };
  const execute = vi.fn(async () => [clientRow]);
  const db = {
    select: () => ({
      from: (table: unknown) => ({
        where: () => ({
          limit: () => (table === resourceServers ? [] : { prepare: () => ({ execute }) }),
        }),
      }),
    }),
  } as unknown as Parameters<typeof createOAuthService>[1];
  const config = {
    issuer: "https://auth.example.test",
    cookieKeys: ["a".repeat(32)],
  } as AppConfig;
  const service = createOAuthService(config, db, {} as KeyService, {} as IdentityService);

  it("names the missing audience in the unknown-resource error", async () => {
    await expect(
      service.startAuthorization({
        initialUri: "/oauth/authorize?client_id=client-1",
        clientId: "client-1",
        redirectUri: "https://portal.example.test/callback",
        responseType: "code",
        scope: "openid",
        resources: ["urn:basis:api:missing"],
        state: "state",
        nonce: "nonce",
        codeChallenge: "a".repeat(43),
        codeChallengeMethod: "S256",
      }),
    ).rejects.toThrow('Resource server "urn:basis:api:missing" is not registered');
  });

  it("allows public OIDC scopes without adding them to the client or resource", async () => {
    const publicScopeClient = {
      ...clientRow,
      resources: ["urn:basis:api:test"],
      metadata: { ...clientRow.metadata, scopes: [] },
    };
    const clientExecute = vi.fn(async () => [publicScopeClient]);
    const dbWithPublicScopes = {
      select: () => ({
        from: (table: unknown) => ({
          where: () => ({
            limit: () => table === resourceServers
              ? [{ audience: "urn:basis:api:test", scopes: [] }]
              : { prepare: () => ({ execute: clientExecute }) },
          }),
        }),
      }),
      insert: () => ({ values: vi.fn(async () => undefined) }),
    } as unknown as Parameters<typeof createOAuthService>[1];
    const publicScopeService = createOAuthService(
      config,
      dbWithPublicScopes,
      {} as KeyService,
      {} as IdentityService,
    );

    await expect(
      publicScopeService.startAuthorization({
        initialUri: "/oauth/authorize?client_id=client-1",
        clientId: "client-1",
        redirectUri: "https://portal.example.test/callback",
        responseType: "code",
        scope: "openid profile email offline_access",
        resources: ["urn:basis:api:test"],
        state: "state",
        nonce: "nonce",
        codeChallenge: "a".repeat(43),
        codeChallengeMethod: "S256",
      }),
    ).resolves.toMatchObject({ interactionToken: expect.any(String) });
  });
});
