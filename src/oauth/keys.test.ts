import { decodeJwt, exportJWK, generateKeyPair, importJWK, SignJWT } from "jose";
import { describe, expect, it, vi } from "vitest";
import type { AppConfig } from "../config.js";
import type { IdentityService } from "../identity.js";
import { createKeyService } from "./keys.js";

function buildConfig(): AppConfig {
  return { issuer: "https://auth.example.test", jwks: { keys: [{} as never] } } as unknown as AppConfig;
}

async function rsaJwk() {
  const { privateKey } = await generateKeyPair("RS256", { extractable: true });
  const jwk = await exportJWK(privateKey);
  jwk.kid = "test";
  return jwk;
}

const USER_ID = "d2c3f635-527c-4c0a-bc1c-15d6af3f0946";

describe("ID token claims", () => {
  it("uses the public profile-picture endpoint for the standard picture claim", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findAccount: async () => ({
        accountId: USER_ID,
        claims: async () => ({ sub: USER_ID }),
      }),
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const token = await keys.issueIdToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["openid", "profile"],
      nonce: "nonce",
      authenticatedAt: new Date(),
      accessToken: "access-token",
    });

    expect(decodeJwt(token).picture).toBe(
      "https://auth.example.test/api/picture/d2c3f635-527c-4c0a-bc1c-15d6af3f0946",
    );
  });

  it("rejects id-token issuance when the account disappears", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = { findAccount: async () => undefined } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    await expect(
      keys.issueIdToken({
        userId: USER_ID,
        clientId: "client",
        scopes: ["openid"],
        nonce: "n",
        authenticatedAt: new Date(),
        accessToken: "a",
      }),
    ).rejects.toThrow("User no longer exists");
  });

  it("uses a preloaded account without re-reading identity", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const findAccount = vi.fn(async () => ({
      accountId: USER_ID,
      claims: async () => ({ sub: USER_ID }),
    }));
    const identity = { findAccount } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    await keys.issueIdToken(
      {
        userId: USER_ID,
        clientId: "client",
        scopes: ["openid"],
        nonce: "nonce",
        authenticatedAt: new Date(),
        accessToken: "access-token",
      },
      { account: { accountId: USER_ID, claims: async () => ({ sub: USER_ID }) }, permissions: [] },
    );

    expect(findAccount).not.toHaveBeenCalled();
  });
});

describe("access-token user state", () => {
  it("issues and verifies client-credentials tokens without a user", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const findUserCompact = vi.fn();
    const keys = await createKeyService(config, { findUserCompact } as unknown as IdentityService);

    const token = await keys.issueApplicationAccessToken({
      clientId: "application-id",
      scopes: ["projects.read"],
      resource: "urn:basis:api:projects",
    });

    expect(decodeJwt(token)).toMatchObject({
      sub: "application-id",
      client_id: "application-id",
      scope: "projects.read",
      permissions: [],
      gty: "client_credentials",
      aud: "urn:basis:api:projects",
    });
    await expect(keys.verifyAccessToken(token, "urn:basis:api:projects")).resolves.toMatchObject({
      sub: "application-id",
      client_id: "application-id",
    });
    expect(findUserCompact).not.toHaveBeenCalled();
  });

  it("rejects disabled subjects and tokens at the revocation barrier", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => ["participant"],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const token = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["user.write.email"],
      resource: "urn:basis:api:test",
    });
    expect(decodeJwt(token).gty).toBe("authorization_code");
    await expect(keys.verifyAccessToken(token)).resolves.toMatchObject({ sub: USER_ID });
    const refreshedToken = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["user.write.email"],
      resource: "urn:basis:api:test",
      grantType: "refresh_token",
    });
    expect(decodeJwt(refreshedToken).gty).toBe("refresh_token");

    const issuedAt = decodeJwt(token).iat!;
    user.tokensValidAfter = new Date(issuedAt * 1000);
    await expect(keys.verifyAccessToken(token)).rejects.toThrow("revoked");

    user.tokensValidAfter = null;
    user.disabled = true;
    await expect(
      keys.issueAccessToken({ userId: USER_ID, clientId: "client", scopes: [], resource: "urn:basis:api:test" }),
    ).rejects.toThrow("disabled");
  });

  it("enforces the audience only when a resource is supplied", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => ["participant"],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const token = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["user.write.email"],
      resource: "urn:basis:api:test",
    });

    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).resolves.toMatchObject({ sub: USER_ID });
    await expect(keys.verifyAccessToken(token, "urn:wrong:resource")).rejects.toThrow();
    await expect(keys.verifyAccessToken(token)).resolves.toMatchObject({ sub: USER_ID });
  });

  it("always includes the permissions claim, even without an OAuth permissions scope", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => ["participant"],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const without = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["openid"],
      resource: "urn:basis:api:test",
    });
    expect(decodeJwt(without).permissions).toEqual(["participant"]);

    const withScope = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["openid", "permissions"],
      resource: "urn:basis:api:test",
    });
    expect(decodeJwt(withScope).permissions).toEqual(["participant"]);
  });

  it("issues via preloaded user and permissions without re-querying identity", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const findUser = vi.fn(async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }));
    const permissionsFor = vi.fn(async () => ["participant"]);
    const identity = {
      findUser,
      permissionsFor,
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    await keys.issueAccessToken(
      { userId: USER_ID, clientId: "client", scopes: ["openid"], resource: "urn:basis:api:test" },
      { user: { id: USER_ID, disabled: false, tokensValidAfter: null }, permissions: ["participant"] },
    );

    expect(findUser).not.toHaveBeenCalled();
    expect(permissionsFor).not.toHaveBeenCalled();
  });

  it("issues a token without an audience when no resource is requested", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findUserCompact: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "client", scopes: ["openid"] });
    expect(decodeJwt(token).aud).toBeUndefined();
    await expect(keys.verifyAccessToken(token)).resolves.toMatchObject({ sub: USER_ID });
  });
});

describe("key service error paths", () => {
  it("rejects a config whose first signing key is missing the private exponent", async () => {
    const config = buildConfig();
    (config.jwks as { keys: unknown[] }).keys = [{ kty: "RSA", n: "x", e: "x" }];
    await expect(createKeyService(config, {} as unknown as IdentityService)).rejects.toThrow("private RSA key");
  });

  it("rejects a config whose first signing key is not RSA", async () => {
    const config = buildConfig();
    (config.jwks as { keys: unknown[] }).keys = [{ kty: "EC", d: "x" }];
    await expect(createKeyService(config, {} as unknown as IdentityService)).rejects.toThrow("private RSA key");
  });

  it("rejects access tokens with structurally invalid claims", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findUserCompact: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const key = await importJWK(jwk, "RS256");
    const sign = (claims: Record<string, unknown>) =>
      new SignJWT(claims)
        .setProtectedHeader({ alg: "RS256", typ: "at+jwt", kid: "test" })
        .setIssuer(config.issuer)
        .setAudience("urn:basis:api:test")
        .sign(key);
    const expectInvalid = async (claims: Record<string, unknown>) =>
      await expect(keys.verifyAccessToken(await sign(claims), "urn:basis:api:test")).rejects.toThrow(
        "Access token claims are invalid",
      );

    await expectInvalid({});
    await expectInvalid({ sub: USER_ID });
    await expectInvalid({ sub: USER_ID, client_id: "client" });
    await expectInvalid({ sub: USER_ID, client_id: "client", scope: "openid" });
    await expectInvalid({ sub: USER_ID, client_id: "client", scope: "openid", jti: "jti" });
    await expectInvalid({ sub: USER_ID, client_id: "client", scope: "openid", jti: "jti", iat: 1, permissions: "nope" });
    await expectInvalid({ sub: USER_ID, client_id: "client", scope: "openid", jti: "jti", iat: 1, permissions: [1] });
  });

  it("rejects verification when the subject no longer exists", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => undefined,
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["openid"],
      resource: "urn:basis:api:test",
    });
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).rejects.toThrow("revoked");
  });

  it("rejects verification for a disabled subject", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "client",
      scopes: ["openid"],
      resource: "urn:basis:api:test",
    });
    user.disabled = true;
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).rejects.toThrow("revoked");
  });
});

describe("key service — doubled battery", () => {
  it("emits an at_hash that depends on the access token", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findUserCompact: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findAccount: async () => ({ accountId: USER_ID, claims: async () => ({ sub: USER_ID }) }),
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const a = decodeJwt(
      await keys.issueIdToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], nonce: "n", authenticatedAt: new Date(), accessToken: "one" }),
    );
    const b = decodeJwt(
      await keys.issueIdToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], nonce: "n", authenticatedAt: new Date(), accessToken: "two" }),
    );
    expect(a.at_hash).not.toBe(b.at_hash);
  });

  it("accepts a token whose iat is after the revocation barrier", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], resource: "urn:basis:api:test" });
    const iat = decodeJwt(token).iat!;
    user.tokensValidAfter = new Date(iat * 1000 - 1000);
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).resolves.toMatchObject({ sub: USER_ID });
  });

  it("rejects a token whose iat equals the revocation barrier", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], resource: "urn:basis:api:test" });
    const iat = decodeJwt(token).iat!;
    user.tokensValidAfter = new Date(iat * 1000);
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).rejects.toThrow("revoked");
  });

  it("verifies a token issued before a user was disabled, once re-enabled", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const user = { id: USER_ID, disabled: false, tokensValidAfter: null as Date | null };
    const identity = {
      findUser: async () => user,
      findUserCompact: async () => user,
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], resource: "urn:basis:api:test" });
    user.disabled = true;
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).rejects.toThrow("revoked");
    user.disabled = false;
    await expect(keys.verifyAccessToken(token, "urn:basis:api:test")).resolves.toMatchObject({ sub: USER_ID });
  });

  it("carries multiple permissions when granted", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findUserCompact: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => ["participant", "admin"],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], resource: "urn:basis:api:test" });
    expect(decodeJwt(token).permissions).toEqual(["participant", "admin"]);
  });

  it("canonicalizes standardized delegated permissions in access tokens", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => ["users.READ"],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);

    const token = await keys.issueAccessToken({
      userId: USER_ID,
      clientId: "c",
      scopes: ["openid"],
      resource: "urn:basis:api:test",
    });

    expect(decodeJwt(token).permissions).toEqual(["Users.read"]);
  });

  it("verifies a token without supplying an audience even when one was embedded", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const identity = {
      findUser: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      findUserCompact: async () => ({ id: USER_ID, disabled: false, tokensValidAfter: null }),
      permissionsFor: async () => [],
    } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueAccessToken({ userId: USER_ID, clientId: "c", scopes: ["openid"], resource: "urn:basis:api:test" });
    await expect(keys.verifyAccessToken(token)).resolves.toMatchObject({ sub: USER_ID });
  });

  it("issues an id token from a preloaded account and permissions without identity reads", async () => {
    const config = buildConfig();
    const jwk = await rsaJwk();
    (config.jwks as { keys: unknown[] }).keys = [jwk];
    const findAccount = vi.fn(async () => ({
      accountId: USER_ID,
      claims: async () => ({ sub: USER_ID, email: "a@b.io" }),
    }));
    const identity = { findAccount } as unknown as IdentityService;
    const keys = await createKeyService(config, identity);
    const token = await keys.issueIdToken(
      { userId: USER_ID, clientId: "c", scopes: ["openid", "profile"], nonce: "n", authenticatedAt: new Date(), accessToken: "at" },
      { account: { accountId: USER_ID, claims: async () => ({ sub: USER_ID, email: "a@b.io" }) }, permissions: ["participant"] },
    );
    expect(decodeJwt(token).email).toBe("a@b.io");
    expect(findAccount).not.toHaveBeenCalled();
  });
});
