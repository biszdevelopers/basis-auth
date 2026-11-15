import { generateKeyPair, exportJWK, SignJWT } from "jose";
import { Hono } from "hono";
import { beforeAll, describe, expect, it, vi } from "vitest";
import { basisAuth, requirePermissions, requireScopes, type AuthVariables } from "./auth.js";

describe("resource-server middleware", () => {
  let privateKey: CryptoKey;
  let publicJwk: Record<string, unknown>;

  beforeAll(async () => {
    const keys = await generateKeyPair("RS256", { extractable: true });
    privateKey = keys.privateKey;
    publicJwk = { ...(await exportJWK(keys.publicKey)), kid: "test", alg: "RS256", use: "sig" };
  });

  async function token(overrides: Record<string, unknown> = {}, expires = "10m") {
    return new SignJWT({
      sub: "user-id",
      client_id: "portal",
      scope: "projects.read",
      permissions: ["participant"],
      ...overrides,
    })
      .setProtectedHeader({ alg: "RS256", kid: "test", typ: "at+jwt" })
      .setIssuer("https://auth.example.test")
      .setAudience("urn:basis:api:projects")
      .setJti("test-token")
      .setIssuedAt()
      .setExpirationTime(expires)
      .sign(privateKey);
  }

  function app(loadTokenSubject?: () => Promise<{ disabled: boolean; tokensValidAfter: Date | null }>) {
    const instance = new Hono<{ Variables: AuthVariables }>();
    instance.use(
      "/protected",
      basisAuth({
        issuer: "https://auth.example.test",
        audience: "urn:basis:api:projects",
        loadTokenSubject,
      }),
    );
    instance.get(
      "/protected",
      requireScopes("projects.read"),
      requirePermissions("participant"),
      (c) => c.json({ sub: c.get("basisToken").sub }),
    );
    return instance;
  }

  it("accepts a correctly scoped access token", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(
        new Response(JSON.stringify({ keys: [publicJwk] }), {
          headers: { "content-type": "application/json", "cache-control": "max-age=3600" },
        }),
      ),
    );
    const response = await app().request("/protected", {
      headers: { authorization: `Bearer ${await token()}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ sub: "user-id" });
    vi.unstubAllGlobals();
  });

  it("rejects a token for another audience", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => new Response(JSON.stringify({ keys: [publicJwk] }))),
    );
    const wrongAudience = await new SignJWT({ sub: "user-id", client_id: "portal" })
      .setProtectedHeader({ alg: "RS256", kid: "test", typ: "at+jwt" })
      .setIssuer("https://auth.example.test")
      .setAudience("urn:basis:api:other")
      .setExpirationTime("10m")
      .sign(privateKey);
    const response = await app().request("/protected", {
      headers: { authorization: `Bearer ${wrongAudience}` },
    });
    expect(response.status).toBe(401);
    vi.unstubAllGlobals();
  });

  it("rejects an ID token even when issuer and audience match", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockResolvedValue(new Response(JSON.stringify({ keys: [publicJwk] }))),
    );
    const idToken = await new SignJWT({ sub: "user-id", client_id: "portal" })
      .setProtectedHeader({ alg: "RS256", kid: "test", typ: "JWT" })
      .setIssuer("https://auth.example.test")
      .setAudience("urn:basis:api:projects")
      .setExpirationTime("10m")
      .sign(privateKey);
    const response = await app().request("/protected", {
      headers: { authorization: `Bearer ${idToken}` },
    });
    expect(response.status).toBe(401);
    vi.unstubAllGlobals();
  });

  it("enforces scopes and permissions after token validation", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => new Response(JSON.stringify({ keys: [publicJwk] }))),
    );
    const missingScope = await app().request("/protected", {
      headers: { authorization: `Bearer ${await token({ scope: "" })}` },
    });
    expect(missingScope.status).toBe(403);

    const missingPermission = await app().request("/protected", {
      headers: { authorization: `Bearer ${await token({ permissions: [] })}` },
    });
    expect(missingPermission.status).toBe(403);
    vi.unstubAllGlobals();
  });

  it("returns the same public error for revoked, expired, and malformed access tokens", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn().mockImplementation(async () => new Response(JSON.stringify({ keys: [publicJwk] }))),
    );
    const instance = app(async () => ({ disabled: false, tokensValidAfter: new Date() }));
    for (const accessToken of [await token(), await token({}, "0s"), "malformed"]) {
      const response = await instance.request("/protected", {
        headers: { authorization: `Bearer ${accessToken}` },
      });
      expect(response.status).toBe(401);
      expect(response.headers.get("www-authenticate")).toBe('Bearer error="invalid_token"');
      expect(await response.json()).toEqual({ error: "invalid_token", error_description: "Invalid access token" });
    }
    vi.unstubAllGlobals();
  });
});
