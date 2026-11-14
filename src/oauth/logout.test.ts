import { createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify } from "jose";
import { afterEach, describe, expect, it, vi } from "vitest";
import { resourceSchema, type AppConfig } from "../config.js";
import type { Database } from "../database/client.js";
import type { IdentityService } from "../identity.js";
import { createInternalApp } from "../internal/app.js";
import type { InternalUserService } from "../internal/users.js";
import { createKeyService } from "./keys.js";
import { createLogoutService } from "./logout.js";

const userId = "d2c3f635-527c-4c0a-bc1c-15d6af3f0946";
const audience = "urn:basis:api:projects";
const issuer = "https://auth.example.test";
const uri = "https://projects.example.test/logout?source=auth";
const internalToken = "i".repeat(32);

function logoutApp(resources: { uri: string | null }[], issueLogoutToken = vi.fn().mockResolvedValue("token")) {
  const limit = vi.fn().mockResolvedValue(resources);
  const db = {
    select: () => ({ from: () => ({ where: () => ({ limit }) }) }),
  } as unknown as Database;
  const users = { findUser: vi.fn().mockResolvedValue({ id: userId }) } as unknown as InternalUserService;
  const app = createInternalApp(internalToken, users, undefined, createLogoutService(db, { issueLogoutToken }));
  return { app, limit, issueLogoutToken };
}

function requestLogout(app: ReturnType<typeof createInternalApp>, authenticated = true, body: unknown = { audience }) {
  return app.request(`/internal/users/${userId}/logout`, {
    method: "POST",
    headers: authenticated ? { authorization: `Bearer ${internalToken}` } : {},
    body: JSON.stringify(body),
  });
}

afterEach(() => vi.unstubAllGlobals());

describe("internal back-channel logout", () => {
  it("sends a signed, short-lived logout token to the configured resource", async () => {
    const { privateKey } = await generateKeyPair("RS256", { extractable: true });
    const jwk = { ...await exportJWK(privateKey), kid: "test" };
    const keys = await createKeyService({ issuer, jwks: { keys: [jwk] } } as AppConfig, {} as IdentityService);
    const { app } = logoutApp([{ uri }], vi.fn(keys.issueLogoutToken));
    const send = vi.fn<typeof fetch>().mockResolvedValue(new Response(null, { status: 204 }));
    vi.stubGlobal("fetch", send);

    expect((await requestLogout(app)).status).toBe(204);
    expect(send).toHaveBeenCalledTimes(1);
    const request = new Request(...send.mock.calls[0]!);
    expect(request.url).toBe(uri);
    expect(request.method).toBe("POST");
    expect(request.redirect).toBe("error");
    expect(request.headers.get("content-type")).toMatch(/^application\/x-www-form-urlencoded/);
    const body = await request.formData();
    const { payload } = await jwtVerify(String(body.get("logout_token")), createLocalJWKSet(keys.publicJwks), {
      issuer, audience, typ: "logout+jwt", algorithms: ["RS256"],
      requiredClaims: ["sub", "exp", "iat", "jti", "events"],
    });
    expect(payload).toMatchObject({
      sub: userId,
      events: { "http://schemas.openid.net/event/backchannel-logout": {} },
    });
    expect(payload.exp! - payload.iat!).toBe(120);
    expect(payload).not.toHaveProperty("nonce");
  });

  it("requires the internal bearer token and a resource audience", async () => {
    const { app, limit } = logoutApp([{ uri }]);
    expect((await requestLogout(app, false)).status).toBe(401);
    expect((await requestLogout(app, true, {})).status).toBe(400);
    expect(limit).not.toHaveBeenCalled();
  });

  it.each([
    { resources: [], status: 404 },
    { resources: [{ uri: null }], status: 409 },
    { resources: [{ uri: "http://projects.example.test/logout" }], status: 502 },
  ])("reports status $status without signing for an unavailable callback", async ({ resources, status }) => {
    const { app, issueLogoutToken } = logoutApp(resources);
    expect((await requestLogout(app)).status).toBe(status);
    expect(issueLogoutToken).not.toHaveBeenCalled();
  });

  it("reports receiver errors and network failures", async () => {
    const { app } = logoutApp([{ uri }]);
    const send = vi.fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 400 }))
      .mockRejectedValueOnce(new Error("network failure"));
    vi.stubGlobal("fetch", send);

    expect((await requestLogout(app)).status).toBe(502);
    expect((await requestLogout(app)).status).toBe(502);
    expect(send).toHaveBeenCalledTimes(2);
  });
});

describe("back-channel logout resource configuration", () => {
  it("accepts an optional HTTPS endpoint without credentials or a fragment", () => {
    expect(resourceSchema.parse({ audience, backchannelLogoutUri: uri }).backchannelLogoutUri).toBe(uri);
    expect(resourceSchema.parse({ audience, backchannelLogoutUri: null }).backchannelLogoutUri).toBeNull();
    for (const value of ["http://example.test/logout", "https://user@example.test/logout", `${uri}#`]) {
      expect(resourceSchema.safeParse({ audience, backchannelLogoutUri: value }).success).toBe(false);
    }
  });
});
