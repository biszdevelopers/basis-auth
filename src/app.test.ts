import { createHmac } from "node:crypto";
import { APIError as SchemaAPIError } from "@basis/schema/api";
import { describe, expect, it, vi } from "vitest";
import { createApp } from "./app.js";
import type { AppConfig } from "./config.js";
import type { IdentityService } from "./identity.js";
import type { MicrosoftService } from "./microsoft.js";
import type { KeyService } from "./oauth/keys.js";
import type { OAuthService } from "./oauth/service.js";
import type { SessionService } from "./oauth/sessions.js";
import { OAuthError } from "./oauth/errors.js";

const config = {
  environment: "test",
  issuer: "https://auth.example.test",
  cookieKeys: ["a".repeat(32)],
  microsoft: undefined,
} as AppConfig;

const app = createApp(
  config,
  {} as OAuthService,
  { publicJwks: { keys: [{ kty: "RSA", kid: "test" }] } } as KeyService,
  {} as SessionService,
  {} as IdentityService,
  {} as MicrosoftService,
);

describe("protocol metadata", () => {
  it("publishes the configured /oauth endpoints", async () => {
    const response = await app.request("/.well-known/openid-configuration");
    expect(response.status).toBe(200);
    const metadata = await response.json();
    expect(metadata).toMatchObject({
      issuer: "https://auth.example.test",
      authorization_endpoint: "https://auth.example.test/oauth/authorize",
      token_endpoint: "https://auth.example.test/oauth/token",
      userinfo_endpoint: "https://auth.example.test/oauth/userinfo",
      jwks_uri: "https://auth.example.test/oauth/jwks",
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code", "refresh_token"],
      code_challenge_methods_supported: ["S256"],
    });
  });

  it("publishes only public JWK material", async () => {
    const response = await app.request("/oauth/jwks");
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ keys: [{ kty: "RSA", kid: "test" }] });
    expect(response.headers.get("cache-control")).toContain("max-age=300");
  });
});

describe("root placeholder", () => {
  it("renders the shared Barry error page", async () => {
    const response = await app.request("/");

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("text/html");
    expect(await response.text()).toContain('go back home</a></h1>');
  });

  it("offers the self-test flow only in development", async () => {
    const devConfig = {
      ...config,
      environment: "development",
      issuer: "http://localhost:3000",
    } as AppConfig;
    const exchangeAuthorizationCode = vi.fn().mockResolvedValue({
      id_token: [
        Buffer.from(JSON.stringify({ alg: "RS256", typ: "JWT" })).toString("base64url"),
        Buffer.from(JSON.stringify({ sub: "demo-user", aud: "basis-auth-dev-demo" })).toString("base64url"),
        "signature",
      ].join("."),
    });
    const devApp = createApp(
      devConfig,
      { exchangeAuthorizationCode } as unknown as OAuthService,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const rootResponse = await devApp.request("/");
    expect(await rootResponse.text()).toContain('href="/dev/demo"');

    const startResponse = await devApp.request("/dev/demo");
    expect(startResponse.status).toBe(302);
    const authorizationUrl = new URL(startResponse.headers.get("location")!);
    expect(authorizationUrl.pathname).toBe("/oauth/authorize");
    expect(authorizationUrl.searchParams.get("client_id")).toBe("basis-auth-dev-demo");
    expect(authorizationUrl.searchParams.get("redirect_uri")).toBe("http://localhost:3000/dev/demo/callback");
    expect(authorizationUrl.searchParams.get("code_challenge_method")).toBe("S256");

    const cookie = startResponse.headers.get("set-cookie")!.split(";", 1)[0]!;
    const callbackResponse = await devApp.request(
      `/dev/demo/callback?code=demo-code&state=${authorizationUrl.searchParams.get("state")}`,
      { headers: { Cookie: cookie } },
    );
    expect(callbackResponse.status).toBe(200);
    const callbackHtml = await callbackResponse.text();
    expect(callbackHtml).toContain("OIDC demo succeeded");
    expect(callbackHtml).toContain('&quot;sub&quot;: &quot;demo-user&quot;');
    expect(exchangeAuthorizationCode).toHaveBeenCalledWith(expect.objectContaining({
      code: "demo-code",
      clientId: "basis-auth-dev-demo",
      redirectUri: "http://localhost:3000/dev/demo/callback",
      codeVerifier: expect.any(String),
    }));
  });
});

describe("OAuth errors", () => {
  it("uses the standardized Basis API error without changing its payload", () => {
    const error = new OAuthError("invalid_request", "Request is invalid", 400, 14000);

    expect(error).toBeInstanceOf(SchemaAPIError);
    expect(error.toJSON()).toEqual({
      status: 400,
      code: 14000,
      error: "invalid_request",
      error_description: "Request is invalid",
    });
  });

  it("returns the specific token error without an ambiguous bearer challenge", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const oauth = {
      exchangeAuthorizationCode: vi
        .fn()
        .mockRejectedValue(new OAuthError("invalid_client", "Client authentication failed", 401, 14004)),
    } as unknown as OAuthService;
    const tokenApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await tokenApp.request("/oauth/token", {
      method: "POST",
      headers: {
        Authorization: `Basic ${Buffer.from("client-id:client-secret").toString("base64")}`,
        "Content-Type": "application/x-www-form-urlencoded",
      },
      body: "grant_type=authorization_code&code=authorization-code",
    });

    expect(response.status).toBe(401);
    expect(response.headers.get("www-authenticate")).toBeNull();
    expect(await response.json()).toEqual({
      status: 401,
      error: "invalid_client",
      code: 14004,
      error_description: "Client authentication failed",
    });
    log.mockRestore();
  });
});

describe("unexpected backend failures", () => {
  const brokenKeys = {} as KeyService;
  Object.defineProperty(brokenKeys, "publicJwks", {
    get() {
      throw new Error("test failure");
    },
  });
  const brokenApp = createApp(
    config,
    {} as OAuthService,
    brokenKeys,
    {} as SessionService,
    {} as IdentityService,
    {} as MicrosoftService,
  );

  it("renders a safe HTML error page for browser navigations", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await brokenApp.request("/oauth/jwks", { headers: { Accept: "text/html" } });
    expect(response.status).toBe(500);
    expect(response.headers.get("content-type")).toContain("text/html");
    const html = await response.text();
    expect(html).toContain('go back home</a> (500)</h1>');
    expect(html).not.toContain("server_error");
    expect(html).not.toContain("test failure");
    log.mockRestore();
  });

  it("keeps API failures as OAuth-style JSON", async () => {
    const log = vi.spyOn(console, "error").mockImplementation(() => undefined);
    const response = await brokenApp.request("/oauth/jwks", { headers: { Accept: "application/json" } });
    expect(response.status).toBe(500);
    expect(await response.json()).toEqual({
      error: "server_error",
      error_description: "The request could not be completed",
    });
    log.mockRestore();
  });
});

describe("SSO account API", () => {
  const user = {
    id: "d2c3f635-527c-4c0a-bc1c-15d6af3f0946",
    provider: "basischina-microsoft",
    displayName: "Example User",
    email: "user@example.test",
    emailVerified: true,
    picture: Buffer.from([137, 80, 78, 71]),
    pictureContentType: "image/png",
  };
  const loginExpiresAt = new Date("2030-01-01T00:00:00.000Z");
  const accountApp = createApp(
    config,
    {} as OAuthService,
    { publicJwks: { keys: [] } } as unknown as KeyService,
    { find: vi.fn((token?: string) => (token ? { userId: user.id, expiresAt: loginExpiresAt } : undefined)) } as unknown as SessionService,
    { findUser: vi.fn().mockResolvedValue(user) } as unknown as IdentityService,
    {} as MicrosoftService,
  );

  it("returns basic account data without embedding the profile picture", async () => {
    const response = await accountApp.request("/api/me", {
      headers: { Cookie: "basis_sso=session-token" },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({
      id: user.id,
      provider: user.provider,
      name: user.displayName,
      email: user.email,
      emailVerified: true,
      loginExpiresAt: loginExpiresAt.toISOString(),
      picture: `/api/picture/${user.id}`,
    });
  });

  it("streams a stored profile picture only to the authenticated owner", async () => {
    const response = await accountApp.request(`/api/picture/${user.id}`, {
      headers: { Cookie: "basis_sso=session-token" },
    });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("image/png");
    expect(Buffer.from(await response.arrayBuffer())).toEqual(user.picture);
  });

  it("refuses profile pictures without an SSO session", async () => {
    const response = await accountApp.request(`/api/picture/${user.id}`);
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
  });

  it("refuses profile pictures for a different user", async () => {
    const response = await accountApp.request("/api/picture/different-user-id", {
      headers: { Cookie: "basis_sso=session-token" },
    });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({ error: "not_found" });
  });
});

describe("discovery caching", () => {
  it("caches the OpenID configuration", async () => {
    const response = await app.request("/.well-known/openid-configuration");
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toContain("max-age=300");
  });
});

describe("CORS", () => {
  const ORIGIN = "https://app.example.test";
  const previous = process.env.CORS_ALLOWED_ORIGINS;
  process.env.CORS_ALLOWED_ORIGINS = ORIGIN;
  const corsApp = createApp(
    config,
    {} as OAuthService,
    { publicJwks: { keys: [] } } as unknown as KeyService,
    {} as SessionService,
    {} as IdentityService,
    {} as MicrosoftService,
  );
  process.env.CORS_ALLOWED_ORIGINS = previous;

  it("echoes an allowed origin on CORS-enabled routes", async () => {
    const response = await corsApp.request("/oauth/userinfo", {
      headers: { Origin: ORIGIN },
    });
    expect(response.headers.get("access-control-allow-origin")).toBe(ORIGIN);
  });

  it("omits CORS headers for a disallowed origin", async () => {
    const response = await corsApp.request("/oauth/userinfo", {
      headers: { Origin: "https://evil.example.test" },
    });
    expect(response.headers.get("access-control-allow-origin")).toBeNull();
  });
});

describe("rate limiting", () => {
  it("rejects the token endpoint after the burst budget is exhausted", async () => {
    const oauth = {
      exchangeAuthorizationCode: vi.fn().mockResolvedValue({ access_token: "t" }),
    } as unknown as OAuthService;
    const limitedApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );
    let sawLimit = false;
    for (let i = 0; i < 200; i += 1) {
      const response = await limitedApp.request("/oauth/token", {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body: "grant_type=authorization_code",
      });
      if (response.status === 429) {
        sawLimit = true;
        break;
      }
    }
    expect(sawLimit).toBe(true);
  });
});

describe("authorization interactions", () => {
  const csrfToken = (uid: string) =>
    createHmac("sha256", config.cookieKeys[0]!).update(`interaction:${uid}`).digest("base64url");

  it("clears the SSO session and returns the interaction to login", async () => {
    const request = { id: "request-id" };
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue(request),
      clearInteractionUser: vi.fn().mockResolvedValue(undefined),
    } as unknown as OAuthService;
    const sessions = { destroy: vi.fn().mockResolvedValue(undefined) } as unknown as SessionService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      sessions,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/logout", {
      method: "POST",
      headers: { Accept: "application/json", Cookie: "basis_sso=session-token; basis_bridge_id=interaction-token" },
    });

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({});
    expect(sessions.destroy).toHaveBeenCalledWith("session-token");
    expect(oauth.clearInteractionUser).toHaveBeenCalledWith("request-id");
    expect(response.headers.getSetCookie().join("\n")).toContain("basis_sso=");
  });

  it("redirects browser logout requests to the original authorization URL", async () => {
    const request = { id: "request-id", initialUri: "/oauth/authorize?client_id=client&state=state" };
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue(request),
      clearInteractionUser: vi.fn().mockResolvedValue(undefined),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      { destroy: vi.fn().mockResolvedValue(undefined) } as unknown as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/logout", {
      headers: { Cookie: "basis_bridge_id=interaction-token" },
    });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe(request.initialUri);
  });

  it("completes authorization when the user allows consent", async () => {
    const request = { id: "request-id" };
    const oauth = {
      interaction: vi.fn().mockResolvedValue({ request }),
      grantConsent: vi.fn().mockResolvedValue(undefined),
      completeAuthorization: vi.fn().mockResolvedValue("https://client.example.test/callback?code=code"),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/interaction/request-id/consent", {
      method: "POST",
      headers: {
        Cookie: "basis_bridge_id=valid-interaction",
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken("request-id"),
      },
      body: JSON.stringify({ action: "allow" }),
    });

    expect(await response.json()).toEqual({ redirectTo: "https://client.example.test/callback?code=code" });
    expect(oauth.grantConsent).toHaveBeenCalledWith(request);
  });

  it("returns the OAuth denial redirect when the user denies consent", async () => {
    const request = { id: "request-id" };
    const oauth = {
      interaction: vi.fn().mockResolvedValue({ request }),
      denyAuthorization: vi.fn().mockResolvedValue("https://client.example.test/callback?error=access_denied"),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/interaction/request-id/consent", {
      method: "POST",
      headers: {
        Cookie: "basis_bridge_id=valid-interaction",
        "Content-Type": "application/json",
        "x-csrf-token": csrfToken("request-id"),
      },
      body: JSON.stringify({ action: "deny" }),
    });

    expect(await response.json()).toEqual({ redirectTo: "https://client.example.test/callback?error=access_denied" });
    expect(oauth.denyAuthorization).toHaveBeenCalledWith(request);
  });

  it("returns the Microsoft redirect URL to frontend requests", async () => {
    const oauth = {
      interaction: vi.fn().mockResolvedValue({ request: { id: "request-id" } }),
    } as unknown as OAuthService;
    const microsoft = {
      begin: vi.fn().mockResolvedValue(new URL("https://login.microsoftonline.com/authorize")),
    } as unknown as MicrosoftService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      microsoft,
    );

    const response = await authorizationApp.request("/oauth/upstream/microsoft?uid=request-id", {
      headers: { Accept: "application/json", Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(await response.json()).toEqual({ redirectTo: "https://login.microsoftonline.com/authorize" });
  });

  it("sends upstream Microsoft failures back to the stored authorization URL", async () => {
    const oauth = {
      interaction: vi.fn().mockRejectedValue(new OAuthError("invalid_request", "Interaction is invalid", 400)),
      getAuthorization: vi.fn().mockResolvedValue({ initialUri: "/oauth/authorize?client_id=client" }),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/upstream/microsoft?uid=request-id", {
      headers: { Accept: "application/json", Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(await response.json()).toEqual({ redirectTo: "/oauth/authorize?client_id=client" });
    expect(response.headers.get("set-cookie")).toContain("basis_bridge_error=");
  });

  it("identifies authenticated interactions as consent pages", async () => {
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue({
        id: "request-id",
        userId: "user-id",
        clientId: "client-id",
        scopes: ["openid"],
        resource: "resource-id",
      }),
      getClient: vi.fn().mockResolvedValue({ id: "client-id" }),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/interaction", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(await response.json()).toMatchObject({ prompt: "consent" });
  });

  it("reuses a valid interaction cookie", async () => {
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue({ id: "request-id", initialUri: "/oauth/authorize" }),
      startAuthorization: vi.fn(),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/authorize", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(response.status).toBe(200);
    expect(oauth.getAuthorization).toHaveBeenCalledWith("valid-interaction");
    expect(oauth.startAuthorization).not.toHaveBeenCalled();
  });

  it("starts a new interaction when the authorization URI changes", async () => {
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue({
        id: "request-id",
        initialUri: "/oauth/authorize?client_id=previous-client",
      }),
      startAuthorization: vi.fn().mockResolvedValue({ id: "new-request", interactionToken: "new-interaction" }),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      { find: vi.fn().mockResolvedValue(undefined) } as unknown as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/authorize?client_id=new-client", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(response.status).toBe(200);
    expect(oauth.startAuthorization).toHaveBeenCalledWith(
      expect.objectContaining({ initialUri: "/oauth/authorize?client_id=new-client" }),
    );
  });

  it("replaces an expired interaction cookie", async () => {
    const oauth = {
      getAuthorization: vi
        .fn()
        .mockRejectedValue(new OAuthError("invalid_request", "Authorization request is invalid or expired", 400)),
      startAuthorization: vi.fn().mockResolvedValue({ id: "request-id", interactionToken: "new-interaction" }),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      { find: vi.fn().mockResolvedValue(undefined) } as unknown as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/authorize", {
      headers: { Cookie: "basis_bridge_id=expired-interaction" },
    });

    expect(response.status).toBe(200);
    expect(oauth.startAuthorization).toHaveBeenCalledOnce();
    expect(response.headers.get("set-cookie")).toContain("basis_bridge_id=new-interaction");
  });

  it("renders an existing bridge error instead of starting another interaction", async () => {
    const oauth = {
      getAuthorization: vi
        .fn()
        .mockRejectedValue(new OAuthError("invalid_request", "Authorization request is invalid or expired", 400)),
      startAuthorization: vi.fn(),
    } as unknown as OAuthService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      {} as MicrosoftService,
    );

    const response = await authorizationApp.request("/oauth/authorize", {
      headers: {
        Cookie: "basis_bridge_id=expired-interaction; basis_bridge_error=eyJlcnJvciI6ImludmFsaWRfcmVxdWVzdCJ9",
      },
    });

    expect(response.status).toBe(200);
    expect(oauth.startAuthorization).not.toHaveBeenCalled();
  });

  it("redirects back to authorize after Microsoft login", async () => {
    const oauth = {
      interaction: vi.fn().mockResolvedValue({
        request: { id: "request-id", initialUri: "/oauth/authorize?client_id=client&state=state" },
        client: {},
      }),
      attachUser: vi.fn().mockResolvedValue(undefined),
    } as unknown as OAuthService;
    const microsoft = {
      callback: vi.fn().mockResolvedValue({
        authorizationRequestId: "request-id",
        user: { id: "user-id", email: "user@example.test", disabled: false },
      }),
    } as unknown as MicrosoftService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      { create: vi.fn().mockResolvedValue("session-token") } as unknown as SessionService,
      {} as IdentityService,
      microsoft,
    );

    const response = await authorizationApp.request("/oauth/callback/microsoft?code=code&state=state", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/oauth/authorize?client_id=client&state=state");
    expect(oauth.attachUser).toHaveBeenCalledWith("request-id", "user-id", expect.any(Date));
  });

  it("returns a bridge error when a client blocks the Microsoft account", async () => {
    const oauth = {
      interaction: vi.fn().mockResolvedValue({
        request: { id: "request-id" },
        client: { filterMode: "whitelist", filterContent: ["allowed@example.test"] },
      }),
      getAuthorization: vi.fn().mockResolvedValue({ initialUri: "/oauth/authorize?client_id=client" }),
      attachUser: vi.fn(),
    } as unknown as OAuthService;
    const sessions = { create: vi.fn() } as unknown as SessionService;
    const microsoft = {
      callback: vi.fn().mockResolvedValue({
        authorizationRequestId: "request-id",
        user: { id: "user-id", email: "blocked@example.test", disabled: false },
      }),
    } as unknown as MicrosoftService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      sessions,
      {} as IdentityService,
      microsoft,
    );

    const response = await authorizationApp.request("/oauth/callback/microsoft?code=code&state=state", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/oauth/authorize?client_id=client");
    expect(response.headers.get("set-cookie")).toContain("basis_bridge_error=");
    expect(sessions.create).not.toHaveBeenCalled();
    expect(oauth.attachUser).not.toHaveBeenCalled();
  });

  it("sends Microsoft callback failures back to the stored authorization URL", async () => {
    const oauth = {
      getAuthorization: vi.fn().mockResolvedValue({ initialUri: "/oauth/authorize?client_id=client" }),
    } as unknown as OAuthService;
    const microsoft = {
      callback: vi.fn().mockRejectedValue(new Error("Microsoft callback failed")),
    } as unknown as MicrosoftService;
    const authorizationApp = createApp(
      config,
      oauth,
      { publicJwks: { keys: [] } } as unknown as KeyService,
      {} as SessionService,
      {} as IdentityService,
      microsoft,
    );

    const response = await authorizationApp.request("/oauth/callback/microsoft?code=code&state=state", {
      headers: { Cookie: "basis_bridge_id=valid-interaction" },
    });

    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/oauth/authorize?client_id=client");
    expect(response.headers.get("set-cookie")).toContain("basis_bridge_error=");
  });
});

describe("not-found responses", () => {
  it("renders the shared Barry page for an unknown browser route", async () => {
    const response = await app.request("/missing", { headers: { Accept: "text/html" } });

    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toContain("text/html");
    const html = await response.text();
    expect(html).toContain('go back home</a> (404)</h1>');
    expect(html).not.toContain("not_found");
  });

  it("returns JSON for an unknown API route", async () => {
    const response = await app.request("/oauth/missing", { headers: { Accept: "application/json" } });
    expect(response.status).toBe(404);
    expect(await response.json()).toEqual({
      error: "not_found",
      error_description: "The requested resource does not exist",
    });
  });
});
