import { createHmac, timingSafeEqual } from "node:crypto";
import { readFile } from "node:fs/promises";
import { renderErrorPage } from "@basis/schema/error-page";
import { serveStatic } from "@hono/node-server/serve-static";
import { decodeJwt, decodeProtectedHeader } from "jose";
import { deleteCookie, getCookie, setCookie } from "hono/cookie";
import { Hono, type Context, type MiddlewareHandler } from "hono";
import { secureHeaders } from "hono/secure-headers";
import {
  DEVELOPMENT_DEMO_CALLBACK_PATH,
  DEVELOPMENT_DEMO_CLIENT_ID,
  DEVELOPMENT_DEMO_PATH,
  type AppConfig,
} from "./config.js";
import type { IdentityService } from "./identity.js";
import type { KeyService } from "./oauth/keys.js";
import { APIError, OAuthError } from "./oauth/errors.js";
import type { OAuthService } from "./oauth/service.js";
import type { SessionService } from "./oauth/sessions.js";
import {
  microsoftAuthErrorPayload,
  resolveAuthErrorCode,
  type MicrosoftService,
  userFacingMicrosoftAuthError,
} from "./microsoft.js";
import { clientIp, rateLimit, RateLimiter } from "./middleware/rateLimit.js";
import { log } from "./log.js";
import { pkceChallenge, randomToken } from "./oauth/crypto.js";

const SSO_COOKIE = "basis_sso";
const INTERACTION_COOKIE = "basis_bridge_id";
const ERROR_COOKIE = "basis_bridge_error";
const DEVELOPMENT_DEMO_COOKIE = "basis_dev_demo";

function escapeHtml(value: string) {
  return value.replace(/[&<>"']/g, (character) => ({
    "&": "&amp;",
    "<": "&lt;",
    ">": "&gt;",
    '"': "&quot;",
    "'": "&#39;",
  })[character]!);
}

function renderDevelopmentDemo(title: string, body: string) {
  return `<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(title)}</title></head>
<body><main><h1>${escapeHtml(title)}</h1>${body}</main></body>
</html>`;
}

type OAuthRequestBody = Record<string, unknown>;

function formValue(body: OAuthRequestBody, key: string) {
  const value = body[key];
  return typeof value === "string" ? value : undefined;
}

async function oauthRequestBody(c: Context): Promise<OAuthRequestBody> {
  const contentType = c.req.header("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType === "application/json") {
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      throw new OAuthError("invalid_request", "Request body must be valid JSON");
    }
    if (!body || typeof body !== "object" || Array.isArray(body)) {
      throw new OAuthError("invalid_request", "Request body must be a JSON object");
    }
    return body as OAuthRequestBody;
  }
  return await c.req.parseBody();
}

function clientCredentials(c: Context, body: OAuthRequestBody, allowBodySecret = false) {
  const authorization = c.req.header("authorization");
  if (authorization?.startsWith("Basic ")) {
    let decoded: string;
    try {
      decoded = Buffer.from(authorization.slice(6), "base64").toString("utf8");
    } catch {
      throw new OAuthError("invalid_client", "Malformed client authorization", 401);
    }
    const separator = decoded.indexOf(":");
    if (separator < 1) throw new OAuthError("invalid_client", "Malformed client authorization", 401);
    const decode = (value: string) => {
      try {
        return decodeURIComponent(value.replace(/\+/g, " "));
      } catch {
        throw new OAuthError("invalid_client", "Malformed client authorization", 401);
      }
    };
    return {
      clientId: decode(decoded.slice(0, separator)),
      clientSecret: decode(decoded.slice(separator + 1)),
    };
  }
  const clientSecret = formValue(body, "client_secret");
  if (clientSecret && !allowBodySecret) {
    throw new OAuthError("invalid_client", "Use client_secret_basic for confidential clients", 401);
  }
  return {
    clientId: formValue(body, "client_id") ?? "",
    clientSecret: allowBodySecret ? clientSecret : undefined,
  };
}

function acceptsHtml(c: Context) {
  return c.req.method === "GET" && c.req.header("accept")?.includes("text/html");
}

export function createApp(
  config: AppConfig,
  oauth: OAuthService,
  keys: KeyService,
  sessions: SessionService,
  identity: IdentityService,
  microsoft: MicrosoftService,
) {
  const app = new Hono();
  const cookieOptions = {
    httpOnly: true,
    secure: config.environment === "production",
    sameSite: "Lax" as const,
    path: "/",
    ...(config.environment !== "production" ? { domain: "localhost" } : {}),
  };
  const deleteCookieOptions = {
    path: "/",
    ...(config.environment !== "production" ? { domain: "localhost" } : {}),
  };
  const csrfToken = (uid: string) =>
    createHmac("sha256", config.cookieKeys[0]!).update(`interaction:${uid}`).digest("base64url");
  const csrfValid = (uid: string, value?: string) => {
    if (!value) return false;
    const expected = Buffer.from(csrfToken(uid));
    const supplied = Buffer.from(value);
    return expected.length === supplied.length && timingSafeEqual(expected, supplied);
  };
  const signDevelopmentDemoState = (state: string, verifier: string) => {
    const payload = Buffer.from(JSON.stringify({ state, verifier })).toString("base64url");
    const signature = createHmac("sha256", config.cookieKeys[0]!).update(payload).digest("base64url");
    return `${payload}.${signature}`;
  };
  const readDevelopmentDemoState = (value?: string) => {
    if (!value) return undefined;
    const [payload, signature] = value.split(".");
    if (!payload || !signature) return undefined;
    const expected = createHmac("sha256", config.cookieKeys[0]!).update(payload).digest("base64url");
    const expectedBytes = Buffer.from(expected);
    const suppliedBytes = Buffer.from(signature);
    if (expectedBytes.length !== suppliedBytes.length || !timingSafeEqual(expectedBytes, suppliedBytes)) {
      return undefined;
    }
    try {
      const parsed = JSON.parse(Buffer.from(payload, "base64url").toString("utf8"));
      return typeof parsed?.state === "string" && typeof parsed?.verifier === "string"
        ? parsed as { state: string; verifier: string }
        : undefined;
    } catch {
      return undefined;
    }
  };
  const errorPayload = (error: any) =>
    error instanceof OAuthError
      ? error.toJSON()
      : {
          status: 500,
          error: "server_error",
          code: 50040,
          error_description: "The request could not be completed: " + error,
        };
  const originalAuthorizationUri = async (c: Context) => {
    try {
      const request = await oauth.getAuthorization(getCookie(c, INTERACTION_COOKIE)!);
      return request.initialUri.startsWith("/oauth/authorize")
        ? request.initialUri
        : "/oauth/authorize";
    } catch {
      return "/oauth/authorize";
    }
  };
  const frontendFlowError = async (c: Context, error: any) => {
    console.error(error)
    const redirectTo = await originalAuthorizationUri(c);
    setCookie(c, ERROR_COOKIE, btoa(JSON.stringify(errorPayload(error))), {
      ...cookieOptions,
      httpOnly: false,
      path: "/oauth",
      maxAge: 10 * 60,
    });
    if (c.req.header("accept")?.includes("application/json")) {
      return c.json({ redirectTo });
    }
    return c.redirect(redirectTo, 303);
  };

  const openidConfiguration = {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    userinfo_endpoint: `${config.issuer}/oauth/userinfo`,
    jwks_uri: `${config.issuer}/oauth/jwks`,
    revocation_endpoint: `${config.issuer}/oauth/revoke`,
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    end_session_endpoint: `${config.issuer}/oauth/logout`,
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    subject_types_supported: ["public"],
    id_token_signing_alg_values_supported: ["RS256"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    scopes_supported: ["openid", "profile", "email", "offline_access"],
    claims_supported: ["sub", "name", "picture", "email", "email_verified"],
    code_challenge_methods_supported: ["S256"],
  };
  const oauthAuthorizationServerConfiguration = {
    issuer: config.issuer,
    authorization_endpoint: `${config.issuer}/oauth/authorize`,
    token_endpoint: `${config.issuer}/oauth/token`,
    jwks_uri: `${config.issuer}/oauth/jwks`,
    revocation_endpoint: `${config.issuer}/oauth/revoke`,
    revocation_endpoint_auth_methods_supported: ["client_secret_basic", "none"],
    response_types_supported: ["code"],
    grant_types_supported: ["authorization_code", "refresh_token", "client_credentials"],
    token_endpoint_auth_methods_supported: ["client_secret_basic", "client_secret_post", "none"],
    code_challenge_methods_supported: ["S256"],
  };

  const limiter = new RateLimiter({ windowMs: 60_000, max: 120 });
  const limitKey = (c: Context) => `${c.req.path}:${clientIp(c)}`;

  const allowedOrigins = (process.env.CORS_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  const corsMiddleware = (origins: string[]): MiddlewareHandler => {
    return async (c, next) => {
      const origin = c.req.header("origin");
      if (origin && origins.includes(origin)) {
        c.header("Access-Control-Allow-Origin", origin);
        c.header("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
        c.header("Access-Control-Allow-Headers", "Authorization, Content-Type");
      }
      if (c.req.method === "OPTIONS") return new Response(null, { status: 204, headers: c.res.headers });
      await next();
    };
  };

  app.use("/api/picture/*", async (c, next) => {
    await next();
    c.header("Cross-Origin-Resource-Policy", "same-site");
  });
  app.use("*", secureHeaders());
  app.get("/health", (c) => c.json({ status: "ok" }));

  app.get("/", async (c) => {
    if (config.environment === "development") {
      return c.html(renderDevelopmentDemo(
        "basis-auth development",
        `<p><a href="${DEVELOPMENT_DEMO_PATH}">Run the OIDC demo flow</a></p>`,
      ));
    }
    return c.html(renderErrorPage(null));
  });

  if (config.environment === "development") {
    app.get(DEVELOPMENT_DEMO_PATH, (c) => {
      const state = randomToken();
      const nonce = randomToken();
      const verifier = randomToken(48);
      const callbackUrl = `${config.issuer}${DEVELOPMENT_DEMO_CALLBACK_PATH}`;
      const authorizationUrl = new URL("/oauth/authorize", config.issuer);
      authorizationUrl.searchParams.set("client_id", DEVELOPMENT_DEMO_CLIENT_ID);
      authorizationUrl.searchParams.set("redirect_uri", callbackUrl);
      authorizationUrl.searchParams.set("response_type", "code");
      authorizationUrl.searchParams.set("scope", "openid profile email");
      authorizationUrl.searchParams.set("resource", `${config.issuer}${DEVELOPMENT_DEMO_PATH}`);
      authorizationUrl.searchParams.set("state", state);
      authorizationUrl.searchParams.set("nonce", nonce);
      authorizationUrl.searchParams.set("code_challenge", pkceChallenge(verifier));
      authorizationUrl.searchParams.set("code_challenge_method", "S256");
      setCookie(c, DEVELOPMENT_DEMO_COOKIE, signDevelopmentDemoState(state, verifier), {
        ...cookieOptions,
        path: DEVELOPMENT_DEMO_PATH,
        maxAge: 10 * 60,
      });
      return c.redirect(authorizationUrl.toString(), 302);
    });

    app.get(DEVELOPMENT_DEMO_CALLBACK_PATH, async (c) => {
      const saved = readDevelopmentDemoState(getCookie(c, DEVELOPMENT_DEMO_COOKIE));
      deleteCookie(c, DEVELOPMENT_DEMO_COOKIE, {
        ...deleteCookieOptions,
        path: DEVELOPMENT_DEMO_PATH,
      });
      const code = c.req.query("code");
      const state = c.req.query("state");
      if (!saved || !code || state !== saved.state) {
        return c.html(renderDevelopmentDemo(
          "OIDC demo failed",
          `<p>The callback was missing a valid code or state. <a href="${DEVELOPMENT_DEMO_PATH}">Try again</a>.</p>`,
        ), 400);
      }

      const tokenSet = await oauth.exchangeAuthorizationCode({
        code,
        clientId: DEVELOPMENT_DEMO_CLIENT_ID,
        redirectUri: `${config.issuer}${DEVELOPMENT_DEMO_CALLBACK_PATH}`,
        codeVerifier: saved.verifier,
      });
      const idToken = typeof tokenSet.id_token === "string" ? tokenSet.id_token : undefined;
      if (!idToken) throw new OAuthError("server_error", "The demo flow did not return an ID token", 500);
      const accessToken = typeof tokenSet.access_token === "string" ? tokenSet.access_token : undefined;
      if (!accessToken) throw new OAuthError("server_error", "The demo flow did not return an access token", 500);
      const decodedIdToken = {
        header: decodeProtectedHeader(idToken),
        payload: decodeJwt(idToken),
      };
      const decodedAccessToken = {
        header: decodeProtectedHeader(accessToken),
        payload: decodeJwt(accessToken),
      };
      return c.html(renderDevelopmentDemo(
        "OIDC demo succeeded",
        `<p>The complete authorization-code flow succeeded.</p><h2>Decoded ID token</h2><pre>${escapeHtml(JSON.stringify(decodedIdToken, null, 2))}</pre><h2>Raw ID token</h2><pre>${escapeHtml(idToken)}</pre><h2>Decoded access token</h2><pre>${escapeHtml(JSON.stringify(decodedAccessToken, null, 2))}</pre><h2>Raw access token</h2><pre>${escapeHtml(accessToken)}</pre><p><a href="${DEVELOPMENT_DEMO_PATH}">Run it again</a></p>`,
      ));
    });
  }

  async function currentSession(c: Context) {
    const session = await sessions.find(getCookie(c, SSO_COOKIE));
    if (!session) return undefined;
    const user = await identity.findUser(session.userId);
    return user ? { session, user } : undefined;
  }

  app.get("/api/me", async (c) => {
    const current = await currentSession(c);
    if (!current) return c.json({ error: "unauthorized" }, 401);
    const { session, user } = current;
    c.header("Cache-Control", "no-store");
    return c.json({
      id: user.id,
      provider: user.provider,
      name: user.displayName,
      email: user.email,
      emailVerified: user.emailVerified,
      loginExpiresAt: session.expiresAt.toISOString(),
      picture: user.picture && user.pictureContentType ? `/api/picture/${user.id}` : null,
    });
  });

  app.get("/api/picture/:userId", async (c) => {
    const session = await sessions.find(getCookie(c, SSO_COOKIE));
    const userId = c.req.param("userId");
    if (!session || session.userId !== userId) return c.json({ error: "not_found" }, 404);
    const user = await identity.findUser(userId);
    if (!user?.picture || !user.pictureContentType) {
      return c.json({ error: "not_found" }, 404);
    }
    c.header("Cache-Control", "public, max-age=300");
    c.header("Content-Type", user.pictureContentType);
    return c.body(new Uint8Array(user.picture));
  });

  app.get("/.well-known/openid-configuration", (c) => {
    c.header("Cache-Control", "public, max-age=300");
    return c.json(openidConfiguration);
  });
  app.get("/.well-known/oauth-authorization-server", (c) => {
    c.header("Cache-Control", "public, max-age=300");
    return c.json(oauthAuthorizationServerConfiguration);
  });
  app.get("/oauth/jwks", (c) => {
    c.header("Cache-Control", "public, max-age=300, stale-while-revalidate=300");
    return c.json(keys.publicJwks);
  });

  app.use("/oauth/token", rateLimit(limiter, limitKey));
  app.use("/oauth/revoke", rateLimit(limiter, limitKey));
  app.use("/oauth/authorize", rateLimit(limiter, limitKey));
  app.use("/oauth/interaction/:uid/consent", rateLimit(limiter, limitKey));
  app.use("/oauth/callback/microsoft", rateLimit(limiter, limitKey));
  app.use("/api/me", rateLimit(limiter, limitKey));
  if (allowedOrigins.length > 0) {
    app.use("/oauth/token", corsMiddleware(allowedOrigins));
    app.use("/oauth/userinfo", corsMiddleware(allowedOrigins));
  }

  app.use("/oauth/token", async (c, next) => {
    c.header("Cache-Control", "no-store");
    c.header("Pragma", "no-cache");
    await next();
  });
  app.use("/oauth/revoke", async (c, next) => {
    c.header("Cache-Control", "no-store");
    await next();
  });

  app.get("/oauth/authorize", async (c) => {
    const initialUrl = new URL(c.req.url);
    const initialUri = initialUrl.pathname + initialUrl.search;
    const interactionToken = getCookie(c, INTERACTION_COOKIE);
    const bridgeError = getCookie(c, ERROR_COOKIE);
    if (interactionToken) {
      try {
        const request = await oauth.getAuthorization(interactionToken);
        if (request.initialUri === initialUri) {
          return c.html(await readFile("./web/dist/index.html", "utf8"));
        }
        deleteCookie(c, INTERACTION_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
        deleteCookie(c, ERROR_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
      } catch (error) {
        if (!(error instanceof OAuthError)) throw error;
        deleteCookie(c, INTERACTION_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
        if (bridgeError) return c.html(await readFile("./web/dist/index.html", "utf8"));
        deleteCookie(c, ERROR_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
      }
    } else if (bridgeError) {
      return c.html(await readFile("./web/dist/index.html", "utf8"));
    } else {
      deleteCookie(c, ERROR_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
    }

    const sso = await sessions.find(getCookie(c, SSO_COOKIE));
    let started;
    try {
      started = await oauth.startAuthorization({
        initialUri,
        clientId: c.req.query("client_id"),
        redirectUri: c.req.query("redirect_uri"),
        responseType: c.req.query("response_type"),
        scope: c.req.query("scope"),
        resources: c.req.queries("resource") ?? [],
        state: c.req.query("state"),
        nonce: c.req.query("nonce"),
        codeChallenge: c.req.query("code_challenge"),
        codeChallengeMethod: c.req.query("code_challenge_method"),
        session: sso ? { userId: sso.userId, authenticatedAt: sso.authenticatedAt } : undefined,
      });
    } catch (error) {
      console.error(error)
      setCookie(c, ERROR_COOKIE, btoa(JSON.stringify(errorPayload(error))), {
        ...cookieOptions,
        httpOnly: false,
        path: "/oauth",
        maxAge: 10 * 60,
      });
      return c.html(await readFile("./web/dist/index.html", "utf8"));
    }

    setCookie(c, INTERACTION_COOKIE, started.interactionToken, {
      ...cookieOptions,
      path: "/oauth",
      maxAge: 10 * 60,
    });

    return c.html(await readFile("./web/dist/index.html", "utf8"));
  });

  app.get("/oauth/interaction", async (c) => {
    const bridgeToken = getCookie(c, INTERACTION_COOKIE);
    if (!bridgeToken) throw new OAuthError("invalid_request", "Interaction cookie is missing");
    const request = await oauth.getAuthorization(bridgeToken);
    const client = await oauth.getClient(request.clientId);
    return c.json({
      uid: request.id,
      prompt: request.userId ? "consent" : "login",
      client,
      scopes: request.scopes,
      resources: [request.resource],
      accountId: request.userId,
      csrfToken: csrfToken(request.id),
      microsoftConfigured: Boolean(config.microsoft),
    });
  });

  app.post("/oauth/interaction/:uid/consent", async (c) => {
    const uid = c.req.param("uid");
    if (!csrfValid(uid, c.req.header("x-csrf-token"))) {
      return c.json({ error: "invalid_csrf_token" }, 403);
    }
    const { request } = await oauth.interaction(uid, getCookie(c, INTERACTION_COOKIE));
    const body = await c.req.json<{ action?: string }>();
    if (body.action === "deny") {
      const redirectTo = await oauth.denyAuthorization(request);
      deleteCookie(c, INTERACTION_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
      return c.json({ redirectTo });
    }
    if (body.action !== "allow") return c.json({ error: "invalid_action" }, 400);
    await oauth.grantConsent(request);
    const redirectTo = await oauth.completeAuthorization(request.id);
    deleteCookie(c, INTERACTION_COOKIE, { ...deleteCookieOptions, path: "/oauth" });
    return c.json({ redirectTo });
  });

  app.get("/oauth/upstream/microsoft", async (c) => {
    try {
      const uid = c.req.query("uid");
      if (!uid) throw new OAuthError("invalid_request", "Interaction is not found or expired");
      const { request } = await oauth.interaction(uid, getCookie(c, INTERACTION_COOKIE));
      if (request.userId) throw new OAuthError("invalid_request", "User is already authenticated");
      const redirectTo = (await microsoft.begin(request.id)).href;
      if (c.req.header("accept")?.includes("application/json")) {
        return c.json({ redirectTo });
      }
      return c.redirect(redirectTo, 302);
    } catch (error: any) {
      log.error(error, "Microsoft upstream begin failed");
      
      return frontendFlowError(c, "Upstream Error");
    }
  });

  app.get("/oauth/callback/microsoft", async (c) => {
    try {
      const incoming = new URL(c.req.url);
      const callbackUrl = new URL(`${incoming.pathname}${incoming.search}`, config.issuer);
      const result = await microsoft.callback(callbackUrl);
      const { request, client } = await oauth.interaction(
        result.authorizationRequestId,
        getCookie(c, INTERACTION_COOKIE),
      );
      const filteredEmail = result.user.email.trim().toLowerCase();
      const filterContent = client?.filterContentSet ?? new Set<string>();
      const matchesFilter = filterContent.has(filteredEmail);
      if (
        result.user.disabled ||
        (client?.filterMode === "whitelist" && !matchesFilter) ||
        (client?.filterMode === "blacklist" && matchesFilter)
      ) {
        throw new OAuthError("access_denied", "This account is not allowed to sign in to this application.", 403);
      }
      const sessionToken = await sessions.create(result.user.id);
      setCookie(c, SSO_COOKIE, sessionToken, { ...cookieOptions, maxAge: 30 * 24 * 60 * 60 });
      await oauth.attachUser(result.authorizationRequestId, result.user.id, new Date());
      return c.redirect(request.initialUri, 303);
    } catch (error: any) {
      const payload = microsoftAuthErrorPayload(error);
      const code = resolveAuthErrorCode(payload);
      const description = userFacingMicrosoftAuthError(payload)
        ?? "Upstream Error: Cannot get your authentication information from Microsoft. Try again later.";
      log.error(error, `Microsoft upstream callback failed (${code.code}: ${code.scenario})`);

      return frontendFlowError(
        c,
        error instanceof OAuthError
          ? error
          : new OAuthError("Upstream Error", description, 500, code.code),
      );
    }
  });

  app.post("/oauth/token", async (c) => {
    const body = await oauthRequestBody(c);
    const grantType = formValue(body, "grant_type");
    const credentials = clientCredentials(c, body, grantType === "client_credentials");
    let response: Record<string, unknown>;
    if (grantType === "authorization_code") {
      const code = formValue(body, "code");
      if (!code) throw new OAuthError("invalid_request", "code is required");
      response = await oauth.exchangeAuthorizationCode({
        code,
        ...credentials,
        redirectUri: formValue(body, "redirect_uri"),
        codeVerifier: formValue(body, "code_verifier"),
      });
    } else if (grantType === "refresh_token") {
      const refreshToken = formValue(body, "refresh_token");
      if (!refreshToken) throw new OAuthError("invalid_request", "refresh_token is required");
      response = await oauth.exchangeRefreshToken({ refreshToken, ...credentials });
    } else if (grantType === "client_credentials") {
      response = await oauth.exchangeClientCredentials({
        ...credentials,
        scope: formValue(body, "scope"),
        resource: formValue(body, "resource"),
      });
    } else {
      throw new OAuthError("unsupported_grant_type", "Unsupported grant_type");
    }
    return c.json(response);
  });

  const userInfo = async (c: Context) => {
    const authorization = c.req.header("authorization");
    if (!authorization?.startsWith("Bearer ")) {
      throw new OAuthError("invalid_token", "Bearer access token is required", 401);
    }
    c.header("Cache-Control", "no-store");
    return c.json(await oauth.userInfo(authorization.slice(7)));
  };
  app.get("/oauth/userinfo", userInfo);
  app.post("/oauth/userinfo", userInfo);

  app.post("/oauth/revoke", async (c) => {
    const body = await c.req.parseBody();
    const token = formValue(body, "token");
    const credentials = clientCredentials(c, body);
    if (!token) throw new OAuthError("invalid_request", "token is required");
    await oauth.revoke(token, credentials.clientId, credentials.clientSecret);
    return c.body(null, 200);
  });

  const logout = async (c: Context) => {
    await sessions.destroy(getCookie(c, SSO_COOKIE));
    deleteCookie(c, SSO_COOKIE, deleteCookieOptions);
    const interactionToken = getCookie(c, INTERACTION_COOKIE);
    let redirectTo = "/oauth/authorize";
    if (interactionToken) {
      const request = await oauth.getAuthorization(interactionToken);
      await oauth.clearInteractionUser(request.id);
      redirectTo = request.initialUri;
    }
    if (c.req.header("accept")?.includes("application/json")) return c.json({});
    return c.redirect(redirectTo, 303);
  };
  app.get("/oauth/logout", logout);
  app.post("/oauth/logout", logout);

  if (config.environment !== "test") {
    app.use("/*", serveStatic({ root: "./web/dist" }));
  }
  const serveIndex = async (c: Context) => c.html(await readFile("./web/dist/index.html", "utf8"));
  app.notFound(async (c) => {
    if (acceptsHtml(c)) {
      return c.html(
        renderErrorPage({
          status: 404,
          code: 404,
          error: "not_found",
          error_description: "The requested resource does not exist",
        }),
        404,
      );
    }
    return c.json({ error: "not_found", error_description: "The requested resource does not exist" }, 404);
  });

  app.onError((error, c) => {
    log.error(error, "Request failed");
    if (error instanceof OAuthError) {
      return c.json(error.toJSON(), error.status as 400);
    }
    const accept = c.req.header("accept") ?? "";
    if (accept.includes("text/html")) {
      return c.html(
        renderErrorPage({
          status: 500,
          code: 500,
          error: "server_error",
          error_description: "The request could not be completed",
        }),
        500,
      );
    }
    return c.json({ error: "server_error", error_description: "The request could not be completed" }, 500);
  });
  return app;
}
