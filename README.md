# basis-auth

`basis-auth` is the authentication and identity boundary for Basis applications. It delegates human login to Microsoft Entra ID and acts as an OpenID Connect Provider for separately deployed applications and resource APIs.

It intentionally does **not** host application resources or share browser sessions with downstream applications.

The implemented surface is intentionally small and is not presented as OpenID certification. Before an internet-facing production launch, run the OpenID Foundation conformance suite and obtain a focused security review of the authorization, redirect, refresh-rotation, and key-management paths.

## Architecture

- **Hono** serves health checks, Microsoft login/callback routes, and the React interaction UI.
- **First-party OAuth/OIDC services** implement the deliberately limited discovery, authorization, token, UserInfo, JWKS, revocation, and logout surface.
- **PostgreSQL** stores identities, permissions, clients, grants, sessions, codes, and refresh-token state.
- **React/Vite** provides the same-origin login and consent interface.

Protocol endpoints:

| Endpoint | Purpose |
| --- | --- |
| `/.well-known/openid-configuration` | OIDC discovery |
| `/.well-known/oauth-authorization-server` | OAuth metadata |
| `/oauth/authorize` | Authorization code flow |
| `/oauth/token` | Code and refresh-token exchange |
| `/oauth/jwks` | RS256 public signing keys |
| `/oauth/userinfo` | OIDC identity claims |
| `/oauth/revoke` | Refresh-token revocation |
| `/oauth/logout` | OIDC/session logout |

Access tokens are ten-minute RS256 JWTs with `typ=at+jwt`. Their `aud` identifies the resource API, while `client_id` identifies the requesting application. Resource APIs validate them locally with the published JWKS.

## Local setup

Requirements: Node.js 24, Bun, and PostgreSQL 14 or newer. Docker is not required.

```bash
cp .env.example .env
bun install
# Point DATABASE_URL in .env at any PostgreSQL 14+ instance.
bun run keys:generate
```

Put the generated JSON into `OIDC_JWKS_JSON`, configure Microsoft Entra, then register this redirect URI in the Entra application:

```text
http://localhost:3000/oauth/callback/microsoft
```

Start the service:

```bash
bun run dev
```

Development serves the React build and OAuth endpoints from Hono at `http://localhost:3000`. `bun run dev` starts Hono plus a Vite build watcher; edits under `web/src/*` rebuild automatically, then reload the browser to see the change. Use `bun run dev:auth` when you only need the backend.

The server applies checked-in Drizzle migrations and idempotently upserts configured clients and resource servers during startup. Removed configuration entries are not automatically deleted.

Production must set an HTTPS `OIDC_ISSUER`, persistent private JWKS, two or more strong cookie keys, Microsoft credentials, and a TLS-enabled PostgreSQL connection. For signing-key rotation, publish the new public key alongside the active key, deploy it everywhere, make it the first private key in the configured JWKS, and retain old public keys until all tokens they signed have expired.

## Client and resource registration

`OIDC_RESOURCES_JSON` declares API audiences and the scopes each API accepts. `OIDC_CLIENTS_JSON` declares which resources and scopes each application may request.

Confidential BFF clients use `client_secret_basic`; PostgreSQL stores only a scrypt hash of the configured secret. Public clients use `token_endpoint_auth_method=none`. Every authorization request from either client type must include a fresh RFC 7636 verifier-derived `code_challenge` and `code_challenge_method=S256`. The token request must include the matching `code_verifier`; `nonce` remains an additional OIDC replay binding and is not a substitute for PKCE.

A typical authorization request is:

```text
/oauth/authorize?
  client_id=basis-portal&
  response_type=code&
  redirect_uri=https%3A%2F%2Fportal.example.org%2Foauth%2Fcallback&
  scope=openid%20profile%20email%20permissions%20offline_access%20projects.read&
  resource=urn%3Abasis%3Aapi%3Aprojects&
  state=...&nonce=...&
  code_challenge=...&code_challenge_method=S256
```

`offline_access` is required for a refresh token. Refresh tokens expire after 30 days and rotate on every use. Consent is remembered by client and expanded scope set; clients configured with `requireConsent: false` silently approve their registered grants.

Each client can restrict Microsoft accounts with `filterMode` and `filterContent` in `OIDC_CLIENTS_JSON`. Set `filterMode` to `"whitelist"` to allow only the normalized Microsoft email/unique names in `filterContent`, or `"blacklist"` to reject those names. Leave the mode as `null` with an empty list to allow all accounts. Administrators can also set `users.disabled` to block an account across every client; blocked sign-ins return to the authorization page with an error.

Manage clients with the interactive TUI (numbered pickers, validated prompts, no flags needed):

```bash
bun run clients          # menu: list, add, remove, edit
bun run clients:add      # add-client walkthrough
bun run clients:remove   # pick a client from a numbered list
```

Adding walks through name, type (confidential/public), redirect URIs, resources (picked from the registered list), scopes, consent, and optional account filters. For confidential clients, leave the secret blank to auto-generate a `sk-...` secret; it is printed once (PostgreSQL stores only a scrypt hash, so copy it then). Editing keeps the existing secret and owners unless you rotate or change the client type; a rotated secret is likewise shown once. Passing a JSON definition without `clientId` still works non-interactively and also auto-generates a missing secret:

```bash
bun run clients:add -- '{"name":"Example","redirectUris":["https://example.test/callback"],"public":false,"resources":["urn:basis:api:example"]}'
bun run clients:remove -- 3fa85f64-5717-4562-b3fc-2c963f66afa6
```

Removing a client cascades to its authorization data. Remove a client from `OIDC_CLIENTS_JSON` before deleting it, otherwise the startup seed will create it again.

TUI-managed clients and resources live in the database only (no `OIDC_*_JSON` edits, no restart): new resource audiences are registered on the spot, new clients authorize instantly, and edits apply within ~60s (client-cache TTL).

## Downstream BFF integration

Each downstream application owns its browser session. It must not forward, inspect, or share the `basis-auth` cookie.

1. Discover `basis-auth` from `/.well-known/openid-configuration`.
2. Store state, nonce, and a PKCE verifier in a short-lived server-side BFF session.
3. Redirect the browser to `/oauth/authorize`, including one registered `resource` audience.
4. Exchange the callback code from the BFF using `client_secret_basic` and the verifier. OAuth 2.1 clients do not need to repeat `redirect_uri` at this step; if supplied for OAuth 2.0 compatibility, it must exactly match the authorization request.
5. Validate the ID token, then create the application's own HTTP-only session cookie.
6. Encrypt the refresh token in the BFF's server-side session store.
7. Send only the access token as `Authorization: Bearer ...` to the resource API.
8. Refresh before access-token expiry; revoke the refresh token and delete the BFF session on logout.

ID tokens authenticate the client login. They must never be accepted by resource APIs. UserInfo may be used for intentional profile retrieval, not as per-request token validation.

## Resource API integration

[`examples/hono-resource-server`](./examples/hono-resource-server) contains reusable Hono middleware and a minimal API. The middleware:

- downloads and caches `/oauth/jwks`;
- allows only RS256 and `typ=at+jwt`;
- validates exact issuer, audience, and token lifetime;
- exposes `requireScopes()` and `requirePermissions()` helpers.

Other platforms should implement the same contract with their standard OAuth resource-server library. APIs that only verify JWTs locally observe user disablement and permission changes when existing access tokens expire, within ten minutes.

Resource APIs that require immediate per-user revocation must also load the token subject's `disabled` and `tokens_valid_after` state after signature validation. Reject disabled subjects and tokens whose `iat` is at or before that barrier. The example middleware exposes `loadTokenSubject` for this check while keeping JWT and revocation validation local to the resource API.

`basis-api` uses the private `/internal/users/:userId` endpoints for this state, profile pictures, and user PATCH operations. They run on a separate listener configured by `INTERNAL_API_HOST` and `INTERNAL_API_PORT`, bound to `127.0.0.1:3001` by default. Requests also require `Authorization: Bearer <INTERNAL_API_TOKEN>`. Use the same random token in trusted local services and keep the listener off the public network.

## Development commands

```bash
bun run typecheck
bun run test
bun run build
bun run db:generate
bun run db:migrate
```

PostgreSQL adapter integration tests are opt-in because they require a `DATABASE_URL`:

```bash
RUN_POSTGRES_TESTS=1 bun run test
```

# API Errors:

These are NOT Http response codes.

| Code | Namespace | Description |
| --- | --- | -----|
| 400 | internal_error | General error such as invalid inputs |
| 14001 | invalid_client | Client is not registered and not found |
| 14002 | invalid_client | Client is disabled |
| 14003 | invalid_client | A public client attempts to send an application secret. `PKCE` is required for this mode. |
| 14004 | invalid_client | Incorrect or unconfigured client secret |
| 14100 | invalid
| 14429 | unsupported_response_type | Unsupported response type |
| 14401 | invalid_scope | Client requests one or more scopes that is not configured or permitted |
| 14407 | unknown_resource | One or more selected resource of the client is not supported or not found. This usually shouldn't happen since client resource configuration and schemed and automated. |
| 14501 | invalid_target | One or more resources is not registered for this application |
| 2400 | invalid_request | Frontend authentication flow cookie not found or expired |
| 50040 | server_error | Internal server error occured during login, such as connection error with microsoft login / authentication endpoint |
