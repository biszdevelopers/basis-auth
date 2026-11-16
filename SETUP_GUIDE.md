# Integrating a Project with basis-auth

This guide is for application and API teams connecting a project to a running
`basis-auth` service. It covers a first integration and keeping that integration
current when basis-auth changes.

It does **not** cover deploying or operating basis-auth itself. For that, see
`README.md` and the `docs/` submodule. This file is the downstream contract.

## 1. What you are integrating with

`basis-auth` is an OpenID Connect provider in front of Microsoft Entra ID.

- Users authenticate through Microsoft; your app never sees Microsoft tokens.
- Your application gets an ID token for login and an access token for its API.
- Each access token is bound to exactly one registered resource audience.
- Access tokens carry app-scoped `permissions` in addition to OAuth scopes.
- Your app owns its browser session. Never share or forward `basis_sso`.
- Your resource also needs a backchannel logout endpoint; see section 5.

| Endpoint | Use |
| --- | --- |
| `GET /.well-known/openid-configuration` | Discovery |
| `GET /oauth/authorize` | Authorization code + PKCE |
| `POST /oauth/token` | Code, refresh, and client-credentials exchange |
| `GET /oauth/jwks` | Public RS256 keys |
| `GET/POST /oauth/userinfo` | Profile claims for a user access token |
| `POST /oauth/revoke` | Revoke a refresh token or access token |
| `GET/POST /oauth/logout` | End the shared basis-auth SSO session |
| `GET /health` | Build and database identity (diagnostics) |

Token contract:

| Artifact | Behavior |
| --- | --- |
| Authorization request | Expires after 10 minutes; requires `openid`, state, nonce, and S256 PKCE. |
| Authorization code | Single-use, opaque, 60-second lifetime. |
| ID token | RS256 JWT, audience is your client ID, 10-minute lifetime. |
| User access token | RS256 JWT, `typ=at+jwt`, audience is one resource, default 60 minutes (`ACCESS_TOKEN_LIFETIME_MS`). |
| Refresh token | Opaque, rotates on every use, expires 30 days after original issue, only with `offline_access`. |
| Client-credentials token | Confidential clients only; no user identity, permissions, ID token, or refresh token. |

A user access token contains `sub`, `client_id`, `scope`, `permissions`, `gty`,
`jti`, `iat`, `exp`, `iss`, and `aud`. `permissions` is always a string array.
It is not an OAuth scope and must not be requested as one.

The stable user key is the basis-auth `sub`. Email is profile data and can
change; do not use it as a durable foreign key across your database.

## 2. What to request from the basis-auth operator

Before writing code, get these values. Ask for staging and production
separately; never reuse a client across environments.

- [ ] Issuer URL, for example `https://auth.example.org`.
- [ ] Client ID and client type (confidential or public).
- [ ] Client secret, for confidential clients only. It is shown once; the
      service stores only a scrypt hash.
- [ ] Registered redirect URI(s), exact scheme/host/port/path.
- [ ] Resource audience for each API you will call.
- [ ] Allowed scopes per resource.
- [ ] Permission definitions and first-login defaults for your client.
- [ ] Resource secret for each resource your app owns or receives callbacks for.
      It is shown once and is required for backchannel verification.
- [ ] The backchannel logout URL(s) registered for each resource.
- [ ] Internal API base URL, if your service calls the private management or
      user endpoints.
- [ ] Organization/tenant and account-filter restrictions that apply to you.

A resource must have at least one valid backchannel logout URL before
authorization-code sign-in works. Without one, authorization returns
`14408 invalid_resource`. A resource may register multiple URLs; logout and
access-token revocation events fan out to all of them.

If you operate basis-auth as well, registration is covered in section 3.
Otherwise, send the operator the values they ask for; most of section 3 is
their checklist.

## 3. Registering the client and resource

A resource declares an audience and its API scopes. A client declares redirect
URIs, resources, scopes, permission definitions, consent behavior,
organizations, and account filters.

Interactive:

```bash
bun run clients        # menu: list, add, edit, remove, register resource
bun run clients:add
bun run clients:remove
bun run clients:doctor
```

Non-interactive:

```bash
bun run clients:add -- '{"name":"Example Web","redirectUris":["https://app.example.org/oauth/callback"],"public":false,"resources":["urn:example:api"],"scopes":["projects.read"],"permissions":{"projects.member":"May use member features"},"defaultPermissions":["projects.member"]}'
```

Configuration seed:

```json
[
  {
    "audience": "urn:example:api",
    "name": "Example API",
    "scopes": ["projects.read", "projects.write"],
    "backchannelLogoutUris": [
      "https://api.example.org/auth/backchannel-logout"
    ]
  }
]
```

```json
[
  {
    "clientId": "example-web",
    "name": "Example Web",
    "clientSecret": "<at-least-16-characters>",
    "redirectUris": ["https://app.example.org/oauth/callback"],
    "public": false,
    "resources": ["urn:example:api"],
    "scopes": ["projects.read", "projects.write"],
    "resourceScopes": { "urn:example:api": ["projects.read", "projects.write"] },
    "permissions": { "projects.member": "May use member features" },
    "defaultPermissions": ["projects.member"],
    "requireConsent": true,
    "organizationIds": ["<entra-tenant-id>"],
    "filterMode": null,
    "filterContent": []
  }
]
```

Rules that break integrations most often:

- Redirect URIs match exactly. Public clients may use
  `http://localhost:*/path`; only the port varies, and only for public clients.
- Every client must reference at least one registered resource.
- Every requested custom scope must exist on the resource and be allowed for
  the client. The built-in scopes `openid`, `profile`, `email`, and
  `offline_access` are always available.
- `defaultPermissions` must name entries in that client's `permissions` object.
- Defaults are granted once, on the user's first successful login to that
  client. Adding defaults later does not update existing users.
- Permission grants belong to one client. Another client does not inherit them.
- `backchannelLogoutUris` entries must use HTTPS or `http://localhost`, with no
  credentials or fragment. The legacy single `backchannelLogoutUri` field is
  still accepted. An empty list clears the callbacks.
- Removing seed entries does not delete database rows. Remove the client or
  resource first, then remove its seed entry.

Resource secrets: every registered resource has one. Existing resources created
before the secret migration temporarily use `sk-1`; rotate them immediately.
Rotate with:

```bash
bun run resources:rotate-secret '<resource audience>'
```

or through the management portal's resource Secret tab. The new value is printed
once. Update every caller, including the backchannel receiver, before relying on
it.

## 4. Application (BFF) integration

Use a backend-for-frontend whenever the application has a server. The BFF owns
the client secret, PKCE verifier, tokens, and app session. The browser receives
only the short-lived authorization code.

### 4.1 Configuration

Store at least:

```text
BASIS_AUTH_ISSUER=https://auth.example.org
BASIS_AUTH_CLIENT_ID=example-web
BASIS_AUTH_CLIENT_SECRET=<secret>
BASIS_AUTH_RESOURCE=urn:example:api
BASIS_AUTH_RESOURCE_SECRET=<resource secret>
BASIS_AUTH_INTERNAL_URL=http://127.0.0.1:3001   # only if calling internal API
```

Public clients have no secret. Keep secrets server-side in every case.

### 4.2 Start login

1. Fetch discovery and JWKS from the issuer. Cache for about five minutes.
2. Generate independent random `state`, `nonce`, and a PKCE verifier. The
   verifier must be 43–128 characters from `[A-Za-z0-9._~-]`.
3. Store `state`, `nonce`, verifier, and the pending browser session server-side
   with a short expiry.
4. Redirect to `/oauth/authorize` with `code_challenge_method=S256`:

```text
client_id=example-web
response_type=code
redirect_uri=https://app.example.org/oauth/callback
scope=openid profile email offline_access projects.read
resource=urn:example:api
state=<random>
nonce=<random>
code_challenge=<base64url-sha256-of-verifier>
code_challenge_method=S256
```

Include `openid` always and exactly one resource. Omit `resource` only if the
client has exactly one registered resource. Include `offline_access` only when
you need a refresh token.

### 4.3 Handle the callback

- Compare `state` with the pending login before doing anything else.
- Handle `error=access_denied` as a cancellation; do not retry automatically.
- Exchange the code from the server within 60 seconds:

```bash
curl -u 'example-web:CLIENT_SECRET' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  --data-urlencode 'grant_type=authorization_code' \
  --data-urlencode 'code=AUTHORIZATION_CODE' \
  --data-urlencode 'code_verifier=ORIGINAL_VERIFIER' \
  https://auth.example.org/oauth/token
```

Use HTTP Basic for confidential clients. Public clients send `client_id` and no
secret. Do not send a body secret for authorization-code or refresh grants.
Repeating `redirect_uri` is optional and, if sent, must match the authorize
request exactly.

### 4.4 Validate the ID token

Use a standard OIDC/JWT library and check:

- RS256 signature against `/oauth/jwks`;
- exact issuer;
- audience equals your client ID;
- expiry;
- `nonce` equals the stored value;
- `at_hash` if your library does not check it automatically.

### 4.5 Create the app session

- Create your own `HttpOnly`, `Secure` in production, `SameSite=Lax` cookie.
- Store tokens server-side; encrypt refresh tokens at rest.
- Do not reuse, inspect, or forward the basis-auth `basis_sso` cookie.
- Link the local account by the stable `sub` using your account-linking policy.
- Do not silently link an existing account by email match alone.

### 4.6 Call the resource API

Send only the access token:

```http
Authorization: Bearer <access_token>
```

Never send the ID token or refresh token to an API.

Use `/oauth/userinfo` only when you intentionally need profile claims. It
accepts a user access token and returns claims allowed by its scopes.
Client-credentials tokens cannot call it, and UserInfo is not a substitute for
per-request token validation.

### 4.7 Refresh

- Refresh before expiry, leaving room for clock skew and retries.
- Use the same client authentication, `grant_type=refresh_token`, and the
  current refresh token.
- Each success returns a new refresh token and consumes the old one. Persist it
  before another request can use the session.
- Reuse of a consumed or expired token revokes the whole session family. Treat
  `invalid_grant` as "clear refresh state and require a new sign-in".
- Refreshing a resource that has no valid backchannel URL fails with
  `14408 invalid_resource` before the token is consumed.

## 5. Backchannel logout and revocation receiver

Each resource needs at least one receiver URL that handles three event types on
the same endpoint:

1. `action=test` webhook verification;
2. `logout_token` user logout;
3. `action=revoke_access_token` access-token revocation.

A resource may register multiple URLs; every configured URL receives logout and
access-token revocation events, and each URL is verified separately.

### 5.1 Verify the webhook

When each URL is saved, basis-auth posts form-encoded `action=test`, a one-time
`nonce` (43-character base64url), and a `challenge` (43-character base64url).

1. Return `202 Accepted` immediately.
2. Compute `challenge_hash` = HMAC-SHA256 with the current resource secret as
   key and the challenge as message, hex-encoded (64 chars).
3. Send the proof to the internal API within 10 seconds:

```js
import { createHmac } from "node:crypto";

const challengeHash = createHmac("sha256", resourceSecret)
  .update(challenge, "utf8")
  .digest("hex");

await fetch(new URL("/internal/backchannel/validate", internalUrl), {
  method: "POST",
  headers: {
    Authorization: `Bearer ${resourceSecret}`,
    "X-Basis-Resource": encodeURIComponent(audience),
    "Content-Type": "application/json",
  },
  body: JSON.stringify({ nonce, challenge_hash: challengeHash }),
});
```

| Response | Meaning |
| --- | --- |
| `200 {"status":"successful"}` | Accepted and consumed. |
| `400 invalid_request` | Bad input, wrong audience, unknown/used nonce, bad hash. |
| `401 unauthorized` | Resource credentials missing or invalid. |
| `408 timeout` | Challenge expired; save the URL again. |

The previous URL list stays active if verification fails. Clearing the list
takes effect immediately.

### 5.2 Handle logout tokens

When a user logs out, every configured receiver gets form-encoded `logout_token`.

Verify it against `/oauth/jwks` and require:

- `alg=RS256`;
- `typ=logout+jwt`;
- exact issuer;
- your resource audience;
- valid expiry (tokens live two minutes);
- `sub`;
- the `http://schemas.openid.net/event/backchannel-logout` event.

End the local sessions for that `sub` and return `200` or `204`.

### 5.3 Handle access-token revocations

When an access token is replaced by refresh or explicitly revoked, every
configured receiver gets form-encoded:

```text
action=revoke_access_token
jti=<token id>
valid_after=<unix seconds>
revocation_token=<signed JWT>
```

Verify `revocation_token` with `/oauth/jwks` and require:

- `alg=RS256`;
- `typ=at-revocation+jwt`;
- exact issuer;
- your resource audience;
- valid expiry (two minutes);
- `access_token_jti` and `valid_after` match the form fields.

Then store the JTI in a denylist and reject matching access JWTs at or after
`valid_after`. Use the signed `access_token_expires_at` claim, when present, to
expire the entry; also allow for your verifier's clock tolerance. Delivery can
retry, so keep the earliest valid-after time per JTI and return `200` or `204`
after persisting.

`ACCESS_TOKEN_REVOCATION_GRACE_SECONDS` on the service sets how far ahead
`valid_after` may be. It defaults to `0`.

### 5.4 Reject invalid access tokens consistently

Revoked, expired, malformed, and otherwise invalid tokens must produce the same
public response:

```http
HTTP/1.1 401
WWW-Authenticate: Bearer error="invalid_token"
```

```json
{ "error": "invalid_token", "error_description": "Invalid access token" }
```

Cookie-based apps may use their existing session error code with the same
description and status. Keep rejection reasons in server-side logs; never log
tokens, codes, secrets, verifiers, or raw cookies. Missing scopes and
permissions remain `403` as usual.

## 6. Resource API integration

Reuse `examples/hono-resource-server/auth.ts`. It caches JWKS, accepts only
RS256 and `typ=at+jwt`, validates issuer, audience, lifetime, and required
claims, applies the standard rejection response, and exposes
`requireScopes()` and `requirePermissions()`.

```ts
app.use("/api/*", basisAuth({
  issuer: process.env.BASIS_AUTH_ISSUER!,
  audience: "urn:example:api",
}));

app.get(
  "/api/projects",
  requireScopes("projects.read"),
  requirePermissions("projects.member"),
  (c) => c.json({ userId: c.get("basisToken").sub, projects: [] }),
);
```

- Never accept ID tokens at a resource API.
- Do not trust an unverified `aud`, `iss`, or `typ`.
- Local JWT validation reflects permission and disablement changes only when
  tokens expire. With the default lifetime, that is within 60 minutes.
- For immediate revocation, implement `loadTokenSubject` against
  `/internal/users/:userId` and fail closed. The response includes `disabled`
  and `tokensValidAfter`; reject disabled users and tokens whose `iat` is at or
  before the barrier.
- For immediate access-token revocation from refresh/logout, also implement the
  denylist from section 5.3.

## 7. Scopes and permissions

| Concept | Meaning | Where granted |
| --- | --- | --- |
| OAuth scope | API capability; appears in `scope` | Resource definition + client `resourceScopes` |
| Permission | App-scoped user entitlement; appears in `permissions` | Client permission catalog and user grants |
| Identity scope | `openid`, `profile`, `email`, `offline_access` | Always available |

- Request the smallest scope set the app uses.
- `projects.member` grants one client only. It is not shared across clients.
- An exact grant such as `nethack.Projects.read` covers that permission. A
  stored `nethack.Projects.all` covers every current and future permission below
  that namespace.
- Removing a definition does not bulk-edit users. Stale grants are pruned on the
  user's next login.
- Access tokens are not rewritten when a grant changes. Fetch a new token, or
  wait for refresh/expiry.
- `BOOTSTRAP_PERMISSION_GRANTS_JSON` is an operator-side seeding mechanism. It
  is not an app runtime API.

## 8. Internal API (only for trusted services)

If your service needs user state or management operations, call the private
listener. Every request authenticates as a resource, not with a shared token:

```http
Authorization: Bearer <resource secret>
X-Basis-Resource: <URL-encoded resource audience>
```

- `GET /internal/users/:userId` returns profile plus `disabled` and
  `tokensValidAfter`.
- `GET /internal/users/:userId/picture` returns picture bytes.
- `PATCH /internal/users/:userId` also requires the caller's audience to be
  listed in `INTERNAL_USER_WRITE_RESOURCES_JSON`.
- `POST /internal/users/:userId/logout` with `{"audience":"..."}` delivers a
  logout token for the caller's own audience. `204` delivered, `404` unknown
  user/resource, `409` no callback, `502` delivery failed.
- Management routes under `/internal/management` and `/internal/applications`
  require the portal resource credential and a user access token in
  `X-Basis-Actor-Token: Bearer ...`.
- `/internal/backchannel/validate` is the webhook proof endpoint from
  section 5.1.

Keep the internal listener on loopback or a protected private network. Treat
the resource secret as a credential.

## 9. Verification checklist

Run against the target issuer before declaring the integration done:

- [ ] Discovery and JWKS are reachable from the app and API networks.
- [ ] Login completes with `openid`, state, nonce, and PKCE.
- [ ] Callback rejects mismatched state and an invalid verifier.
- [ ] Code exchange succeeds once; a reused code fails with `invalid_grant`.
- [ ] ID token validates issuer, audience, signature, expiry, nonce, and hash.
- [ ] App creates its own session; no `basis_sso` sharing.
- [ ] API accepts a valid token for the exact resource audience.
- [ ] API rejects a token with the wrong audience, missing scope, or missing
      permission.
- [ ] API returns the standard `401 invalid_token` response for revoked,
      expired, and malformed tokens.
- [ ] Backchannel `action=test` verification succeeds and saves the URL.
- [ ] Logout ends the app session and terminates the matching user's API
      sessions through `logout_token`.
- [ ] Refresh rotates the token and a reused token forces re-authentication.
- [ ] A revoked access token is denied after the delivered revocation event.
- [ ] Disabled users cannot sign in and existing tokens are rejected as
      configured.
- [ ] Unregistered resources, scopes, and redirect URIs fail closed with the
      documented codes.

## 10. Updating an integration when basis-auth changes

An update is a contract review, not a dependency bump. The issuer URL may stay
the same while claims, lifetimes, revocation behavior, or registration rules
change.

### 10.1 Detect contract changes

Review the diff since the integration was last verified:

```bash
git log --oneline <last-verified-commit>..origin/main
git diff <last-verified-commit>..origin/main -- README.md examples/ src/config.ts src/oauth/ src/internal/
```

Focus on:

- endpoints and discovery metadata;
- token claims, `typ` values, lifetimes, and JWT algorithms;
- authorization requirements (PKCE, nonce, resource, scopes);
- refresh rotation and revocation behavior;
- backchannel logout and revocation event formats;
- client/resource registration fields and defaults;
- error codes and rejection responses;
- new required resource configuration such as webhook URLs.

Also compare against the live issuer, because it may run ahead of the code you
have locally:

```bash
curl -s https://auth.example.org/.well-known/openid-configuration
curl -s https://auth.example.org/oauth/jwks
```

### 10.2 Contract review checklist

- [ ] Client ID, client secret, and redirect URIs still match the environment.
- [ ] Resource audience and scopes still registered and allowed.
- [ ] Permission catalog, defaults, and grants still valid.
- [ ] Access and ID token validation still checks issuer, audience, algorithm,
      `typ`, expiry, nonce, and `at_hash`.
- [ ] Access-token lifetime assumptions (caches, refresh thresholds, clock skew)
      still hold.
- [ ] Standard `invalid_token` response unchanged.
- [ ] Backchannel receiver still verifies `logout_token` and
      `revocation_token` with the current JWKS and types.
- [ ] Access-token denylist still keyed by `jti` and honors `valid_after`.
- [ ] Every resource webhook URL still verified and reachable from basis-auth.
- [ ] Internal API callers still send `X-Basis-Resource` and the current secret.
- [ ] Management callers still send a valid actor token in
      `X-Basis-Actor-Token`.
- [ ] Local account linking still uses `sub`, never email.

### 10.3 Apply the update

1. Update app configuration and secrets first, then deploy code that accepts
   both old and new behavior when the contract changes.
2. If token validation changed, deploy API changes before the issuer starts
   issuing the new format.
3. If token lifetimes changed, adjust refresh thresholds and cache TTLs.
4. If revocation or logout changed, deploy the receiver before enabling the
   feature for the resource.
5. Re-run the section 9 checklist in staging, then production.
6. Keep the previous app version deployable until a full login, refresh, logout,
   and revocation cycle passes.

### 10.4 Rotate a client secret

Coordinate with the operator:

1. Operator rotates or sets the new secret.
2. Deploy the new secret to the app's environment.
3. Confirm login and refresh succeed.
4. Remove the old secret from every environment and secret store.
5. Remember that rotating a secret invalidates the old value immediately unless
   the operator keeps both; otherwise expect a brief auth outage.

If the client ID changes, update the app, the backchannel receiver, bootstrap
grants, and any `applicationId` references. Remove the old client ID from
`OIDC_CLIENTS_JSON` if the operator uses seed configuration, or startup may
recreate it.

### 10.5 Rotate a resource secret

The same resource secret is used by:

- the backchannel receiver to sign the webhook proof;
- internal API calls for that resource;
- any other service that authenticates as the resource.

Sequence:

1. Operator issues the new secret once.
2. Distribute it to every caller and keep it ready.
3. Switch callers, starting with the receiver and internal API clients.
4. Verify webhook re-verification, internal calls, refresh, and revocation.
5. Retire the old value.

A missed caller shows up as `401 unauthorized` from the internal listener or a
failed webhook verification.

### 10.6 Change scopes or permissions

- Adding a scope requires the resource to register it and the client to allow
  it before any request includes it.
- Removing a scope or permission definition does not rewrite existing tokens.
  Expect a transition window until tokens expire or are refreshed.
- Changing first-login defaults does not retroactively grant them.
- To revoke a user's access immediately, disable the user or end the
  authorization session through the management API; otherwise wait for token
  expiry.

### 10.7 Roll back

Keep the previous app deployment and both old/new credentials available during
the change window. If validation fails:

1. Route new logins back to the previous app version.
2. Stop accepting the new token shape at the API.
3. Do not translate or re-sign tokens between versions.
4. Restore the previous client/resource configuration with the operator.
5. Re-run the checklist after the rollback.

## 11. Troubleshooting

Numeric codes are application codes, not HTTP status codes.

| Code | Meaning | Fix |
| --- | --- | --- |
| `14001` | Client not registered | Check the client ID and environment. |
| `14002` | Client disabled | Ask the operator to re-enable it. |
| `14003` | Public client sent a secret | Use PKCE and no secret. |
| `14004` | Confidential secret invalid or missing | Use HTTP Basic and the current secret. |
| `14005` | Client has no organizations | Link an organization. |
| `14100` | Redirect URI missing or unregistered | Compare character-for-character. |
| `14401` | Scope not allowed | Align resource scopes, client scopes, and request. |
| `14407` | Resource not registered | Register the audience. |
| `14408` | Resource has no valid backchannel logout URL | Configure and verify at least one webhook. |
| `14429` | Unsupported response type | Send `response_type=code`. |
| `14501` | Resource not registered for this client | Add the audience to the client. |
| `2400` | Interaction missing or expired | Restart authorization. |

Other common failures:

- **`invalid_grant`** on code exchange: code expired, was consumed, or the
  verifier is wrong. Restart the flow.
- **`invalid_grant`** on refresh: the token was already rotated or the session
  was revoked. Clear state and require sign-in.
- **`401 invalid_token` at the API**: wrong audience, wrong issuer, expired,
  revoked, malformed, or not `typ=at+jwt`. Log the reason server-side only.
- **`403 insufficient_scope` / `insufficient_permissions`**: the token is valid
  but lacks the required grant. Fix registration or user grants.
- **Webhook verification fails**: challenge hash, secret, audience, nonce, or
  the 10-second window is wrong. Save the URL again for a fresh nonce.
- **Logout returns `409`**: the resource has no stored callback. Register and
  verify one.
- **Logout returns `502`**: the receiver was unreachable or did not return
  `200`/`204`.
- **Microsoft login errors** (`5004xx`): they are upstream Entra failures
  mapped by the provider. Check the documented Microsoft error tables in
  `README.md` before changing integration code.

## 12. Keeping this guide current

This file is the downstream integration contract and part of the product. Any
change to endpoints, token claims, `typ` values, lifetimes, revocation or
backchannel behavior, scopes, permissions, client/resource registration,
internal API authentication, error codes, or the example integration must update
this guide in the same change. See `AGENTS.md` for the mandatory rule.
