# Implement a backchannel logout receiver

Register the resource audience with Basis Auth and configure the receiver with the resource's current secret and the Basis Auth internal API URL. A resource can have more than one callback URL; logout and access-token revocation events are delivered to every verified URL. In the portal, open **Resource Servers → Backchannel** for that audience and enter the receiver URLs one at a time. Use HTTPS or an HTTP URL whose hostname is exactly `localhost`, such as `http://localhost:4321/logout`. Every URL must be reachable from Basis Auth. The receiver must also be able to reach Basis Auth's internal listener.

## Verify the webhook

Each URL is verified independently. The exchange has a 10-second deadline.

1. When you save a URL, Basis Auth sends a `POST` to it with `Content-Type: application/x-www-form-urlencoded`. The body contains `action=test`, a single-use `nonce`, and a random `challenge`. Preserve both values exactly as received.
2. Return HTTP `202 Accepted` promptly. Then send the proof to `POST /internal/backchannel/validate`.
3. Send the original `nonce` and `challenge_hash`. Compute the hash as HMAC-SHA256 with the current resource secret as the key and the challenge string as the message. Encode the digest as 64 hexadecimal characters. The callback accepts JSON or form data.

Both the nonce and challenge are 43-character base64url strings. Use the challenge as received in the HMAC message, including its original casing.

### Send the proof from Node.js

Call this function with the `nonce` and `challenge` parsed from the test request.

```js
import { createHmac } from "node:crypto";

async function validateWebhook({ internalApiUrl, audience, resourceSecret, nonce, challenge }) {
  const challengeHash = createHmac("sha256", resourceSecret)
    .update(challenge, "utf8")
    .digest("hex");

  return fetch(new URL("/internal/backchannel/validate", internalApiUrl), {
    method: "POST",
    headers: {
      Authorization: `Bearer ${resourceSecret}`,
      "X-Basis-Resource": encodeURIComponent(audience),
      "Content-Type": "application/json",
    },
    body: JSON.stringify({ nonce, challenge_hash: challengeHash }),
  });
}
```

### Handle the response

| HTTP status | Body | Meaning |
| --- | --- | --- |
| `200` | `{"status":"successful"}` | Basis Auth accepted and consumed the proof. |
| `400` | `{"error":"invalid_request"}` | The input is malformed, the nonce is unknown or already used, the audience differs, or the hash is incorrect. |
| `401` | `{"error":"unauthorized"}` | The resource credentials are missing or invalid. |
| `408` | `{"error":"timeout"}` | The challenge expired. Save the webhook URL again to start a fresh verification. |

Basis Auth saves a URL after it receives both the receiver's `202` and valid proof. The previous list stays active if verification fails. Clearing the list takes effect immediately. URLs configured through `OIDC_RESOURCES_JSON` go through the same checks after the internal listener starts.

Authorization-code sign-in works without a valid saved webhook. For those resources, newly issued access tokens have a maximum lifetime of 10 minutes across code exchange, refresh, and client credentials. To enable callback delivery and use the configured access-token lifetime, verify a webhook for the resource.

## Receive logout events

When Basis Auth delivers a logout, it sends a form-encoded `POST` to every verified URL with a `logout_token` field. Route `action=test` requests to the verification flow and `logout_token` requests to session termination.

Verify the logout token signature against Basis Auth's `/oauth/jwks`. Require `alg=RS256`, `typ=logout+jwt`, the configured issuer, the resource audience, and a valid expiration. Basis Auth issues these tokens for two minutes and includes `sub`, `iat`, `jti`, and the `http://schemas.openid.net/event/backchannel-logout` event. End the local sessions for the verified `sub` and return `200` or `204`.

## Receive access-token revocations

Basis Auth posts to every valid saved URL when an access token is replaced by refresh or explicitly revoked. For APIs that rely on webhooks for revocation, a token can remain usable until expiry when the resource has no valid callback. Expired access tokens are rejected during normal JWT validation.

The form body contains `action=revoke_access_token`, the revoked access token's `jti`, `valid_after` as a Unix timestamp in seconds, and a signed `revocation_token`. `ACCESS_TOKEN_REVOCATION_GRACE_SECONDS` controls how far in the future `valid_after` is set and defaults to `0`.

Verify `revocation_token` with `/oauth/jwks`. Require `alg=RS256`, `typ=at-revocation+jwt`, the configured issuer, your resource audience, and a valid expiration. The verified claims `access_token_jti` and `valid_after` must match the form fields. Use those signed claims to store the JTI in your denylist and reject matching access JWTs at or after `valid_after`. The signed `access_token_expires_at` claim is the old JWT's expiration in Unix seconds, or `null` for a session created before expiration tracking. When known, keep the entry through expiration plus your JWT verifier's clock tolerance.

Return `200` or `204` after persisting the entry. Delivery may be retried, so handle duplicates by keeping the earliest revocation time for the JTI. Each event targets one access token. Continue to handle user-wide session termination through the existing `logout_token` flow.

Reject access tokens found in the denylist using the same public response as other invalid access tokens. Follow the [access-token rejection standard](../README.md#access-token-rejection) and keep any reason for the rejection in server-side console logs.

The portal can list a user's active authorization sessions through `GET /internal/management/users/:userId/sessions` and end one through `DELETE /internal/management/users/:userId/sessions/:sessionId`. Both routes require the portal's resource credentials and a signed portal actor token. Users can manage their own sessions. Access to other users' sessions follows the portal's user read and update permissions. Ending a session disables its refresh grant and queues a revocation for its current access token with no grace period. Basis Auth attempts delivery to that session's resource before responding and retries failed deliveries.
