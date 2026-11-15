# Implement a backchannel logout receiver

Register the resource audience with Basis Auth and configure the receiver with the resource's current secret and the Basis Auth internal API URL. In the portal, open **Resource Servers → Backchannel** for that audience and enter the receiver's URL. Use HTTPS or an HTTP URL whose hostname is exactly `localhost`, such as `http://localhost:4321/logout`. The URL must be reachable from Basis Auth. The receiver must also be able to reach Basis Auth's internal listener.

## Verify the webhook

1. When you save the URL, Basis Auth sends a `POST` to it with `Content-Type: application/x-www-form-urlencoded`. The body contains `action=test`, a single-use `nonce`, and a random `challenge`. Preserve both values exactly as received.
2. Return HTTP `202 Accepted` promptly. Then send the proof to `POST /internal/backchannel/validate`. The entire exchange has a 10-second deadline.
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

Basis Auth saves the URL after it receives both the receiver's `202` and valid proof. The previous URL stays active if verification fails. Clearing the URL takes effect immediately. A new URL configured through `OIDC_RESOURCES_JSON` goes through the same check after the internal listener starts.

Authorization-code sign-in requires a valid saved webhook for the requested resource. A missing or invalid URL produces `14408: invalid_resource`. To bootstrap the portal's own resource before you can sign in, configure its webhook through `OIDC_RESOURCES_JSON` and start the receiver with its resource secret.

## Receive logout events

When Basis Auth delivers a logout, it sends a form-encoded `POST` to the verified URL with a `logout_token` field. Route `action=test` requests to the verification flow and `logout_token` requests to session termination.

Verify the logout token signature against Basis Auth's `/oauth/jwks`. Require `alg=RS256`, `typ=logout+jwt`, the configured issuer, the resource audience, and a valid expiration. Basis Auth issues these tokens for two minutes and includes `sub`, `iat`, `jti`, and the `http://schemas.openid.net/event/backchannel-logout` event. End the local sessions for the verified `sub` and return `200` or `204`.
