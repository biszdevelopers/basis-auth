import { and, eq, gt } from "drizzle-orm";
import { toPng } from "jdenticon";
import * as client from "openid-client";
import type { AppConfig } from "./config.js";
import type { Database } from "./database/client.js";
import { upstreamAuthRequests } from "./database/schema.js";
import { isVerifiedBasisEmail, type IdentityService } from "./identity.js";

const MICROSOFT_SCOPE = "openid profile email User.Read";

function defaultProfilePicture(issuer: string, subject: string) {
  return { data: toPng(`${issuer}:${subject}`, 512), contentType: "image/png" };
}

async function profilePicture(
  pictureUrl: unknown,
  accessToken: string,
  issuer: string,
  subject: string,
) {
  if (typeof pictureUrl !== "string") return defaultProfilePicture(issuer, subject);

  try {
    const response = await fetch(pictureUrl, {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
    const contentType = response.headers.get("content-type");
    if (!response.ok || !contentType?.startsWith("image/")) throw new Error("Profile picture unavailable");
    return { data: Buffer.from(await response.arrayBuffer()), contentType };
  } catch {
    return defaultProfilePicture(issuer, subject);
  }
}

export function createMicrosoftService(
  appConfig: AppConfig,
  db: Database,
  identity: IdentityService,
) {
  let discovered: Promise<client.Configuration> | undefined;

  function microsoftConfig() {
    if (!appConfig.microsoft) throw new Error("Microsoft login is not configured");
    discovered ??= client.discovery(
      new URL(appConfig.microsoft.issuer),
      appConfig.microsoft.clientId,
      appConfig.microsoft.clientSecret,
    );
    return discovered;
  }

  async function begin(authorizationRequestId: string) {
    const configuration = await microsoftConfig();
    const state = client.randomState();
    const nonce = client.randomNonce();
    const codeVerifier = client.randomPKCECodeVerifier();
    const codeChallenge = await client.calculatePKCECodeChallenge(codeVerifier);
    await db.insert(upstreamAuthRequests).values({
      state,
      authorizationRequestId,
      codeVerifier,
      nonce,
      expiresAt: new Date(Date.now() + 10 * 60 * 1000),
    });
    return client.buildAuthorizationUrl(configuration, {
      redirect_uri: `${appConfig.issuer}/oauth/callback/microsoft`,
      scope: MICROSOFT_SCOPE,
      response_type: "code",
      state,
      nonce,
      code_challenge: codeChallenge,
      code_challenge_method: "S256",
    });
  }

  async function callback(currentUrl: URL) {
    const state = currentUrl.searchParams.get("state");
    if (!state) throw new Error("Microsoft callback is missing state");
    const [request] = await db
      .delete(upstreamAuthRequests)
      .where(
        and(
          eq(upstreamAuthRequests.state, state),
          gt(upstreamAuthRequests.expiresAt, new Date()),
        ),
      )
      .returning();
    if (!request) throw new Error("Microsoft login request is invalid or expired");

    const configuration = await microsoftConfig();
    const tokens = await client.authorizationCodeGrant(configuration, currentUrl, {
      pkceCodeVerifier: request.codeVerifier,
      expectedState: state,
      expectedNonce: request.nonce,
    });
    const claims = tokens.claims();
    if (!claims?.sub) throw new Error("Microsoft ID token is missing sub");
    if (!tokens.access_token) throw new Error("Microsoft token response is missing access token");
    const userInfo = await client.fetchUserInfo(configuration, tokens.access_token, claims.sub);

    const emailValue = userInfo.email ?? claims.email ?? claims.unique_name;
    if (typeof emailValue !== "string" || !emailValue) {
      throw new Error("Microsoft ID token is missing email or unique_name");
    }

    const user = await identity.upsertFromMicrosoft({
      provider: "basischina-microsoft",
      issuer: claims.iss,
      subject: claims.sub,
      email: emailValue,
      emailVerified: isVerifiedBasisEmail(emailValue),
      displayName:
        typeof userInfo.name === "string"
          ? userInfo.name
          : typeof claims.name === "string"
            ? claims.name
            : undefined,
      picture: await profilePicture(
        userInfo.picture ?? claims.picture,
        tokens.access_token,
        claims.iss,
        claims.sub,
      ),
    });
    return { authorizationRequestId: request.authorizationRequestId, user };
  }

  return { begin, callback };
}

export type MicrosoftService = ReturnType<typeof createMicrosoftService>;


export interface MicrosoftAuthErrorPayload {
  error: string;
  error_description?: string;
  error_codes?: number[];
  timestamp?: string;
  trace_id?: string;
  correlation_id?: string;
  error_uri?: string;
}

export interface ResolvedAuthError {
  code: number;
  scenario: string;
  matchedBy: 'numeric_code' | 'protocol_error' | 'fallback';
  rawError: string;
  rawErrorCode?: number;
}

/**
 * Maps Microsoft OAuth token exchange errors to internal application error codes (500410 + N).
 * Evaluates `error_codes[0]` first, falling back to the standard `error` string.
 */
export function resolveAuthErrorCode(payload: MicrosoftAuthErrorPayload): ResolvedAuthError {
  const primaryCode = payload.error_codes?.[0];
  const protocolError = payload.error?.toLowerCase()?.trim();

  // Priority 1: Specific Microsoft AADSTS Numeric Codes (error_codes[0])
  if (primaryCode !== undefined) {
    switch (primaryCode) {
      case 7000215:
        return {
          code: 500411,
          scenario: "Invalid client secret value sent (often confused with Secret ID).",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 70002:
        return {
          code: 500412,
          scenario: "Client authentication failed or invalid client secret.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 70000:
        return {
          code: 500413,
          scenario: "Authorization code is invalid, expired, or already redeemed.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 50011:
        return {
          code: 500414,
          scenario: "Redirect URI mismatch between authorize call and token request.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 50148:
        return {
          code: 500415,
          scenario: "PKCE code verifier validation failed.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 65001:
        return {
          code: 500416,
          scenario: "User or admin consent is required for requested scopes.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 50001:
        return {
          code: 500417,
          scenario: "Invalid or disabled resource/scope requested.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 50076:
      case 50079:
        return {
          code: 500418,
          scenario: "Multi-Factor Authentication (MFA) challenge required.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
      case 53003:
        return {
          code: 500419,
          scenario: "Blocked by Azure AD Conditional Access policy.",
          matchedBy: 'numeric_code',
          rawError: payload.error,
          rawErrorCode: primaryCode,
        };
    }
  }

  // Priority 2: Standard OAuth 2.0 Protocol Errors (`error` string)
  switch (protocolError) {
    case 'invalid_request':
      return {
        code: 500420,
        scenario: "Malformed request parameters (missing mandatory parameters).",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'invalid_grant':
      return {
        code: 500421,
        scenario: "Generic invalid grant (code/refresh token invalid or expired).",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'invalid_client':
      return {
        code: 500422,
        scenario: "Generic client authentication failure.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'unauthorized_client':
      return {
        code: 500423,
        scenario: "Client is not authorized to use the authorization_code grant type.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'unsupported_grant_type':
      return {
        code: 500424,
        scenario: "Requested grant type is not supported by Microsoft Entra ID.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'invalid_scope':
      return {
        code: 500425,
        scenario: "Invalid, unknown, or malformed scopes requested.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'interaction_required':
      return {
        code: 500426,
        scenario: "User interaction is required before token issuance.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
    case 'temporarily_unavailable':
      return {
        code: 500427,
        scenario: "Microsoft Entra service is temporarily degraded or down.",
        matchedBy: 'protocol_error',
        rawError: payload.error,
        rawErrorCode: primaryCode,
      };
  }

  // Fallback: Default code for unmapped errors
  return {
    code: 500410,
    scenario: "Unclassified Microsoft authentication error.",
    matchedBy: 'fallback',
    rawError: payload.error,
    rawErrorCode: primaryCode,
  };
}