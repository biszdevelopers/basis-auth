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
