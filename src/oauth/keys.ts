import {
  accessTokenClaimsSchema,
  type AccessTokenClaims as SchemaAccessTokenClaims,
} from "@basis/schema/auth";
import { DelegatedPermissionSet } from "@basis/schema/permissions";
import {
  createLocalJWKSet,
  importJWK,
  jwtVerify,
  SignJWT,
  type JWK,
} from "jose";
import { z } from "zod";
import type { AppConfig } from "../config.js";
import type { Database } from "../database/client.js";
import type { IdentityService } from "../identity.js";
import { isAccessTokenRevoked } from "./access-token-revocations.js";
import { randomToken } from "./crypto.js";

const privateFields = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);
const basisAuthAccessTokenClaimsSchema = accessTokenClaimsSchema
  .omit({ aud: true, permissions: true })
  .extend({
    aud: accessTokenClaimsSchema.shape.aud.optional(),
    permissions: z.array(z.string()),
    gty: z.enum(["authorization_code", "refresh_token", "client_credentials"]),
  });

function toPublicJwk(jwk: JWK): JWK {
  return Object.fromEntries(Object.entries(jwk).filter(([key]) => !privateFields.has(key))) as JWK;
}

export type AccessTokenClaims = Pick<
  SchemaAccessTokenClaims,
  "sub" | "client_id" | "scope" | "jti" | "iat" | "exp" | "iss"
> &
  Pick<SchemaAccessTokenClaims, "permissions"> &
  Partial<Pick<SchemaAccessTokenClaims, "aud">> & {
    gty: "authorization_code" | "refresh_token" | "client_credentials";
  };

type UserState = { id: string; disabled: boolean; tokensValidAfter: Date | null };
type Account = Awaited<ReturnType<IdentityService["findAccount"]>>;

export async function createKeyService(config: AppConfig, identity: IdentityService, db?: Pick<Database, "select">) {
  const signingJwk = config.jwks.keys[0];
  if (!signingJwk?.d || signingJwk.kty !== "RSA") {
    throw new Error("The first OIDC signing JWK must be a private RSA key");
  }
  const activeJwk = signingJwk;
  const signingKey = await importJWK(signingJwk, "RS256");
  const publicJwks = { keys: config.jwks.keys.map(toPublicJwk) };
  const verifier = createLocalJWKSet(publicJwks);

  async function issueAccessToken(
    input: {
      userId: string;
      clientId: string;
      scopes: string[];
      resource?: string;
      grantType?: "authorization_code" | "refresh_token";
      jti?: string;
    },
    preloaded?: { user?: UserState; permissions?: string[] },
  ) {
    const user = preloaded?.user ?? (await identity.findUser(input.userId));
    if (!user || user.disabled) throw new Error("Cannot issue an access token for a missing or disabled user");
    const permissions = [...new DelegatedPermissionSet(
      preloaded?.permissions ?? (await identity.permissionsFor(input.userId, input.clientId)),
    ).permissions];
    const token = new SignJWT({
      client_id: input.clientId,
      scope: input.scopes.join(" "),
      permissions,
      gty: input.grantType ?? "authorization_code",
    })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "at+jwt" })
      .setIssuer(config.issuer)
      .setSubject(input.userId);
    if (input.resource) token.setAudience(input.resource);
    return token
      .setJti(input.jti ?? randomToken())
      .setIssuedAt()
      .setExpirationTime(`${config.accessTokenLifetimeSeconds}s`)
      .sign(signingKey);
  }

  async function issueApplicationAccessToken(input: {
    clientId: string;
    scopes: string[];
    resource: string;
  }) {
    return new SignJWT({
      client_id: input.clientId,
      scope: input.scopes.join(" "),
      permissions: [],
      gty: "client_credentials",
    })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "at+jwt" })
      .setIssuer(config.issuer)
      .setSubject(input.clientId)
      .setAudience(input.resource)
      .setJti(randomToken())
      .setIssuedAt()
      .setExpirationTime(`${config.accessTokenLifetimeSeconds}s`)
      .sign(signingKey);
  }

  async function issueIdToken(
    input: {
      userId: string;
      clientId: string;
      scopes: string[];
      nonce: string;
      authenticatedAt: Date;
      accessToken: string;
    },
    preloaded?: { account?: Account; permissions?: string[] },
  ) {
    const account =
      preloaded?.account ?? (await identity.findAccount(input.userId));
    if (!account) throw new Error("User no longer exists");
    const claims = await account.claims("id_token", input.scopes.join(" "));
    const picture = input.scopes.includes("profile")
      ? { picture: `${config.issuer}/api/picture/${encodeURIComponent(input.userId)}` }
      : {};
    const digest = Buffer.from(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(input.accessToken)));
    const atHash = digest.subarray(0, digest.length / 2).toString("base64url");
    return new SignJWT({ ...claims, ...picture, nonce: input.nonce, auth_time: Math.floor(input.authenticatedAt.getTime() / 1000), at_hash: atHash })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "JWT" })
      .setIssuer(config.issuer)
      .setSubject(input.userId)
      .setAudience(input.clientId)
      .setIssuedAt()
      .setExpirationTime("10m")
      .sign(signingKey);
  }

  async function issueLogoutToken(userId: string, audience: string) {
    return new SignJWT({ events: { "http://schemas.openid.net/event/backchannel-logout": {} } })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "logout+jwt" })
      .setIssuer(config.issuer)
      .setSubject(userId)
      .setAudience(audience)
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(signingKey);
  }

  async function issueAccessTokenRevocation(input: { audience: string; jti: string; validAfter: number; expiresAt: number | null }) {
    return new SignJWT({
      access_token_jti: input.jti,
      valid_after: input.validAfter,
      access_token_expires_at: input.expiresAt,
    })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "at-revocation+jwt" })
      .setIssuer(config.issuer)
      .setAudience(input.audience)
      .setIssuedAt()
      .setExpirationTime("2m")
      .sign(signingKey);
  }

  async function readAccessToken(token: string, audience?: string) {
    const { payload } = await jwtVerify(token, verifier, {
      algorithms: ["RS256"],
      issuer: config.issuer,
      typ: "at+jwt",
      ...(audience ? { audience } : {}),
    });
    const parsed = basisAuthAccessTokenClaimsSchema.safeParse(payload);
    if (!parsed.success) {
      throw new Error("Access token claims are invalid");
    }
    return parsed.data as AccessTokenClaims;
  }

  async function verifyAccessToken(token: string, audience?: string) {
    const claims = await readAccessToken(token, audience);
    if (db && await isAccessTokenRevoked(db, claims.jti)) throw new Error("Access token has been revoked");
    if (claims.gty === "client_credentials" && claims.sub === claims.client_id) {
      return claims;
    }
    if (!/^[A-Za-z0-9_-]{43}$/.test(claims.jti)) {
      throw new Error("Access token was issued before session JTI tracking");
    }
    const user = await identity.findUserCompact(claims.sub);
    if (
      !user ||
      user.disabled ||
      (user.tokensValidAfter && claims.iat * 1000 <= user.tokensValidAfter.getTime())
    ) {
      throw new Error("Access token has been revoked");
    }
    return claims;
  }

  return { publicJwks, issueAccessToken, issueApplicationAccessToken, issueIdToken, issueLogoutToken, issueAccessTokenRevocation, readAccessToken, verifyAccessToken };
}

export type KeyService = Awaited<ReturnType<typeof createKeyService>>;
