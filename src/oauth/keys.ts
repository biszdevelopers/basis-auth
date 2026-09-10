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
import type { IdentityService } from "../identity.js";

const privateFields = new Set(["d", "p", "q", "dp", "dq", "qi", "oth", "k"]);
const basisAuthAccessTokenClaimsSchema = accessTokenClaimsSchema
  .omit({ aud: true, permissions: true })
  .extend({
    aud: accessTokenClaimsSchema.shape.aud.optional(),
    permissions: z.array(z.string()),
  });

function toPublicJwk(jwk: JWK): JWK {
  return Object.fromEntries(Object.entries(jwk).filter(([key]) => !privateFields.has(key))) as JWK;
}

export type AccessTokenClaims = Pick<
  SchemaAccessTokenClaims,
  "sub" | "client_id" | "scope" | "jti" | "iat" | "exp" | "iss"
> &
  Pick<SchemaAccessTokenClaims, "permissions"> &
  Partial<Pick<SchemaAccessTokenClaims, "aud">>;

type UserState = { id: string; disabled: boolean; tokensValidAfter: Date | null };
type Account = Awaited<ReturnType<IdentityService["findAccount"]>>;

export async function createKeyService(config: AppConfig, identity: IdentityService) {
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
    },
    preloaded?: { user?: UserState; permissions?: string[] },
  ) {
    const user = preloaded?.user ?? (await identity.findUser(input.userId));
    if (!user || user.disabled) throw new Error("Cannot issue an access token for a missing or disabled user");
    const permissions = [...new DelegatedPermissionSet(
      preloaded?.permissions ?? (await identity.permissionsFor(input.userId)),
    ).permissions];
    const token = new SignJWT({
      client_id: input.clientId,
      scope: input.scopes.join(" "),
      permissions,
    })
      .setProtectedHeader({ alg: "RS256", kid: activeJwk.kid, typ: "at+jwt" })
      .setIssuer(config.issuer)
      .setSubject(input.userId);
    if (input.resource) token.setAudience(input.resource);
    return token
      .setJti(crypto.randomUUID())
      .setIssuedAt()
      .setExpirationTime("10m")
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

  async function verifyAccessToken(token: string, audience?: string) {
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
    const claims = parsed.data as AccessTokenClaims;
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

  return { publicJwks, issueAccessToken, issueIdToken, verifyAccessToken };
}

export type KeyService = Awaited<ReturnType<typeof createKeyService>>;
