import type { MiddlewareHandler } from "hono";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

export interface BasisAccessToken extends JWTPayload {
  sub: string;
  client_id: string;
  scope: string;
  permissions: string[];
  jti: string;
  iat: number;
}

export interface TokenSubjectState {
  disabled: boolean;
  tokensValidAfter: Date | null;
}

export type AuthVariables = {
  basisToken: BasisAccessToken;
};

export function basisAuth(options: {
  issuer: string;
  audience: string;
  loadTokenSubject?: (subject: string) => Promise<TokenSubjectState | undefined>;
}): MiddlewareHandler<{
  Variables: AuthVariables;
}> {
  const issuer = options.issuer.replace(/\/$/, "");
  const jwks = createRemoteJWKSet(new URL(`${issuer}/oauth/jwks`));

  return async (c, next) => {
    const authorization = c.req.header("authorization");
    try {
      const token = authorization?.match(/^Bearer ([^\s]+)$/i)?.[1];
      if (!token) throw new Error("Missing bearer access token");
      const { payload } = await jwtVerify(token, jwks, {
        algorithms: ["RS256"],
        issuer,
        audience: options.audience,
        typ: "at+jwt",
        requiredClaims: ["exp"],
      });
      if (
        !payload.sub ||
        typeof payload.client_id !== "string" ||
        typeof payload.scope !== "string" ||
        !Array.isArray(payload.permissions) ||
        !payload.permissions.every((permission) => typeof permission === "string") ||
        typeof payload.jti !== "string" ||
        typeof payload.iat !== "number"
      ) {
        throw new Error("Required access-token claims are missing");
      }
      if (options.loadTokenSubject) {
        const subject = await options.loadTokenSubject(payload.sub);
        if (
          !subject ||
          subject.disabled ||
          (subject.tokensValidAfter && payload.iat * 1000 <= subject.tokensValidAfter.getTime())
        ) {
          throw new Error("Access token subject is unavailable or revoked");
        }
      }
      c.set("basisToken", payload as BasisAccessToken);
    } catch {
      return c.json({ error: "invalid_token", error_description: "Invalid access token" }, 401, {
        "WWW-Authenticate": 'Bearer error="invalid_token"',
      });
    }
    await next();
  };
}

export function requireScopes(...required: string[]): MiddlewareHandler<{
  Variables: AuthVariables;
}> {
  return async (c, next) => {
    const granted = new Set((c.get("basisToken").scope ?? "").split(" ").filter(Boolean));
    if (!required.every((scope) => granted.has(scope))) {
      return c.json({ error: "insufficient_scope" }, 403, {
        "WWW-Authenticate": `Bearer error="insufficient_scope", scope="${required.join(" ")}"`,
      });
    }
    await next();
  };
}

export function requirePermissions(...required: string[]): MiddlewareHandler<{
  Variables: AuthVariables;
}> {
  return async (c, next) => {
    const granted = new Set(c.get("basisToken").permissions ?? []);
    if (!required.every((permission) => granted.has(permission))) {
      return c.json({ error: "insufficient_permissions" }, 403);
    }
    await next();
  };
}
