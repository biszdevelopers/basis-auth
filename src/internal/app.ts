import { DelegatedPermissionSet, type Permission } from "@basis/schema/permissions";
import { Hono, type Context } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { z } from "zod";
import { backchannelLogoutUriSchema } from "../config.js";
import type { KeyService } from "../oauth/keys.js";
import type { createLogoutService } from "../oauth/logout.js";
import type { OAuthService } from "../oauth/service.js";
import {
  InternalApplicationError,
  type ApplicationActor,
  type InternalApplicationService,
} from "./applications.js";
import { InternalUserError, internalUserInternals, type InternalUserService } from "./users.js";

type ManagementOptions = {
  applications: InternalApplicationService;
  keys: KeyService;
  clientId: string;
  audience: string;
  scope: string;
  sessions?: Pick<OAuthService, "listAuthorizationSessions" | "endAuthorizationSession">;
};

type InternalEnvironment = { Variables: { resourceAudience: string; resourceSecret: string } };
type ResourceAuthentication = {
  verifyResource: (audience: string, secret: string) => Promise<boolean>;
  userWriteResources?: readonly string[];
};

function decodeResourceAudience(value: string | undefined) {
  try {
    return value ? decodeURIComponent(value) : undefined;
  } catch {
    return undefined;
  }
}

export function createInternalApp(
  authentication: ResourceAuthentication,
  users: InternalUserService,
  management?: ManagementOptions,
  executeLogout?: ReturnType<typeof createLogoutService>,
) {
  const app = new Hono<InternalEnvironment>();
  const userWriteResources = new Set(authentication.userWriteResources);
  app.use("*", secureHeaders());
  app.use("*", async (c, next) => {
    c.header("Cache-Control", "no-store");
    const secret = c.req.header("authorization")?.match(/^Bearer ([!-~]{1,256})$/i)?.[1];
    const audience = decodeResourceAudience(c.req.header("x-basis-resource"));
    if (!secret || !audience || !(await authentication.verifyResource(audience, secret))) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.set("resourceAudience", audience);
    c.set("resourceSecret", secret);
    await next();
  });

  app.get("/internal/users/:userId", async (c) => {
    try {
      const user = await users.findUser(c.req.param("userId"));
      return user ? c.json({ user }) : c.json({ error: "user_not_found" }, 404);
    } catch (error) {
      if (error instanceof InternalUserError) {
        return c.json({ error: error.code, message: error.message }, error.status);
      }
      throw error;
    }
  });

  app.get("/internal/users/:userId/picture", async (c) => {
    try {
      const picture = await users.findPicture(c.req.param("userId"));
      if (!picture?.data || !picture.contentType) return c.json({ error: "picture_not_found" }, 404);
      c.header("Content-Type", picture.contentType);
      return c.body(new Uint8Array(picture.data));
    } catch (error) {
      if (error instanceof InternalUserError) {
        return c.json({ error: error.code, message: error.message }, error.status);
      }
      throw error;
    }
  });

  app.patch("/internal/users/:userId", async (c) => {
    if (!userWriteResources.has(c.get("resourceAudience"))) return c.json({ error: "forbidden" }, 403);
    let body: unknown;
    try {
      body = await c.req.json();
    } catch {
      return c.json({ error: "invalid_request", message: "Request body is not valid JSON" }, 400);
    }
    try {
      return c.json({ user: await users.patchUser(c.req.param("userId"), body) });
    } catch (error) {
      if (error instanceof InternalUserError) {
        return c.json({ error: error.code, message: error.message }, error.status);
      }
      throw error;
    }
  });

  if (executeLogout) {
    const logoutRequestSchema = z.object({ audience: z.string().min(1) });
    app.post("/internal/users/:userId/logout", async (c) => {
      const request = logoutRequestSchema.safeParse(await c.req.json<unknown>().catch(() => null));
      if (!request.success) return c.json({ error: "invalid_request", message: "A resource audience is required" }, 400);
      if (request.data.audience !== c.get("resourceAudience")) return c.json({ error: "forbidden" }, 403);
      let user;
      try {
        user = await users.findUser(c.req.param("userId"));
      } catch (error) {
        if (error instanceof InternalUserError) {
          return c.json({ error: error.code, message: error.message }, error.status);
        }
        throw error;
      }
      if (!user) return c.json({ error: "user_not_found" }, 404);
      const result = await executeLogout(user.id, request.data.audience);
      switch (result) {
        case "unknown_resource": return c.json({ error: result }, 404);
        case "logout_not_configured": return c.json({ error: result }, 409);
        case "logout_delivery_failed": return c.json({ error: result }, 502);
        case "delivered": return c.body(null, 204);
      }
    });
  }

  async function actor(c: Context<InternalEnvironment>): Promise<{ actor: ApplicationActor; jti: string }> {
    if (!management) throw new InternalApplicationError(404, "not_found", "Application management is unavailable");
    if (c.get("resourceAudience") !== management.audience) {
      throw new InternalApplicationError(403, "forbidden", "Portal resource credentials are required");
    }
    const value = c.req.header("x-basis-actor-token")?.match(/^Bearer ([^\s]+)$/)?.[1];
    try {
      if (!value) throw new Error("Missing actor token");
      const claims = await management.keys.verifyAccessToken(value, management.audience);
      const scopes = new Set(claims.scope.split(/\s+/).filter(Boolean));
      if (claims.gty === "client_credentials" || claims.client_id !== management.clientId || !scopes.has(management.scope)) {
        throw new Error("actor token is not a portal user token");
      }
      return { actor: { id: claims.sub, permissions: claims.permissions }, jti: claims.jti };
    } catch {
      throw new InternalApplicationError(403, "forbidden", "Invalid access token");
    }
  }

  async function managed(c: Context<InternalEnvironment>, operation: (actor: ApplicationActor, actorJti: string) => Promise<unknown>) {
    try {
      const identity = await actor(c);
      return c.json(await operation(identity.actor, identity.jti) as never);
    } catch (error) {
      if (error instanceof InternalApplicationError) return c.json({ error: error.code, message: error.message }, error.status);
      if (error instanceof InternalUserError) return c.json({ error: error.code, message: error.message }, error.status);
      if (error instanceof z.ZodError) return c.json({ error: "invalid_request", message: error.issues[0]?.message ?? "Invalid request" }, 400);
      if (error instanceof SyntaxError) return c.json({ error: "invalid_request", message: "Request body is not valid JSON" }, 400);
      throw error;
    }
  }

  app.get("/internal/management/users/:userId", (c) => managed(c, async (who) => {
    if (!new DelegatedPermissionSet(who.permissions).has("BiszPortal.Users.read" as Permission)) {
      throw new InternalApplicationError(403, "forbidden", "User details require BiszPortal.Users.read");
    }
    const result = await users.findManagementUser(c.req.param("userId"));
    if (!result) throw new InternalUserError("User not found", 404, "user_not_found");
    return result;
  }));

  app.patch("/internal/management/users/:userId", (c) => managed(c, async (who) => {
    if (!new DelegatedPermissionSet(who.permissions).has("BiszPortal.Users.update" as Permission)) {
      throw new InternalApplicationError(403, "forbidden", "User updates require BiszPortal.Users.update");
    }
    const body = await c.req.json<unknown>();
    if (
      who.id === c.req.param("userId") && body && typeof body === "object" && !Array.isArray(body) &&
      "disabled" in body && body.disabled === true
    ) {
      throw new InternalApplicationError(400, "invalid_request", "You cannot disable your own account");
    }
    return users.patchManagementUser(c.req.param("userId"), body);
  }));

  if (management?.sessions) {
    const sessions = management.sessions;
    const userSessionsPath = "/internal/management/users/:userId/sessions";
    app.get(userSessionsPath, (c) => managed(c, async (who, actorJti) => {
      const userId = z.uuid().parse(c.req.param("userId")).toLowerCase();
      if (who.id !== userId && !new DelegatedPermissionSet(who.permissions).has("BiszPortal.Users.read" as Permission)) {
        throw new InternalApplicationError(403, "forbidden", "Viewing another user's sessions requires BiszPortal.Users.read");
      }
      return { sessions: await sessions.listAuthorizationSessions(userId, actorJti) };
    }));
    app.delete(`${userSessionsPath}/:sessionId`, (c) => managed(c, async (who, actorJti) => {
      const userId = z.uuid().parse(c.req.param("userId")).toLowerCase();
      const sessionId = z.uuid().parse(c.req.param("sessionId"));
      if (who.id !== userId && !new DelegatedPermissionSet(who.permissions).has("BiszPortal.Users.update" as Permission)) {
        throw new InternalApplicationError(403, "forbidden", "Ending another user's session requires BiszPortal.Users.update");
      }
      const result = await sessions.endAuthorizationSession(userId, sessionId, actorJti);
      if (!result) throw new InternalUserError("Active session not found", 404, "session_not_found");
      return result;
    }));
  }

  if (management) {
    const roleSchema = z.enum(["role.ADMIN", "role.GENERAL"]);
    const oauthScope = /^[\x21\x23-\x5b\x5d-\x7e]+$/;
    const upstreamScopeSchema = z.string().trim().regex(oauthScope, "Enter one valid upstream scope").nullable();
    const resourceSchema = z.object({
      resourceId: z.string().min(1),
      name: z.string().trim().min(1),
      availableScopes: z.array(z.string().min(1)).default([]),
      upstreamScopes: z.record(z.string().min(1), upstreamScopeSchema).optional(),
    }).refine(
      ({ availableScopes, upstreamScopes }) =>
        Object.keys(upstreamScopes ?? {}).every((scope) => availableScopes.includes(scope)),
      { path: ["upstreamScopes"], message: "Upstream mappings require a scope in availableScopes" },
    );
    const settingsSchema = z.object({
      name: z.string().trim().min(1).max(120),
      requireConsent: z.boolean(),
      filterMode: z.enum(["whitelist", "blacklist"]).nullable(),
      filterContent: z.array(z.string().trim().min(1)),
      organizationIds: z.array(z.uuid()).min(1).refine((values) => new Set(values).size === values.length, "Organization IDs must be unique"),
    });
    const permissionSchema = z.object({ permission: z.string().trim().min(1), description: z.string().trim().min(1) });
    const resourceScopeChangeSchema = z.discriminatedUnion("action", [
      z.object({
        action: z.literal("add"),
        scope: z.string().trim().regex(oauthScope, "Enter one valid OAuth scope"),
        upstreamScope: upstreamScopeSchema.optional(),
      }),
      z.object({ action: z.literal("update"), scope: z.string().min(1), upstreamScope: upstreamScopeSchema }),
      z.object({ action: z.literal("remove"), scope: z.string().min(1) }),
    ]);
    const logoutUrisSchema = z.object({
      backchannelLogoutUris: z.array(backchannelLogoutUriSchema).optional(),
      backchannelLogoutUri: backchannelLogoutUriSchema.nullable().optional(),
    }).refine(
      (value) => value.backchannelLogoutUris !== undefined || value.backchannelLogoutUri !== undefined,
      "Provide backchannelLogoutUris or backchannelLogoutUri",
    );
    const backchannelValidationSchema = z.object({
      nonce: z.string().regex(/^[A-Za-z0-9_-]{43}$/),
      challenge_hash: z.string().regex(/^[a-f\d]{64}$/i),
    });

    app.post("/internal/backchannel/validate", async (c) => {
      const contentType = c.req.header("content-type") ?? "";
      const body = await (contentType.startsWith("application/x-www-form-urlencoded")
        ? c.req.parseBody()
        : c.req.json<unknown>()).catch(() => null);
      const proof = backchannelValidationSchema.safeParse(body);
      if (!proof.success) return c.json({ error: "invalid_request" }, 400);
      const result = await management.applications.validateBackchannel(
        c.get("resourceAudience"), c.get("resourceSecret"), proof.data.nonce, proof.data.challenge_hash,
      );
      if (result === "timeout") return c.json({ error: "timeout" }, 408);
      if (result !== "verified") return c.json({ error: "invalid_request" }, 400);
      return c.json({ status: "successful" });
    });
    app.get("/internal/resources", (c) => managed(c, async (who) => ({
      resources: await management.applications.listResources(who),
    })));
    app.get("/internal/resources/:resourceId", (c) => managed(c, async (who) => ({
      resource: await management.applications.resourceDetail(c.req.param("resourceId"), who),
    })));
    app.patch("/internal/resources/:resourceId/scopes", (c) => managed(c, async (who) => ({
      resource: await management.applications.updateResourceScope(
        c.req.param("resourceId"), who, resourceScopeChangeSchema.parse(await c.req.json()),
      ),
    })));
    app.post("/internal/resources/:resourceId/secret/rotate", (c) => managed(c, (who) =>
      management.applications.rotateResourceSecret(c.req.param("resourceId"), who),
    ));
    app.get("/internal/resources/:resourceId/backchannel/logout", (c) => managed(c, async (who) => {
      const { backchannelLogoutUris } = await management.applications.resourceDetail(c.req.param("resourceId"), who);
      return { backchannelLogoutUris, backchannelLogoutUri: backchannelLogoutUris[0] ?? null };
    }));
    app.put("/internal/resources/:resourceId/backchannel/logout", (c) => managed(c, async (who) => {
      const body = logoutUrisSchema.parse(await c.req.json());
      const uris = body.backchannelLogoutUris
        ?? (body.backchannelLogoutUri === null ? [] : [body.backchannelLogoutUri!]);
      const result = await management.applications.setResourceLogoutUris(c.req.param("resourceId"), who, uris);
      return { backchannelLogoutUris: result.backchannelLogoutUris, backchannelLogoutUri: result.backchannelLogoutUris[0] ?? null };
    }));
    app.delete("/internal/resources/:resourceId/backchannel/logout", (c) => managed(c, async (who) => {
      const result = await management.applications.setResourceLogoutUris(c.req.param("resourceId"), who, []);
      return { backchannelLogoutUris: result.backchannelLogoutUris, backchannelLogoutUri: result.backchannelLogoutUris[0] ?? null };
    }));
    app.delete("/internal/resources/:resourceId", (c) => managed(c, async (who) => {
      const resourceId = c.req.param("resourceId");
      await management.applications.deleteResource(resourceId, who);
      return { deleted: true, resourceId };
    }));

    app.get("/internal/users", (c) => managed(c, async (who) => {
      if (!new DelegatedPermissionSet(who.permissions).has("BiszPortal.Users.read" as Permission)) {
        throw new InternalApplicationError(403, "forbidden", "User listing requires BiszPortal.Users.read");
      }
      const pagination = internalUserInternals.parsePagination({
        page: c.req.query("page"),
        pageSize: c.req.query("pageSize"),
      });
      return users.listUsers(pagination);
    }));

    app.get("/internal/applications", (c) => managed(c, async (who) => ({
      applications: await management.applications.list(who),
      organizations: await management.applications.listOrganizations(who),
    })));
    app.post("/internal/applications", async (c) => managed(c, async (who) => {
      const body = settingsSchema.extend({ public: z.boolean(), redirectUris: z.array(z.string().min(1)).min(1) }).parse(await c.req.json());
      const created = await management.applications.createApplication(who, body);
      return { application: await management.applications.detail(created.clientId, who), ...(created.clientSecret ? { clientSecret: created.clientSecret } : {}) };
    }));
    app.get("/internal/applications/:clientId", (c) => managed(c, async (who) => ({ application: await management.applications.detail(c.req.param("clientId"), who) })));
    app.patch("/internal/applications/:clientId", async (c) => managed(c, async (who) => {
      await management.applications.updateApplication(c.req.param("clientId"), who, settingsSchema.parse(await c.req.json()));
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.delete("/internal/applications/:clientId", (c) => managed(c, async (who) => {
      await management.applications.deleteApplication(c.req.param("clientId"), who);
      return { deleted: true, clientId: c.req.param("clientId") };
    }));
    app.post("/internal/applications/:clientId/credentials", (c) => managed(c, async (who) => ({ clientSecret: await management.applications.rotateSecret(c.req.param("clientId"), who) })));
    app.delete("/internal/applications/:clientId/credentials", (c) => managed(c, async (who) => {
      await management.applications.removeSecret(c.req.param("clientId"), who);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.post("/internal/applications/:clientId/owners", async (c) => managed(c, async (who) => {
      const body = z.object({ userId: z.uuid(), role: roleSchema }).parse(await c.req.json());
      await management.applications.addOwner(c.req.param("clientId"), who, body.userId, body.role);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.patch("/internal/applications/:clientId/owners/:userId", async (c) => managed(c, async (who) => {
      const body = z.object({ role: roleSchema }).parse(await c.req.json());
      await management.applications.updateOwner(c.req.param("clientId"), who, c.req.param("userId"), body.role);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.delete("/internal/applications/:clientId/owners/:userId", (c) => managed(c, async (who) => {
      await management.applications.removeOwner(c.req.param("clientId"), who, c.req.param("userId"));
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.post("/internal/applications/:clientId/resources/attach", async (c) => managed(c, async (who) => {
      const body = z.object({ resourceId: z.string().min(1) }).parse(await c.req.json());
      await management.applications.attachResource(c.req.param("clientId"), who, body.resourceId);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.post("/internal/applications/:clientId/resources", async (c) => managed(c, async (who) => {
      await management.applications.createResource(c.req.param("clientId"), who, resourceSchema.parse(await c.req.json()));
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.patch("/internal/applications/:clientId/resources", async (c) => managed(c, async (who) => {
      await management.applications.updateResource(c.req.param("clientId"), who, resourceSchema.parse(await c.req.json()));
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.delete("/internal/applications/:clientId/resources", async (c) => managed(c, async (who) => {
      const body = z.object({ resourceId: z.string().min(1), deleteDefinition: z.boolean().default(false) }).parse(await c.req.json());
      await management.applications.removeResource(c.req.param("clientId"), who, body.resourceId, body.deleteDefinition);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.put("/internal/applications/:clientId/scopes", async (c) => managed(c, async (who) => {
      const body = z.object({ resourceScopes: z.record(z.string(), z.array(z.string())) }).parse(await c.req.json());
      await management.applications.updateScopes(c.req.param("clientId"), who, body.resourceScopes);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.post("/internal/applications/:clientId/permissions", async (c) => managed(c, async (who) => {
      const body = permissionSchema.parse(await c.req.json());
      await management.applications.createPermission(c.req.param("clientId"), who, body.permission, body.description);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.patch("/internal/applications/:clientId/permissions", async (c) => managed(c, async (who) => {
      const body = permissionSchema.parse(await c.req.json());
      await management.applications.updatePermission(c.req.param("clientId"), who, body.permission, body.description);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.delete("/internal/applications/:clientId/permissions", async (c) => managed(c, async (who) => {
      const body = z.object({ permission: z.string().trim().min(1) }).parse(await c.req.json());
      await management.applications.deletePermission(c.req.param("clientId"), who, body.permission);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.put("/internal/applications/:clientId/default-permissions", async (c) => managed(c, async (who) => {
      const body = z.object({
        permissions: z.array(z.string().trim().min(1)).refine(
          (permissions) => new Set(permissions).size === permissions.length,
          "Default permissions must be unique",
        ),
      }).parse(await c.req.json());
      await management.applications.updateDefaultPermissions(c.req.param("clientId"), who, body.permissions);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
    app.put("/internal/applications/:clientId/redirect-uris", async (c) => managed(c, async (who) => {
      const body = z.object({ redirectUris: z.array(z.string().min(1)).min(1) }).parse(await c.req.json());
      await management.applications.updateRedirectUris(c.req.param("clientId"), who, body.redirectUris);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
  }

  return app;
}
