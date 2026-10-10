import { timingSafeEqual } from "node:crypto";
import { Hono, type Context } from "hono";
import { secureHeaders } from "hono/secure-headers";
import { z } from "zod";
import type { KeyService } from "../oauth/keys.js";
import {
  InternalApplicationError,
  type ApplicationActor,
  type InternalApplicationService,
} from "./applications.js";
import { InternalUserError, type InternalUserService } from "./users.js";

type ManagementOptions = {
  applications: InternalApplicationService;
  keys: KeyService;
  clientId: string;
  audience: string;
  scope: string;
};

export function createInternalApp(token: string, users: InternalUserService, management?: ManagementOptions) {
  const app = new Hono();
  app.use("*", secureHeaders());
  app.use("*", async (c, next) => {
    const supplied = c.req.header("authorization")?.match(/^Bearer ([^\s]+)$/)?.[1];
    if (!supplied) return c.json({ error: "unauthorized" }, 401);
    const suppliedBytes = Buffer.from(supplied);
    const expectedBytes = Buffer.from(token);
    if (suppliedBytes.length !== expectedBytes.length || !timingSafeEqual(suppliedBytes, expectedBytes)) {
      return c.json({ error: "unauthorized" }, 401);
    }
    c.header("Cache-Control", "no-store");
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

  async function actor(c: Context): Promise<ApplicationActor> {
    if (!management) throw new InternalApplicationError(404, "not_found", "Application management is unavailable");
    const value = c.req.header("x-basis-actor-token")?.match(/^Bearer ([^\s]+)$/)?.[1];
    if (!value) throw new InternalApplicationError(403, "forbidden", "Actor token is required");
    try {
      const claims = await management.keys.verifyAccessToken(value, management.audience);
      const scopes = new Set(claims.scope.split(/\s+/).filter(Boolean));
      if (claims.gty === "client_credentials" || claims.client_id !== management.clientId || !scopes.has(management.scope)) {
        throw new Error("actor token is not a portal user token");
      }
      return { id: claims.sub, permissions: claims.permissions };
    } catch {
      throw new InternalApplicationError(403, "forbidden", "Actor token is invalid");
    }
  }

  async function managed(c: Context, operation: (actor: ApplicationActor) => Promise<unknown>) {
    try {
      return c.json(await operation(await actor(c)) as never);
    } catch (error) {
      if (error instanceof InternalApplicationError) return c.json({ error: error.code, message: error.message }, error.status);
      if (error instanceof z.ZodError) return c.json({ error: "invalid_request", message: error.issues[0]?.message ?? "Invalid request" }, 400);
      if (error instanceof SyntaxError) return c.json({ error: "invalid_request", message: "Request body is not valid JSON" }, 400);
      throw error;
    }
  }

  if (management) {
    const roleSchema = z.enum(["role.ADMIN", "role.GENERAL"]);
    const resourceSchema = z.object({ resourceId: z.string().min(1), name: z.string().trim().min(1), availableScopes: z.array(z.string().min(1)).default([]) });
    const settingsSchema = z.object({
      name: z.string().trim().min(1).max(120),
      requireConsent: z.boolean(),
      filterMode: z.enum(["whitelist", "blacklist"]).nullable(),
      filterContent: z.array(z.string().trim().min(1)),
      organizationIds: z.array(z.uuid()).min(1).refine((values) => new Set(values).size === values.length, "Organization IDs must be unique"),
    });
    const permissionSchema = z.object({ permission: z.string().trim().min(1), description: z.string().trim().min(1) });

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
    app.put("/internal/applications/:clientId/redirect-uris", async (c) => managed(c, async (who) => {
      const body = z.object({ redirectUris: z.array(z.string().min(1)).min(1) }).parse(await c.req.json());
      await management.applications.updateRedirectUris(c.req.param("clientId"), who, body.redirectUris);
      return { application: await management.applications.detail(c.req.param("clientId"), who) };
    }));
  }

  return app;
}
