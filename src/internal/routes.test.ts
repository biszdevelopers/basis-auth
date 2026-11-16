import { describe, expect, it, vi } from "vitest";
import { createInternalApp } from "./app.js";
import type { InternalUserService } from "./users.js";
import type { InternalApplicationService } from "./applications.js";
import type { KeyService } from "../oauth/keys.js";
import type { OAuthService } from "../oauth/service.js";

const token = "i".repeat(32);
const portalAudience = "devconnect://noesis";
const serviceAudience = "urn:basis:api:projects";
const portalCredentials = { authorization: `Bearer ${token}`, "x-basis-resource": encodeURIComponent(portalAudience) };
const serviceCredentials = { authorization: `Bearer ${token}`, "x-basis-resource": encodeURIComponent(serviceAudience) };
const authentication = {
  verifyResource: async (audience: string, secret: string) =>
    [portalAudience, serviceAudience].includes(audience) && secret === token,
  userWriteResources: [serviceAudience],
};
const user = {
  id: "d2c3f635-527c-4c0a-bc1c-15d6af3f0946",
  provider: "microsoft",
  upstreamIssuer: "https://login.microsoftonline.com/test/v2.0",
  upstreamSubject: "microsoft-subject",
  email: "person@example.test",
  studentId: null,
  schoolDistrict: null,
  disabled: false,
  displayName: "Person",
  tokensValidAfter: null,
  createdAt: new Date("2025-01-01T00:00:00Z"),
  updatedAt: new Date("2025-01-01T00:00:00Z"),
  hasPicture: true,
};

function internalApp(service: InternalUserService) {
  return createInternalApp(authentication, service);
}

function managementApp(
  applications: InternalApplicationService,
  verifyAccessToken = vi.fn(),
  users = {} as InternalUserService,
  sessions?: Pick<OAuthService, "listAuthorizationSessions" | "endAuthorizationSession">,
) {
  return createInternalApp(authentication, users, {
    applications,
    keys: { verifyAccessToken } as unknown as KeyService,
    clientId: "portal-client",
    audience: portalAudience,
    scope: "noesis.access",
    sessions,
  });
}

it("allows actors to manage their own sessions and requires delegated permissions for other users", async () => {
  const otherUserId = "2caa198c-0d46-49ba-a456-505978796f0d";
  const sessionId = "f7cd643f-ea84-482e-9317-1e0b00ad32c1";
  const session = { id: sessionId, createdAt: new Date(), expiresAt: new Date(), resource: portalAudience, current: true };
  const listAuthorizationSessions = vi.fn().mockResolvedValue([session]);
  const endAuthorizationSession = vi.fn().mockResolvedValue({ currentSessionEnded: true });
  const claims = { sub: user.id, jti: "actor-jti", client_id: "portal-client", scope: "noesis.access", permissions: [] };
  const verify = vi.fn().mockResolvedValue(claims);
  const app = managementApp({} as InternalApplicationService, verify, undefined, {
    listAuthorizationSessions, endAuthorizationSession,
  });
  const path = (id: string) => `/internal/management/users/${id}/sessions`;
  const headers = { ...portalCredentials, "x-basis-actor-token": "Bearer actor" };

  const list = await app.request(path(user.id), { headers });
  expect(list.status).toBe(200);
  expect(await list.json()).toEqual({ sessions: [{ ...session, createdAt: session.createdAt.toISOString(), expiresAt: session.expiresAt.toISOString() }] });
  expect(listAuthorizationSessions).toHaveBeenCalledWith(user.id, claims.jti);

  expect((await app.request(path(otherUserId), { headers })).status).toBe(403);
  expect((await app.request(`${path(otherUserId)}/${sessionId}`, { method: "DELETE", headers })).status).toBe(403);
  expect(endAuthorizationSession).not.toHaveBeenCalled();

  const ended = await app.request(`${path(user.id)}/${sessionId}`, { method: "DELETE", headers });
  expect(ended.status).toBe(200);
  expect(await ended.json()).toEqual({ currentSessionEnded: true });
  expect(endAuthorizationSession).toHaveBeenCalledWith(user.id, sessionId, claims.jti);

  verify.mockResolvedValue({ ...claims, permissions: ["BiszPortal.Users.update"] });
  endAuthorizationSession.mockResolvedValue(null);
  expect((await app.request(`${path(otherUserId)}/${sessionId}`, { method: "DELETE", headers })).status).toBe(404);
  expect(endAuthorizationSession).toHaveBeenLastCalledWith(otherUserId, sessionId, claims.jti);
});

describe("internal user HTTP API", () => {
  it("rejects requests without the internal service token", async () => {
    const service = { findUser: vi.fn() } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(401);
    expect(service.findUser).not.toHaveBeenCalled();
  });

  it("returns user state to an authenticated service", async () => {
    const service = { findUser: vi.fn().mockResolvedValue(user) } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`, {
      headers: serviceCredentials,
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      user: {
        id: user.id,
        upstreamIssuer: user.upstreamIssuer,
        upstreamSubject: user.upstreamSubject,
        hasPicture: true,
      },
    });
  });

  it("delegates PATCH mutation to the auth-owned service", async () => {
    const patchUser = vi.fn().mockResolvedValue({ ...user, disabled: true });
    const service = { patchUser } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`, {
      method: "PATCH",
      headers: { ...serviceCredentials, "content-type": "application/json" },
      body: JSON.stringify({ disabled: true }),
    });
    expect(response.status).toBe(200);
    expect(patchUser).toHaveBeenCalledWith(user.id, { disabled: true });
    expect(await response.json()).toMatchObject({ user: { disabled: true } });
  });

  it("requires explicitly trusted resource credentials for service-only user writes", async () => {
    const patchUser = vi.fn();
    const response = await internalApp({ patchUser } as unknown as InternalUserService).request(`/internal/users/${user.id}`, {
      method: "PATCH",
      headers: portalCredentials,
    });
    expect(response.status).toBe(403);
    expect(patchUser).not.toHaveBeenCalled();
  });

  it("returns a permission-protected paged user list", async () => {
    const listUsers = vi.fn().mockResolvedValue({
      users: [user],
      pagination: { page: 2, pageSize: 10, total: 11, totalPages: 2 },
    });
    const verify = vi.fn().mockResolvedValue({
      sub: user.id,
      client_id: "portal-client",
      scope: "noesis.access",
      permissions: ["BiszPortal.Users.read"],
      gty: "authorization_code",
    });
    const response = await managementApp(
      {} as InternalApplicationService,
      verify,
      { listUsers } as unknown as InternalUserService,
    ).request("/internal/users?page=2&pageSize=10", {
      headers: { ...portalCredentials, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(200);
    expect(listUsers).toHaveBeenCalledWith({ page: 2, pageSize: 10 });
    expect(await response.json()).toMatchObject({ pagination: { total: 11 } });
  });

  it("rejects user listing without the delegated read permission", async () => {
    const listUsers = vi.fn();
    const verify = vi.fn().mockResolvedValue({
      sub: user.id,
      client_id: "portal-client",
      scope: "noesis.access",
      permissions: [],
      gty: "authorization_code",
    });
    const response = await managementApp(
      {} as InternalApplicationService,
      verify,
      { listUsers } as unknown as InternalUserService,
    ).request("/internal/users", {
      headers: { ...portalCredentials, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(403);
    expect(listUsers).not.toHaveBeenCalled();
  });
});

describe("internal application HTTP API", () => {
  it("requires a signed portal actor token in addition to the service token", async () => {
    const applications = { list: vi.fn() } as unknown as InternalApplicationService;
    const response = await managementApp(applications).request("/internal/applications", {
      headers: portalCredentials,
    });
    expect(response.status).toBe(403);
    expect(applications.list).not.toHaveBeenCalled();
  });

  it("passes validated actor claims to the application service", async () => {
    const applications = {
      list: vi.fn().mockResolvedValue([{ clientId: "client", name: "Client" }]),
      listOrganizations: vi.fn().mockResolvedValue([]),
    } as unknown as InternalApplicationService;
    const verify = vi.fn().mockResolvedValue({
      sub: user.id,
      client_id: "portal-client",
      scope: "openid noesis.access",
      permissions: ["BiszPortal.Applications.read.me"],
      gty: "authorization_code",
    });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      headers: { ...portalCredentials, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(200);
    expect(verify).toHaveBeenCalledWith("actor", "devconnect://noesis");
    expect(applications.list).toHaveBeenCalledWith({ id: user.id, permissions: ["BiszPortal.Applications.read.me"] });
  });

  it.each([
    { client_id: "different-client", scope: "noesis.access", gty: "authorization_code" },
    { client_id: "portal-client", scope: "openid", gty: "authorization_code" },
    { client_id: "portal-client", scope: "noesis.access", gty: "client_credentials" },
  ])("rejects actor tokens outside the portal contract: %o", async (claims) => {
    const applications = { list: vi.fn() } as unknown as InternalApplicationService;
    const verify = vi.fn().mockResolvedValue({ sub: user.id, permissions: [], ...claims });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      headers: { ...portalCredentials, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(403);
    expect(applications.list).not.toHaveBeenCalled();
  });

  it("validates organization-aware application creation", async () => {
    const createApplication = vi.fn().mockResolvedValue({ clientId: "new-client", clientSecret: null });
    const detail = vi.fn().mockResolvedValue({ clientId: "new-client" });
    const applications = { createApplication, detail } as unknown as InternalApplicationService;
    const permissions = ["BiszPortal.Applications.create", "BiszPortal.Applications.read.me"];
    const verify = vi.fn().mockResolvedValue({ sub: user.id, client_id: "portal-client", scope: "noesis.access", permissions, gty: "authorization_code" });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      method: "POST",
      headers: { ...portalCredentials, "x-basis-actor-token": "Bearer actor", "content-type": "application/json" },
      body: JSON.stringify({
        name: "New app",
        public: true,
        redirectUris: ["https://example.test/callback"],
        requireConsent: true,
        filterMode: null,
        filterContent: [],
        organizationIds: ["cbc6e1e2-a6bb-4002-bbdc-6da892a051a7"],
      }),
    });
    expect(response.status).toBe(200);
    expect(createApplication).toHaveBeenCalledWith({ id: user.id, permissions }, expect.objectContaining({ name: "New app", public: true }));
  });

  it("does not run destructive operations without an actor token", async () => {
    const deleteApplication = vi.fn();
    const applications = { deleteApplication } as unknown as InternalApplicationService;
    const response = await managementApp(applications).request("/internal/applications/client", {
      method: "DELETE",
      headers: portalCredentials,
    });
    expect(response.status).toBe(403);
    expect(deleteApplication).not.toHaveBeenCalled();
  });

  it("replaces default grant permissions and returns refreshed application details", async () => {
    const updateDefaultPermissions = vi.fn().mockResolvedValue(undefined);
    const detail = vi.fn().mockResolvedValue({
      clientId: "client",
      defaultPermissions: ["Example.read"],
    });
    const applications = {
      updateDefaultPermissions,
      detail,
    } as unknown as InternalApplicationService;
    const permissions = ["BiszPortal.ApplicationPermissions.manage"];
    const verify = vi.fn().mockResolvedValue({
      sub: user.id,
      client_id: "portal-client",
      scope: "noesis.access",
      permissions,
      gty: "authorization_code",
    });
    const response = await managementApp(applications, verify).request(
      "/internal/applications/client/default-permissions",
      {
        method: "PUT",
        headers: {
          ...portalCredentials,
          "x-basis-actor-token": "Bearer actor",
          "content-type": "application/json",
        },
        body: JSON.stringify({ permissions: ["Example.read"] }),
      },
    );

    expect(response.status).toBe(200);
    expect(updateDefaultPermissions).toHaveBeenCalledWith(
      "client",
      { id: user.id, permissions },
      ["Example.read"],
    );
    expect(detail).toHaveBeenCalledWith("client", { id: user.id, permissions });
    expect(await response.json()).toMatchObject({
      application: { defaultPermissions: ["Example.read"] },
    });
  });

  it("rejects duplicate default grant permissions before calling the service", async () => {
    const updateDefaultPermissions = vi.fn();
    const applications = { updateDefaultPermissions } as unknown as InternalApplicationService;
    const verify = vi.fn().mockResolvedValue({
      sub: user.id,
      client_id: "portal-client",
      scope: "noesis.access",
      permissions: ["BiszPortal.ApplicationPermissions.manage"],
      gty: "authorization_code",
    });
    const response = await managementApp(applications, verify).request(
      "/internal/applications/client/default-permissions",
      {
        method: "PUT",
        headers: {
          ...portalCredentials,
          "x-basis-actor-token": "Bearer actor",
          "content-type": "application/json",
        },
        body: JSON.stringify({ permissions: ["Example.read", "Example.read"] }),
      },
    );

    expect(response.status).toBe(400);
    expect(updateDefaultPermissions).not.toHaveBeenCalled();
  });
});

describe("internal resource HTTP API", () => {
  const permissions = ["BiszPortal.Resources.all"];
  const resourceId = "https://projects.example.test/api/a%2Fb";
  const path = `/internal/resources/${encodeURIComponent(resourceId)}/backchannel/logout`;
  const headers = {
    ...portalCredentials,
    "x-basis-actor-token": "Bearer actor",
    "content-type": "application/json",
  };

  it("reads, saves, and clears multiple webhooks using an encoded resource audience", async () => {
    const backchannelLogoutUris = [
      "https://projects.example.test/logout",
      "https://projects.example.test/backup-logout",
    ];
    const resourceDetail = vi.fn().mockResolvedValue({ backchannelLogoutUris: [] });
    const setResourceLogoutUris = vi.fn()
      .mockResolvedValueOnce({ backchannelLogoutUris })
      .mockResolvedValueOnce({ backchannelLogoutUris: [] });
    const app = managementApp(
      { resourceDetail, setResourceLogoutUris } as unknown as InternalApplicationService,
      vi.fn().mockResolvedValue({ sub: user.id, client_id: "portal-client", scope: "noesis.access", permissions }),
    );

    const get = await app.request(path, { headers });
    const put = await app.request(path, { method: "PUT", headers, body: JSON.stringify({ backchannelLogoutUris }) });
    const remove = await app.request(path, { method: "DELETE", headers });

    expect(get.status).toBe(200);
    expect(await get.json()).toEqual({ backchannelLogoutUris: [], backchannelLogoutUri: null });
    expect(put.status).toBe(200);
    expect(await put.json()).toEqual({
      backchannelLogoutUris,
      backchannelLogoutUri: backchannelLogoutUris[0],
    });
    expect(remove.status).toBe(200);
    expect(await remove.json()).toEqual({ backchannelLogoutUris: [], backchannelLogoutUri: null });
    expect(resourceDetail).toHaveBeenCalledWith(resourceId, { id: user.id, permissions });
    expect(setResourceLogoutUris.mock.calls).toEqual([
      [resourceId, { id: user.id, permissions }, backchannelLogoutUris],
      [resourceId, { id: user.id, permissions }, []],
    ]);
  });

  it("requires the portal resource credential before verifying a management actor", async () => {
    const verify = vi.fn();
    const response = await managementApp({} as InternalApplicationService, verify).request("/internal/resources", {
      headers: { ...serviceCredentials, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(403);
    expect(verify).not.toHaveBeenCalled();
  });

  it("returns the issued resource secret from rotation and never uses a caller-supplied value", async () => {
    const resourceSecret = "sk-" + "s".repeat(32);
    const rotateResourceSecret = vi.fn().mockResolvedValue({ resourceSecret });
    const app = managementApp(
      { rotateResourceSecret } as unknown as InternalApplicationService,
      vi.fn().mockResolvedValue({ sub: user.id, client_id: "portal-client", scope: "noesis.access", permissions }),
    );
    const secretPath = `/internal/resources/${encodeURIComponent(resourceId)}/secret/rotate`;
    const updated = await app.request(secretPath, {
      method: "POST", headers, body: JSON.stringify({ secret: "caller-chosen" }),
    });
    expect(updated.status).toBe(200);
    expect(updated.headers.get("cache-control")).toBe("no-store");
    expect(await updated.json()).toEqual({ resourceSecret });
    expect(rotateResourceSecret).toHaveBeenCalledExactlyOnceWith(resourceId, { id: user.id, permissions });
  });

  it.each(["http://projects.example.test/logout", "https://a:b@projects.example.test/logout", "https://projects.example.test/logout#x"])(
    "rejects an unsupported callback %s before updating storage",
    async (backchannelLogoutUri) => {
      const setResourceLogoutUris = vi.fn();
      const app = managementApp(
        { setResourceLogoutUris } as unknown as InternalApplicationService,
        vi.fn().mockResolvedValue({ sub: user.id, client_id: "portal-client", scope: "noesis.access", permissions }),
      );
      const response = await app.request(path, { method: "PUT", headers, body: JSON.stringify({ backchannelLogoutUri }) });
      expect(response.status).toBe(400);
      expect(setResourceLogoutUris).not.toHaveBeenCalled();
    },
  );
});
