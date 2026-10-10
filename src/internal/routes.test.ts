import { describe, expect, it, vi } from "vitest";
import { createInternalApp } from "./app.js";
import type { InternalUserService } from "./users.js";
import type { InternalApplicationService } from "./applications.js";
import type { KeyService } from "../oauth/keys.js";

const token = "i".repeat(32);
const user = {
  id: "d2c3f635-527c-4c0a-bc1c-15d6af3f0946",
  provider: "microsoft",
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
  return createInternalApp(token, service);
}

function managementApp(applications: InternalApplicationService, verifyAccessToken = vi.fn()) {
  return createInternalApp(token, {} as InternalUserService, {
    applications,
    keys: { verifyAccessToken } as unknown as KeyService,
    clientId: "portal-client",
    audience: "devconnect://noesis",
    scope: "noesis.access",
  });
}

describe("internal user HTTP API", () => {
  it("rejects requests without the internal service token", async () => {
    const service = { findUser: vi.fn() } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`);
    expect(response.status).toBe(401);
    expect(service.findUser).not.toHaveBeenCalled();
  });

  it("returns user state to an authenticated service", async () => {
    const service = { findUser: vi.fn().mockResolvedValue(user) } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`, {
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({ user: { id: user.id, hasPicture: true } });
  });

  it("delegates PATCH mutation to the auth-owned service", async () => {
    const patchUser = vi.fn().mockResolvedValue({ ...user, disabled: true });
    const service = { patchUser } as unknown as InternalUserService;
    const response = await internalApp(service).request(`/internal/users/${user.id}`, {
      method: "PATCH",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ disabled: true }),
    });
    expect(response.status).toBe(200);
    expect(patchUser).toHaveBeenCalledWith(user.id, { disabled: true });
    expect(await response.json()).toMatchObject({ user: { disabled: true } });
  });
});

describe("internal application HTTP API", () => {
  it("requires a signed portal actor token in addition to the service token", async () => {
    const applications = { list: vi.fn() } as unknown as InternalApplicationService;
    const response = await managementApp(applications).request("/internal/applications", {
      headers: { authorization: `Bearer ${token}` },
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
      permissions: ["BiszPortal.Applications.read"],
      gty: "authorization_code",
    });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      headers: { authorization: `Bearer ${token}`, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(200);
    expect(verify).toHaveBeenCalledWith("actor", "devconnect://noesis");
    expect(applications.list).toHaveBeenCalledWith({ id: user.id, permissions: ["BiszPortal.Applications.read"] });
  });

  it.each([
    { client_id: "different-client", scope: "noesis.access", gty: "authorization_code" },
    { client_id: "portal-client", scope: "openid", gty: "authorization_code" },
    { client_id: "portal-client", scope: "noesis.access", gty: "client_credentials" },
  ])("rejects actor tokens outside the portal contract: %o", async (claims) => {
    const applications = { list: vi.fn() } as unknown as InternalApplicationService;
    const verify = vi.fn().mockResolvedValue({ sub: user.id, permissions: [], ...claims });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      headers: { authorization: `Bearer ${token}`, "x-basis-actor-token": "Bearer actor" },
    });
    expect(response.status).toBe(403);
    expect(applications.list).not.toHaveBeenCalled();
  });

  it("validates organization-aware application creation", async () => {
    const createApplication = vi.fn().mockResolvedValue({ clientId: "new-client", clientSecret: null });
    const detail = vi.fn().mockResolvedValue({ clientId: "new-client" });
    const applications = { createApplication, detail } as unknown as InternalApplicationService;
    const permissions = ["BiszPortal.Applications.create", "BiszPortal.Applications.read"];
    const verify = vi.fn().mockResolvedValue({ sub: user.id, client_id: "portal-client", scope: "noesis.access", permissions, gty: "authorization_code" });
    const response = await managementApp(applications, verify).request("/internal/applications", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "x-basis-actor-token": "Bearer actor", "content-type": "application/json" },
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
      headers: { authorization: `Bearer ${token}` },
    });
    expect(response.status).toBe(403);
    expect(deleteApplication).not.toHaveBeenCalled();
  });
});
