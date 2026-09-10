import { describe, expect, it, vi } from "vitest";
import { createInternalApp } from "./app.js";
import type { InternalUserService } from "./users.js";

const token = "i".repeat(32);
const user = {
  id: "d2c3f635-527c-4c0a-bc1c-15d6af3f0946",
  provider: "microsoft",
  email: "person@example.test",
  emailVerified: true,
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
