import { describe, expect, it, vi } from "vitest";
import type { Database } from "../database/client.js";
import { createInternalApplicationService } from "./applications.js";

const actor = { id: "d2c3f635-527c-4c0a-bc1c-15d6af3f0946", permissions: [] };
const settings = {
  name: "Test app",
  requireConsent: true,
  filterMode: null,
  filterContent: [],
  organizationIds: ["cbc6e1e2-a6bb-4002-bbdc-6da892a051a7"],
};

describe("internal application authorization", () => {
  const service = createInternalApplicationService({} as Database, "https://issuer.example", vi.fn());

  it.each([
    ["create", () => service.createApplication(actor, { ...settings, public: true, redirectUris: ["https://example.test/callback"] })],
    ["update", () => service.updateApplication("client", actor, settings)],
    ["delete", () => service.deleteApplication("client", actor)],
    ["rotate credentials", () => service.rotateSecret("client", actor)],
    ["remove credentials", () => service.removeSecret("client", actor)],
  ])("rejects %s before accessing storage when the delegated permission is absent", async (_name, operation) => {
    await expect(operation()).rejects.toMatchObject({ status: 403, code: "forbidden" });
  });
});
