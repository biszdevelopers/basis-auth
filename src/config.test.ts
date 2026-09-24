import { describe, expect, it } from "vitest";
import { loadConfig } from "./config.js";

const base = {
  NODE_ENV: "test",
  DATABASE_URL: "postgresql://test:test@localhost/test",
  INTERNAL_API_TOKEN: "a".repeat(32),
  OIDC_ISSUER: "https://auth.example.test/",
  OIDC_COOKIE_KEYS: "a".repeat(32),
  OIDC_RESOURCES_JSON: JSON.stringify([
    { audience: "urn:basis:api:test", scopes: ["records.read"] },
  ]),
  OIDC_CLIENTS_JSON: JSON.stringify([
    {
      clientId: "test-client",
      clientSecret: "a-sufficiently-long-secret",
      redirectUris: ["https://client.example.test/callback"],
      scopes: ["records.read"],
      resources: ["urn:basis:api:test"],
    },
  ]),
};

describe("configuration", () => {
  it("normalizes the issuer and validates client resources", async () => {
    const config = await loadConfig(base);
    expect(config.issuer).toBe("https://auth.example.test");
    expect(config.clients[0]?.clientId).toBe("test-client");
    expect(config.jwks.keys[0]?.d).toBeTypeOf("string");
  });

  it("does not add public OIDC scopes to a client allowlist", async () => {
    const config = await loadConfig({
      ...base,
      OIDC_CLIENTS_JSON: JSON.stringify([
        {
          clientId: "identity-client",
          clientSecret: "a-sufficiently-long-secret",
          redirectUris: ["https://client.example.test/callback"],
          resources: ["urn:basis:api:test"],
        },
      ]),
    });

    expect(config.clients[0]?.scopes).toEqual([]);
  });

  it("accepts descriptive, namespaced permission definitions", async () => {
    const config = await loadConfig({
      ...base,
      OIDC_CLIENTS_JSON: JSON.stringify([{
        clientId: "nethack",
        clientSecret: "a-sufficiently-long-secret",
        redirectUris: ["https://client.example.test/callback"],
        scopes: ["records.read"],
        permissions: { "nethack.Projects.read.all": "View all projects" },
        resources: ["urn:basis:api:test"],
      }]),
    });
    expect(config.clients[0]?.permissions).toEqual({ "nethack.Projects.read.all": "View all projects" });
  });

  it("rejects invalid permission descriptions and scopes absent from the resource", async () => {
    await expect(loadConfig({
      ...base,
      OIDC_CLIENTS_JSON: JSON.stringify([{
        clientId: "nethack",
        clientSecret: "a-sufficiently-long-secret",
        redirectUris: ["https://client.example.test/callback"],
        scopes: ["nethack.access"],
        permissions: { "nethack.Projects.read": "" },
        resources: ["urn:basis:api:test"],
      }]),
    })).rejects.toThrow();
    await expect(loadConfig({
      ...base,
      OIDC_CLIENTS_JSON: JSON.stringify([{
        clientId: "nethack",
        clientSecret: "a-sufficiently-long-secret",
        redirectUris: ["https://client.example.test/callback"],
        scopes: ["nethack.access"],
        resources: ["urn:basis:api:test"],
      }]),
    })).rejects.toThrow("not registered by its resource");
  });

  it("rejects clients referencing an unknown resource", async () => {
    await expect(
      loadConfig({
        ...base,
        OIDC_CLIENTS_JSON: JSON.stringify([
          {
            clientId: "bad-client",
            clientSecret: "a-sufficiently-long-secret",
            redirectUris: ["https://client.example.test/callback"],
            scopes: ["openid"],
            resources: ["urn:basis:api:missing"],
          },
        ]),
      }),
    ).rejects.toThrow("unknown resource");
  });

  it("rejects incomplete Microsoft configuration", async () => {
    await expect(loadConfig({ ...base, MICROSOFT_CLIENT_ID: "client" })).rejects.toThrow(
      "must be set together",
    );
  });

  it("treats blank optional JSON arrays as empty", async () => {
    const config = await loadConfig({
      ...base,
      OIDC_CLIENTS_JSON: "",
      OIDC_RESOURCES_JSON: "",
      BOOTSTRAP_PERMISSION_GRANTS_JSON: "",
    });

    expect(config.clients).toEqual([]);
    expect(config.resources).toEqual([]);
    expect(config.bootstrapPermissionGrants).toEqual([]);
  });

  it("requires a filter mode when a client has filter content", async () => {
    await expect(
      loadConfig({
        ...base,
        OIDC_CLIENTS_JSON: JSON.stringify([
          {
            clientId: "filtered-client",
            clientSecret: "a-sufficiently-long-secret",
            redirectUris: ["https://client.example.test/callback"],
            scopes: ["openid"],
            resources: ["urn:basis:api:test"],
            filterContent: ["student@example.test"],
          },
        ]),
      }),
    ).rejects.toThrow("requires filterMode");
  });

  it("rejects placeholder cookie-signing keys", async () => {
    await expect(
      loadConfig({ ...base, OIDC_COOKIE_KEYS: "changeme-changeme-changeme-changeme" }),
    ).rejects.toThrow("must be replaced with real randomly generated values");
  });

  it("rejects development mode with a non-localhost issuer", async () => {
    await expect(
      loadConfig({ ...base, NODE_ENV: "development", OIDC_ISSUER: "https://auth.example.test" }),
    ).rejects.toThrow("NODE_ENV=production");
  });

  it("allows development mode with a localhost issuer", async () => {
    const config = await loadConfig({
      ...base,
      NODE_ENV: "development",
      OIDC_ISSUER: "http://localhost:3000",
    });
    expect(config.issuer).toBe("http://localhost:3000");
    expect(config.clients).toContainEqual(expect.objectContaining({
      clientId: "basis-auth-dev-demo",
      public: true,
      redirectUris: ["http://localhost:3000/dev/demo/callback"],
    }));
    expect(config.resources).toContainEqual({
      audience: "http://localhost:3000/dev/demo",
      scopes: [],
    });
  });
});
