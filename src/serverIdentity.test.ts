import { describe, expect, it } from "vitest";
import { databaseIdentity, serverIdentity } from "./serverIdentity.js";

describe("databaseIdentity", () => {
  it("reports host, port, and database without credentials or query parameters", () => {
    expect(databaseIdentity(
      "postgresql://basis_user:super-secret@db.example.test:6543/basis_auth?sslmode=require",
    )).toEqual({
      host: "db.example.test",
      port: 6543,
      database: "basis_auth",
    });
  });

  it("defaults the port and decodes the database name", () => {
    expect(databaseIdentity("postgresql://db.example.test/basis%20auth")).toEqual({
      host: "db.example.test",
      port: 5432,
      database: "basis auth",
    });
  });

  it("returns null without a URL or with a malformed URL", () => {
    expect(databaseIdentity(undefined)).toBeNull();
    expect(databaseIdentity("not a connection string")).toBeNull();
  });
});

describe("serverIdentity", () => {
  it("reports a parseable start time, package version, and environment", () => {
    const identity = serverIdentity("test", "postgresql://user:secret@localhost:5432/basis_auth");

    expect(Number.isNaN(Date.parse(identity.startedAt))).toBe(false);
    expect(identity.version).toMatch(/^\d+\.\d+\.\d+/);
    expect(identity.environment).toBe("test");
    expect(identity.pid).toBe(process.pid);
    expect(identity.database).toEqual({ host: "localhost", port: 5432, database: "basis_auth" });
    expect(JSON.stringify(identity)).not.toContain("secret");
  });
});
