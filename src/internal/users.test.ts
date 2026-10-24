import { describe, expect, it } from "vitest";
import { internalUserInternals, InternalUserError } from "./users.js";

describe("management user patch contract", () => {
  it("accepts a profile and application grant update together", () => {
    expect(internalUserInternals.parseManagementPatch({
      displayName: "Portal user",
      disabled: false,
      applications: [{
        applicationId: "portal",
        catalogVersion: 3,
        grants: ["BiszPortal.Users.read"],
      }],
    })).toEqual({
      patch: { displayName: "Portal user", disabled: false },
      applications: [{
        applicationId: "portal",
        catalogVersion: 3,
        grants: ["BiszPortal.Users.read"],
      }],
    });
  });

  it("rejects case-insensitive duplicate grant clauses", () => {
    expect(() => internalUserInternals.parseManagementPatch({
      applications: [{
        applicationId: "portal",
        catalogVersion: 3,
        grants: ["BiszPortal.Users.read", "biszportal.users.READ"],
      }],
    })).toThrowError(InternalUserError);
  });

  it("requires a catalog version and application list", () => {
    expect(() => internalUserInternals.parseManagementPatch({ displayName: "User" }))
      .toThrow("applications must be an array");
    expect(() => internalUserInternals.parseManagementPatch({
      applications: [{ applicationId: "portal", grants: [] }],
    })).toThrow("catalogVersion");
  });
});
