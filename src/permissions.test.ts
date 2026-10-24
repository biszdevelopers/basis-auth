import { describe, expect, it } from "vitest";
import { compactPermissionClauses, expandPermissionClauses, prunePermissionClauses } from "./permissions.js";

const definitions = [
  { permission: "BiszPortal.Applications.create", description: "Create applications" },
  { permission: "BiszPortal.Applications.read", description: "Read applications" },
  { permission: "BiszPortal.Applications.update", description: "Update applications" },
  { permission: "BiszPortal.Applications.delete", description: "Delete applications" },
  { permission: "BiszPortal.Applications.Export.csv", description: "Export CSV" },
  { permission: "BiszPortal.Users.read", description: "Read users" },
];

describe("application permission clauses", () => {
  it("keeps a complete set of granular CRUD grants exact", () => {
    expect(compactPermissionClauses(
      definitions.slice(0, 4).map(({ permission }) => permission),
      definitions,
    )).toEqual([
      "BiszPortal.Applications.read",
      "BiszPortal.Applications.create",
      "BiszPortal.Applications.delete",
      "BiszPortal.Applications.update",
    ]);
  });

  it("preserves an explicit wildcard and removes only clauses it covers", () => {
    const clauses = compactPermissionClauses([
      "biszportal.applications.all",
      "BiszPortal.Applications.read",
      "BiszPortal.Applications.Export.all",
      "BiszPortal.Users.read",
    ], definitions);
    expect(clauses).toEqual([
      "BiszPortal.Users.read",
      "BiszPortal.Applications.all",
    ]);
    expect(expandPermissionClauses(clauses, definitions)).toEqual([
      "BiszPortal.Applications.Export.csv",
      "BiszPortal.Applications.create",
      "BiszPortal.Applications.delete",
      "BiszPortal.Applications.read",
      "BiszPortal.Applications.update",
      "BiszPortal.Users.read",
    ]);
  });

  it("normalizes case and deduplicates clauses without inferring wildcards", () => {
    expect(compactPermissionClauses([
      "biszportal.applications.READ",
      "BiszPortal.Applications.read",
    ], definitions)).toEqual(["BiszPortal.Applications.read"]);
  });

  it("rejects unknown exact grants and wildcards without catalog descendants", () => {
    expect(() => compactPermissionClauses(["BiszPortal.Applications.archive"], definitions))
      .toThrow("not defined");
    expect(() => compactPermissionClauses(["BiszPortal.Missing.all"], definitions))
      .toThrow("no defined descendants");
  });

  it("prunes deleted grants but preserves a surviving wildcard for future descendants", () => {
    const currentDefinitions = definitions.filter(({ permission }) =>
      permission !== "BiszPortal.Applications.delete" && permission !== "BiszPortal.Users.read",
    );
    const kept = prunePermissionClauses([
      "BiszPortal.Applications.create",
      "BiszPortal.Applications.delete",
      "BiszPortal.Users.all",
    ], currentDefinitions);
    expect(kept).toEqual(["BiszPortal.Applications.create"]);

    const survivingWildcard = prunePermissionClauses(
      ["BiszPortal.Applications.all"],
      currentDefinitions,
    );
    expect(survivingWildcard).toEqual(["BiszPortal.Applications.all"]);
    expect(expandPermissionClauses(survivingWildcard, [
      ...currentDefinitions,
      { permission: "BiszPortal.Applications.archive", description: "Archive applications" },
    ])).toContain("BiszPortal.Applications.archive");
  });
});
