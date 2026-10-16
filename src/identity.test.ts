import { describe, expect, it, vi } from "vitest";
import { defaultPermissions, userPermissions, users } from "./database/schema.js";
import { createIdentityService, deriveBasisStudentDetails } from "./identity.js";

describe("deriveBasisStudentDetails", () => {
  it("extracts the student ID and district from a Basis student email", () => {
    expect(deriveBasisStudentDetails("jamesfengtian.li71984-bisz@basischina.com")).toEqual({
      studentId: "71984",
      schoolDistrict: "bisz",
    });
  });

  it("handles student IDs with any number of digits", () => {
    expect(deriveBasisStudentDetails("student7-bj@basischina.com")).toEqual({
      studentId: "7",
      schoolDistrict: "bj",
    });
  });

  it("keeps the district but leaves teacher and service-account IDs null", () => {
    expect(deriveBasisStudentDetails("devclub-bisz@basischina.com")).toEqual({
      studentId: null,
      schoolDistrict: "bisz",
    });
  });

  it("returns null attributes for non-Basis email domains", () => {
    expect(deriveBasisStudentDetails("person@example.test")).toEqual({
      studentId: null,
      schoolDistrict: null,
    });
  });
});

describe("default permissions", () => {
  it("merges live defaults with user grants, removes duplicates, and sorts them", async () => {
    const select = vi.fn(() => ({
      from: (table: unknown) => table === defaultPermissions
        ? Promise.resolve([
            { permission: "participant" },
            { permission: "Assets.Assets.read" },
            { permission: "Assets.Assets.create" },
          ])
        : table === userPermissions
          ? { where: () => Promise.resolve([
              { permission: "Assets.Assets.upload" },
              { permission: "participant" },
            ]) }
          : table === users
            ? {
                where: () => ({
                  limit: () => ({ prepare: () => ({ execute: async () => [] }) }),
                }),
              }
          : Promise.reject(new Error("Unexpected table")),
    }));
    const identity = createIdentityService(
      { select } as never,
      {} as never,
      [],
    );

    await expect(identity.permissionsFor("user-id")).resolves.toEqual([
      "Assets.Assets.create",
      "Assets.Assets.read",
      "Assets.Assets.upload",
      "participant",
    ]);
  });
});
