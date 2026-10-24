import { describe, expect, it, vi } from "vitest";
import { userPermissions } from "./database/schema.js";
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

describe("application-scoped permissions", () => {
  it("loads only grants for the requested application", async () => {
    const select = vi.fn(() => ({
      from: (table: unknown) => table === userPermissions
        ? { where: () => Promise.resolve([
            { permission: "Assets.Assets.upload" },
            { permission: "Assets.Assets.create" },
          ]) }
        : {
            where: () => ({
              limit: () => ({
                prepare: () => ({ execute: vi.fn() }),
              }),
            }),
          },
    }));
    const identity = createIdentityService(
      { select } as never,
      {} as never,
      [],
    );

    await expect(identity.permissionsFor("user-id", "assets-app")).resolves.toEqual([
      "Assets.Assets.create",
      "Assets.Assets.upload",
    ]);
  });
});
