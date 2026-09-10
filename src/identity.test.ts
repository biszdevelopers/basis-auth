import { describe, expect, it } from "vitest";
import { deriveBasisStudentDetails } from "./identity.js";

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
