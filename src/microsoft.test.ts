import { describe, expect, it } from "vitest";
import { isVerifiedBasisEmail } from "./identity.js";

describe("isVerifiedBasisEmail", () => {
  it("verifies a Basis China email", () => {
    expect(isVerifiedBasisEmail("student71984-bisz@basischina.com")).toBe(true);
  });

  it("verifies a Basis Global email", () => {
    expect(isVerifiedBasisEmail("person@basis-global.com")).toBe(true);
  });

  it("leaves every other email unverified", () => {
    expect(isVerifiedBasisEmail("person@example.test")).toBe(false);
    expect(isVerifiedBasisEmail("person@basisinternational-sz.com")).toBe(false);
  });
});
