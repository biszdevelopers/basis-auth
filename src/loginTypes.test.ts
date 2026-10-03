import { describe, expect, it } from "vitest";
import { loginTypeFor, microsoftAuthorityFor } from "./loginTypes.js";

describe("login types", () => {
  it("classifies mapped and organization-less users", () => {
    expect(loginTypeFor(true)).toBe("FIRST_PARTY");
    expect(loginTypeFor(false)).toBe("THIRD_PARTY");
    expect(loginTypeFor(null)).toBe("COMMON");
  });

  it("selects the broadest required Microsoft authority", () => {
    const tenant = "cbc6e1e2-a6bb-4002-bbdc-6da892a051a7";
    expect(microsoftAuthorityFor(["FIRST_PARTY"], tenant)).toBe(tenant);
    expect(microsoftAuthorityFor(["FIRST_PARTY", "THIRD_PARTY"], tenant)).toBe("organizations");
    expect(microsoftAuthorityFor(["FIRST_PARTY", "THIRD_PARTY", "COMMON"], tenant)).toBe("common");
  });
});
