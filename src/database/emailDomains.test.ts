import { describe, expect, it } from "vitest";
import { EmailDomainError, emailSuffix, normalizeEmailSuffix } from "./emailDomains.js";

describe("email domain normalization", () => {
  it("normalizes a domain suffix without changing its matching boundary", () => {
    expect(normalizeEmailSuffix("  Basis-Global.COM ")).toBe("basis-global.com");
    expect(emailSuffix(" Person@Basis-Global.COM ")).toBe("basis-global.com");
    expect(emailSuffix("person@sub.basis-global.com")).toBe("sub.basis-global.com");
  });

  it("rejects suffixes containing @ or malformed labels", () => {
    for (const value of ["@basis-global.com", "basis_global.com", "-bad.example", "localhost"]) {
      expect(() => normalizeEmailSuffix(value)).toThrow(EmailDomainError);
    }
  });
});
