import { describe, expect, it } from "vitest";
import { isVerifiedBasisEmail } from "./identity.js";
import {
  microsoftAuthErrorPayload,
  userFacingMicrosoftAuthError,
} from "./microsoft.js";

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

describe("Microsoft authentication errors", () => {
  it("extracts an AADSTS code from an authorization callback error", () => {
    const payload = microsoftAuthErrorPayload({
      error: "access_denied",
      error_description: "AADSTS50057: The user account is disabled.",
      cause: new URLSearchParams({
        error: "access_denied",
        error_description: "AADSTS50057: The user account is disabled.",
      }),
    });

    expect(payload).toMatchObject({
      error: "access_denied",
      error_codes: [50057],
    });
    expect(userFacingMicrosoftAuthError(payload)).toBe(
      "Upstream Error: Your account has been disabled in your Microsoft tenant. Contact your tenant administrator.",
    );
  });

  it("shows a specific message for MFA errors", () => {
    expect(userFacingMicrosoftAuthError({
      error: "interaction_required",
      error_codes: [50076],
    })).toContain("requires multi-factor authentication");
  });

  it("does not expose a specific message for application or unknown failures", () => {
    expect(userFacingMicrosoftAuthError({
      error: "invalid_client",
      error_codes: [7000215],
    })).toBeUndefined();
    expect(userFacingMicrosoftAuthError({ error: "server_error" })).toBeUndefined();
  });
});
