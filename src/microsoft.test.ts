import { describe, expect, it } from "vitest";
import {
  isAllowedProfilePictureUrl,
  microsoftAuthErrorPayload,
  userFacingMicrosoftAuthError,
} from "./microsoft.js";

describe("Microsoft profile picture URLs", () => {
  it.each([
    "https://graph.microsoft.com/v1.0/me/photo/$value",
    "https://login.microsoftonline.com/common/photo",
    "https://media.microsoft.com/photo.png",
  ])("allows the Microsoft HTTPS host %s", (url) => {
    expect(isAllowedProfilePictureUrl(url)).toBe(true);
  });

  it.each([
    "http://graph.microsoft.com/v1.0/me/photo/$value",
    "https://graph.microsoft.com.evil.example/photo",
    "https://evil.example/photo",
    "https://user:secret@graph.microsoft.com/photo",
    "http://127.0.0.1/photo",
    "http://169.254.169.254/latest/meta-data",
  ])("rejects the unsafe URL %s", (url) => {
    expect(isAllowedProfilePictureUrl(url)).toBe(false);
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
