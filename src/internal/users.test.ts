import { describe, expect, it } from "vitest";
import { InternalUserError, internalUserInternals } from "./users.js";

describe("internal user PATCH validation", () => {
  it("normalizes email and accepts grouped pictures", () => {
    const picture = Buffer.from("picture").toString("base64");
    expect(
      internalUserInternals.parsePatch({
        email: "Person@Example.TEST",
        picture: { data: picture, contentType: "image/png" },
      }),
    ).toEqual({
      email: "person@example.test",
      picture: { data: picture, contentType: "image/png" },
    });
  });

  it("rejects empty, immutable, and malformed fields", () => {
    for (const input of [{}, { createdAt: "2020-01-01" }, { email: "not-an-email" }, { picture: {} }]) {
      expect(() => internalUserInternals.parsePatch(input)).toThrow(InternalUserError);
    }
  });

  it("rejects malformed user IDs before querying PostgreSQL", () => {
    expect(() => internalUserInternals.validateUserId("not-a-uuid")).toThrow(InternalUserError);
  });
});

describe("internal user pagination validation", () => {
  it("applies defaults and accepts bounded positive integers", () => {
    expect(internalUserInternals.parsePagination({})).toEqual({ page: 1, pageSize: 20 });
    expect(internalUserInternals.parsePagination({ page: "3", pageSize: "50" })).toEqual({
      page: 3,
      pageSize: 50,
    });
  });

  it.each([
    { page: "0" },
    { page: "1.5" },
    { page: "nope" },
    { pageSize: "0" },
    { pageSize: "101" },
  ])("rejects invalid pagination: %o", (query) => {
    expect(() => internalUserInternals.parsePagination(query)).toThrow(InternalUserError);
  });
});
