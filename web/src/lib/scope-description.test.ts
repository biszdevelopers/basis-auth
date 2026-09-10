import { describe, expect, it } from "vitest";
import { describeScope, describeScopes } from "./scope-description";

describe("describeScope", () => {
  it("uses explicit descriptions for identity scopes", () => {
    expect(describeScope("email")).toMatchObject({
      description: "Access your email address",
      sensitive: false,
    });
  });

  it("describes future resource scopes by their action", () => {
    expect(describeScope("projects.read")).toMatchObject({
      description: "View your projects",
      sensitive: false,
    });
    expect(describeScope("projects.write")).toMatchObject({
      description: "View and modify your projects",
      sensitive: true,
    });
  });

  it("lists sensitive scopes first", () => {
    expect(describeScopes(["openid", "email", "nethack.access"]).map((scope) => scope.scope)).toEqual([
      "openid",
      "email",
      "nethack.access",
    ]);
  });

  it("describes an application access scope", () => {
    expect(describeScope("nethack.access")).toMatchObject({
      description: "Access nethack",
      sensitive: false,
    });
  });
});
