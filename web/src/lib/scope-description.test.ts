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
    expect(describeScopes(["openid", "email", "permissions"]).map((scope) => scope.scope)).toEqual([
      "permissions",
      "openid",
      "email",
    ]);
  });

  it("describes every Network Hackathon delegated scope", () => {
    const scopes = new Map([
      ["Profile.all", true], ["Projects.read.all", false], ["Projects.write.self", true],
      ["Teams.all", true], ["Voting.all", true], ["Judging.all", true],
      ["Seasons.all", true], ["Files.all", true], ["Chatbot.use", false],
      ["Database.export", true],
    ]);
    for (const [scope, sensitive] of scopes) {
      expect(describeScope(scope)).toMatchObject({ sensitive });
      expect(describeScope(scope).description).toContain("Network Hackathon");
    }
  });

  it("makes wildcard consent grants explicit", () => {
    for (const scope of ["Profile.all", "Projects.read.all", "Teams.all", "Voting.all", "Judging.all", "Seasons.all", "Files.all"]) {
      expect(describeScope(scope).description.toLowerCase()).toContain("all");
    }
  });
});
