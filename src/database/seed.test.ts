import { describe, expect, it } from "vitest";
import { hashClientSecret, secretMatches } from "./seed.js";

describe("client secret hashing", () => {
  it("accepts the matching secret and rejects another one", async () => {
    const encoded = await hashClientSecret("a-sufficiently-long-secret");

    await expect(secretMatches("a-sufficiently-long-secret", encoded)).resolves.toBe(true);
    await expect(secretMatches("a-different-long-secret", encoded)).resolves.toBe(false);
  });

  it("rejects malformed or truncated hashes without throwing", async () => {
    await expect(secretMatches("secret", null)).resolves.toBe(false);
    await expect(secretMatches("secret", "scrypt:!:!")).resolves.toBe(false);
    await expect(secretMatches("secret", "scrypt:YWJj:")).resolves.toBe(false);
    await expect(secretMatches("secret", "scrypt:YWJj:YWJj")).resolves.toBe(false);
  });
});
