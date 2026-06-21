import { describe, expect, it } from "vitest";
import { codeChallenge, randomToken } from "./pkce";

describe("pkce", () => {
  it("randomToken produces base64url without padding", () => {
    const token = randomToken();
    expect(token).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(token.length).toBeGreaterThanOrEqual(42);
  });

  it("codeChallenge is deterministic and base64url", async () => {
    const verifier = "test-verifier-123";
    const a = await codeChallenge(verifier);
    const b = await codeChallenge(verifier);
    expect(a).toBe(b);
    expect(a).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("different verifiers yield different challenges", async () => {
    expect(await codeChallenge("a")).not.toBe(await codeChallenge("b"));
  });
});
