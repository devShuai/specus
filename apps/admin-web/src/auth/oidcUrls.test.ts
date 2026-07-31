import { describe, expect, it } from "vitest";
import type { OidcConfig } from "../api/types";
import { buildOidcRegistrationUrl } from "./oidcUrls";

const config: OidcConfig = {
  configured: true,
  passwordLoginEnabled: false,
  authorizationEndpoint: "https://certus.example.com/oauth2/authorize",
  registrationEndpoint: "https://certus.example.com/register",
  endSessionEndpoint: "https://certus.example.com/oauth2/logout",
  clientId: "specus",
  redirectUri: "https://specus.example.com/",
  scope: "openid profile email",
};

describe("buildOidcRegistrationUrl", () => {
  it("preserves the complete authorization request as a relative Certus continuation", () => {
    const authorizationUrl = new URL(config.authorizationEndpoint);
    authorizationUrl.search = new URLSearchParams({
      response_type: "code",
      client_id: "specus",
      redirect_uri: config.redirectUri,
      state: "state-value",
      nonce: "nonce-value",
      code_challenge: "challenge-value",
      code_challenge_method: "S256",
    }).toString();

    const registrationUrl = buildOidcRegistrationUrl(config, authorizationUrl);

    expect(registrationUrl.origin).toBe("https://certus.example.com");
    expect(registrationUrl.pathname).toBe("/register");
    expect(registrationUrl.searchParams.get("client_id")).toBe("specus");
    const continuation = new URL(
      registrationUrl.searchParams.get("continue") ?? "",
      registrationUrl.origin,
    );
    expect(continuation.pathname).toBe("/oauth2/authorize");
    expect(continuation.searchParams.get("state")).toBe("state-value");
    expect(continuation.searchParams.get("nonce")).toBe("nonce-value");
    expect(continuation.searchParams.get("code_challenge")).toBe("challenge-value");
  });

  it("rejects a registration endpoint hosted by another origin", () => {
    expect(() => buildOidcRegistrationUrl(
      { ...config, registrationEndpoint: "https://attacker.example/register" },
      new URL(config.authorizationEndpoint),
    )).toThrow("必须与授权地址同源");
  });
});
