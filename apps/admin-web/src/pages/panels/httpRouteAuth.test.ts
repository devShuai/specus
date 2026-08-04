import { describe, expect, it } from "vitest";
import {
  buildHttpRouteAuthMutation,
  HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH,
  HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH,
  validateHttpRouteAuth,
  type HttpRouteAuthDraft,
} from "./httpRouteAuth";

function draft(overrides: Partial<HttpRouteAuthDraft> = {}): HttpRouteAuthDraft {
  return {
    enabled: true,
    username: "visitor",
    password: "secret",
    passwordConfigured: false,
    ...overrides,
  };
}

describe("HTTP route Basic authentication", () => {
  it("does not require credentials for a public route", () => {
    expect(validateHttpRouteAuth(draft({ enabled: false, username: "", password: "" }))).toBe("");
    expect(buildHttpRouteAuthMutation(draft({ enabled: false }))).toEqual({ authEnabled: false });
  });

  it("requires a username and first password when authentication is enabled", () => {
    expect(validateHttpRouteAuth(draft({ username: "" }))).toBe("请输入访问用户名");
    expect(validateHttpRouteAuth(draft({ password: "   " }))).toBe("请输入访问密码");
  });

  it("rejects Basic usernames that contain a delimiter or line break", () => {
    expect(validateHttpRouteAuth(draft({ username: "name:part" }))).toBe("访问用户名不能包含冒号");
    expect(validateHttpRouteAuth(draft({ username: "name\npart" }))).toBe("访问用户名不能包含换行符");
  });

  it("enforces the shared credential length limits", () => {
    expect(validateHttpRouteAuth(draft({ username: "u".repeat(HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH + 1) })))
      .toContain(String(HTTP_ROUTE_AUTH_USERNAME_MAX_LENGTH));
    expect(validateHttpRouteAuth(draft({ password: "p".repeat(HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH + 1) })))
      .toContain(String(HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH));
  });

  it("omits an empty password when an existing password is configured", () => {
    const mutation = buildHttpRouteAuthMutation(draft({
      username: "  visitor  ",
      password: "",
      passwordConfigured: true,
    }));

    expect(validateHttpRouteAuth(draft({ password: "", passwordConfigured: true }))).toBe("");
    expect(mutation).toEqual({ authEnabled: true, authUsername: "visitor" });
    expect(mutation).not.toHaveProperty("authPassword");
  });

  it("treats an all-whitespace edit password as omitted", () => {
    const existing = draft({
      password: " ".repeat(HTTP_ROUTE_AUTH_PASSWORD_MAX_LENGTH + 1),
      passwordConfigured: true,
    });

    expect(validateHttpRouteAuth(existing)).toBe("");
    expect(buildHttpRouteAuthMutation(existing)).not.toHaveProperty("authPassword");
  });

  it("preserves password whitespace when a new password is submitted", () => {
    expect(buildHttpRouteAuthMutation(draft({ password: " secret " }))).toEqual({
      authEnabled: true,
      authUsername: "visitor",
      authPassword: " secret ",
    });
  });
});
