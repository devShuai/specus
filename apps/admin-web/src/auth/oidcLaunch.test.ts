import { describe, expect, it } from "vitest";
import { oidcLaunchReturnPath } from "./oidcLaunch";

describe("oidcLaunchReturnPath", () => {
  it("consumes the OIDC launch flag and preserves the local destination", () => {
    expect(oidcLaunchReturnPath(
      "https://specus.example.com/?login=oidc&panel=transfer#room",
    )).toBe("/?panel=transfer#room");
  });

  it("does not consume unrelated login values", () => {
    expect(oidcLaunchReturnPath("https://specus.example.com/?login=password")).toBeNull();
    expect(oidcLaunchReturnPath("https://specus.example.com/")).toBeNull();
  });
});
